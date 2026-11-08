// GulpProxy — WebSockets through the proxy (F01 PRX-030…PRX-034). The upgrade request is sent with
// the engine's `upgrade`; on `101` the proxy writes the 101 to the client and then relays each
// direction through a pump that parses frames:
//   - frames are forwarded as their original wire bytes (raw bytes are the truth), one frame at a
//     time, unless a WebSocket Match & Replace rule or WebSocket Intercept applies to the direction;
//   - then a whole data message is collected, rewritten / held (PRX-033), and sent on unchanged
//     (original bytes) or re-framed as one frame if it changed;
//   - a stream the parser can't follow is relayed raw from then on (and no longer recorded).
// Messages are recorded in the order the pumps pass them (PRX-031), compressed ones decompressed
// for the record (PRX-034). Without a 101 the connection returns to HTTP.

import GulpCore
import GulpHTTP
import NIOConcurrencyHelpers
import NIOCore

/// Sent to the client connection's handler when the upgrade succeeded: client bytes go to `sink`.
struct UpgradeEstablished: Sendable {
    let sink: @Sendable ([UInt8]) -> Void
}

/// Sent when the server did not switch protocols: keep speaking HTTP on the connection.
struct UpgradeDeclined: Sendable {}

/// What may change a WebSocket message on its way: Match & Replace and Intercept (PRX-033).
struct WSHooks: Sendable {
    let intercept: InterceptQueue?
    let matchReplace: MatchReplaceHook?
    let upgrade: RawRequest
    let target: HTTPTarget

    /// Whether messages going `direction` must be collected whole before they are sent on.
    func active(_ direction: WSDirection) async -> Bool {
        if matchReplace?.rewritesWebSockets(direction) == true { return true }
        guard let intercept else { return false }
        return await intercept.interceptsWebSockets(upgrade: upgrade, target: target)
    }

    /// The payload to send for `message` (nil: dropped in Intercept).
    func process(_ message: WSMessage, _ direction: WSDirection) async -> [UInt8]? {
        var payload = message.payload
        if let matchReplace { payload = matchReplace.rewriteWebSocket(payload, direction: direction) }
        guard let intercept else { return payload }
        let (decision, _) = await intercept.holdWebSocketMessage(
            payload, opcode: message.opcode, direction: direction, upgrade: upgrade, target: target)
        switch decision {
        case .drop: return nil
        case .forward(let edited?): return edited.rawBytes
        case .forward(nil): return payload
        }
    }
}

/// One message as passed on, for the recorder.
struct WSPassed: Sendable {
    let direction: WSDirection
    let message: WSMessage
    /// The payload before an edit, if it was edited.
    var original: [UInt8]? = nil
    var dropped = false
}

enum ProxyWebSocket {
    /// Whether `request` asks to switch to WebSocket.
    static func isUpgrade(_ request: RawRequest) -> Bool {
        request.hasHeaderToken("upgrade", "websocket") && request.hasHeaderToken("connection", "upgrade")
    }

    /// Upgrade and relay until either side closes. Returns what the serving loop should still write
    /// (nothing once relaying) and whether to close.
    static func relay(
        _ request: RawRequest, to target: HTTPTarget, upstream: ProxyUpstream, client: any Channel
    ) async -> (bytes: [UInt8], close: Bool) {
        guard let engine = upstream.engine as? NIOHTTPEngine else {
            client.pipeline.fireUserInboundEventTriggered(UpgradeDeclined())
            return (ProxyConnection.errorPage(502, "WebSockets need the NIO engine."), false)
        }
        let (fromServer, toClient) = AsyncStream.makeStream(of: [UInt8].self)
        let (result, connection) = await engine.upgrade(
            request, to: target, options: upstream.options,
            onRead: { toClient.yield($0) },
            onClose: { toClient.finish() })  // the client-bound pump closes the client when done
        guard let connection, let response = result.exchange.response else {
            toClient.finish()
            client.pipeline.fireUserInboundEventTriggered(UpgradeDeclined())
            if let response = result.exchange.response {
                return (HTTP2Text.http1Response(from: response), false)
            }
            let reason = result.error?.userDescription ?? "no response"
            return (ProxyConnection.errorPage(502, "The WebSocket upgrade failed: \(reason)."), false)
        }
        let upstreamChannel = connection.channel
        // 101 first; the server's frames wait in `fromServer` until the pump starts.
        do {
            try await client.writeAndFlush(client.allocator.buffer(bytes: response.wireBytes.rawBytes))
        } catch {
            upstreamChannel.close(promise: nil)
            toClient.finish()
            return ([], true)
        }
        let (passed, record) = AsyncStream.makeStream(of: WSPassed.self)
        let (fromClient, toServer) = AsyncStream.makeStream(of: [UInt8].self)
        let hooks = WSHooks(
            intercept: upstream.intercept, matchReplace: upstream.matchReplace, upgrade: request,
            target: target)
        let serverBound = Task {
            await pump(fromClient, direction: .toServer, hooks: hooks, record: record) { bytes in
                upstreamChannel.writeAndFlush(upstreamChannel.allocator.buffer(bytes: bytes), promise: nil)
            }
            upstreamChannel.close(promise: nil)
        }
        let clientBound = Task {
            await pump(fromServer, direction: .toClient, hooks: hooks, record: record) { bytes in
                client.writeAndFlush(client.allocator.buffer(bytes: bytes), promise: nil)
            }
            client.close(promise: nil)
        }
        client.pipeline.fireUserInboundEventTriggered(UpgradeEstablished(sink: { toServer.yield($0) }))
        let recorder = upstream.webSockets
        let url = webSocketURL(request, target: target)
        let exchangeID = result.exchange.id
        let compressed = WebSocketInflater.negotiated(in: response)
        let recording = Task {
            await self.record(
                passed, recorder: recorder, url: url, exchangeID: exchangeID, compressed: compressed)
        }
        try? await client.closeFuture.get()
        toServer.finish()
        toClient.finish()
        await serverBound.value
        await clientBound.value
        record.finish()
        await recording.value
        return ([], true)
    }

    /// Relay one direction: parse frames, forward them (or whole, possibly edited, messages), and
    /// report every message passed on to `record`.
    static func pump(
        _ input: AsyncStream<[UInt8]>, direction: WSDirection, hooks: WSHooks,
        record: AsyncStream<WSPassed>.Continuation, write: @escaping @Sendable ([UInt8]) -> Void
    ) async {
        var parser = WSFrameParser()
        var assembler = WSMessageAssembler()
        var unparsed: [UInt8] = []  // the bytes the parser holds, to slice frames' wire bytes from
        var raw = false
        // The wire bytes of the data message being collected whole (nil: frames go on as they come).
        var collected: [[UInt8]]?
        for await bytes in input {
            if raw {
                write(bytes)
                continue
            }
            unparsed += bytes
            for frame in parser.feed(bytes) {
                let wire = Array(unparsed.prefix(frame.wireLength))
                unparsed.removeFirst(frame.wireLength)
                let isControl = frame.opcode >= 8
                if !isControl, frame.opcode != WSOpcode.continuation.rawValue {
                    // A new data message. A compressed one (RSV1) can't be edited: it goes on as is.
                    let editable = frame.rsv & 0x04 == 0
                    let whole = editable ? await hooks.active(direction) : false
                    collected = whole ? [] : nil
                }
                if isControl || collected == nil { write(wire) } else { collected?.append(wire) }
                guard let message = assembler.add(frame) else { continue }
                guard !isControl, let frames = collected else {
                    record.yield(WSPassed(direction: direction, message: message))
                    continue
                }
                collected = nil
                guard let payload = await hooks.process(message, direction) else {
                    record.yield(WSPassed(direction: direction, message: message, dropped: true))
                    continue
                }
                if payload == message.payload {
                    for frame in frames { write(frame) }  // unchanged: the original bytes
                    record.yield(WSPassed(direction: direction, message: message))
                    continue
                }
                let opcode = WSOpcode(rawValue: message.opcode) ?? .binary
                let mask = direction == .toServer ? (0..<4).map { _ in UInt8.random(in: 0...255) } : nil
                write(WebSocketWire.frame(opcode: opcode, payload: payload, mask: mask))
                let info = WSFrameInfo(
                    fin: true, opcode: message.opcode, rsv: 0, length: payload.count, masked: mask != nil)
                let sent = WSMessage(opcode: message.opcode, payload: payload, frames: [info])
                record.yield(WSPassed(direction: direction, message: sent, original: message.payload))
            }
            if parser.failed {
                // Not a stream we can follow (or a frame over the size limit): relay raw from here.
                for frame in collected ?? [] { write(frame) }
                collected = nil
                write(unparsed)
                unparsed = []
                raw = true
            }
        }
        for frame in collected ?? [] { write(frame) }  // the connection ended mid-message
        if !unparsed.isEmpty { write(unparsed) }
    }

    /// Record the passed messages in order; compressed messages are recorded decompressed.
    static func record(
        _ passed: AsyncStream<WSPassed>, recorder: (any WebSocketRecorder)?, url: String,
        exchangeID: ExchangeID, compressed: Bool
    ) async {
        guard let recorder else {
            for await _ in passed {}
            return
        }
        let upgradeID = exchangeID == 0 ? nil : exchangeID
        let id = await recorder.webSocketOpened(upgradeExchangeID: upgradeID, url: url)
        var inflaters: [WSDirection: WebSocketInflater] = [:]
        if compressed {
            inflaters[.toServer] = WebSocketInflater()
            inflaters[.toClient] = WebSocketInflater()
        }
        var closeCode: Int?
        for await item in passed {
            var message = item.message
            let isCompressed = (message.frames.first?.rsv ?? 0) & 0x04 != 0
            if isCompressed, let plain = try? inflaters[item.direction]?.inflate(message.payload) {
                message.payload = plain
            }
            if message.opcode == WSOpcode.close.rawValue, message.payload.count >= 2, !item.dropped {
                closeCode = Int(message.payload[0]) << 8 | Int(message.payload[1])
            }
            if let id {
                await recorder.webSocketMessage(
                    id, direction: item.direction, message: message, original: item.original,
                    dropped: item.dropped)
            }
        }
        if let id { await recorder.webSocketClosed(id, code: closeCode) }
    }

    static func webSocketURL(_ request: RawRequest, target: HTTPTarget) -> String {
        let path = request.bytes[request.parsed.target].string()
        let scheme = target.scheme == .https ? "wss" : "ws"
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        let authority = standard ? target.host : "\(target.host):\(target.port)"
        if path.hasPrefix("http://") || path.hasPrefix("https://") {
            return scheme + path.drop { $0 != ":" }  // absolute-form: keep host and path
        }
        return "\(scheme)://\(authority)\(path)"
    }
}
