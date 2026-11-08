// GulpProxy — WebSockets through the proxy (F01 PRX-030, PRX-031). The upgrade request is sent with
// the engine's `upgrade`; on `101` the proxy writes the 101 to the client and then relays bytes in
// both directions untouched, while a copy of each direction is parsed into messages and recorded
// (in order, by one task per connection). Without a 101 the connection returns to HTTP.

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

/// Holds bytes until a writer is attached, then forwards everything in order.
final class BytesGate: Sendable {
    typealias Writer = @Sendable ([UInt8]) -> Void
    private let state = NIOLockedValueBox<(writer: Writer?, held: [[UInt8]])>((nil, []))

    func deliver(_ bytes: [UInt8]) {
        let writer: Writer? = state.withLockedValue { state in
            if state.writer == nil { state.held.append(bytes) }
            return state.writer
        }
        writer?(bytes)
    }

    func open(_ writer: @escaping Writer) {
        let held = state.withLockedValue { state -> [[UInt8]] in
            state.writer = writer
            defer { state.held = [] }
            return state.held
        }
        for bytes in held { writer(bytes) }
    }
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
        let (events, recording) = AsyncStream.makeStream(of: (WSDirection, [UInt8]).self)
        let fromServer = BytesGate()
        // The upstream closing ends the client connection only once relaying started: a declined
        // upgrade closes the upstream too, but the client keeps speaking HTTP.
        let relaying = NIOLockedValueBox(false)
        let (result, connection) = await engine.upgrade(
            request, to: target, options: upstream.options,
            onRead: { bytes in
                fromServer.deliver(bytes)
                recording.yield((.toClient, bytes))
            },
            onClose: { if relaying.withLockedValue({ $0 }) { client.close(promise: nil) } })
        guard let connection, let response = result.exchange.response else {
            recording.finish()
            client.pipeline.fireUserInboundEventTriggered(UpgradeDeclined())
            if let response = result.exchange.response {
                return (HTTP2Text.http1Response(from: response), false)
            }
            let reason = result.error?.userDescription ?? "no response"
            return (ProxyConnection.errorPage(502, "The WebSocket upgrade failed: \(reason)."), false)
        }
        // 101 first, then the server's frames, then client frames flow upstream.
        do {
            try await client.writeAndFlush(client.allocator.buffer(bytes: response.wireBytes.rawBytes))
        } catch {
            connection.channel.close(promise: nil)
            recording.finish()
            return ([], true)
        }
        fromServer.open { bytes in
            client.writeAndFlush(client.allocator.buffer(bytes: bytes), promise: nil)
        }
        let upstreamChannel = connection.channel
        relaying.withLockedValue { $0 = true }
        if !upstreamChannel.isActive { client.close(promise: nil) }  // it closed before the flag
        client.pipeline.fireUserInboundEventTriggered(
            UpgradeEstablished(sink: { bytes in
                upstreamChannel.writeAndFlush(upstreamChannel.allocator.buffer(bytes: bytes), promise: nil)
                recording.yield((.toServer, bytes))
            }))
        let recorder = upstream.webSockets
        let url = webSocketURL(request, target: target)
        let exchangeID = result.exchange.id
        let recordingTask = Task {
            await record(events, recorder: recorder, url: url, exchangeID: exchangeID)
        }
        try? await client.closeFuture.get()
        upstreamChannel.close(promise: nil)
        recording.finish()
        await recordingTask.value
        return ([], true)
    }

    /// Parse both directions into messages and record them in arrival order.
    static func record(
        _ events: AsyncStream<(WSDirection, [UInt8])>, recorder: (any WebSocketRecorder)?, url: String,
        exchangeID: ExchangeID
    ) async {
        guard let recorder else {
            for await _ in events {}
            return
        }
        let upgradeID = exchangeID == 0 ? nil : exchangeID
        let id = await recorder.webSocketOpened(upgradeExchangeID: upgradeID, url: url)
        var parsers = [WSDirection.toServer: WSFrameParser(), .toClient: WSFrameParser()]
        var assemblers = [WSDirection.toServer: WSMessageAssembler(), .toClient: WSMessageAssembler()]
        var closeCode: Int?
        for await (direction, bytes) in events {
            guard let frames = parsers[direction]?.feed(bytes) else { continue }
            for frame in frames {
                guard let message = assemblers[direction]?.add(frame) else { continue }
                if message.opcode == WSOpcode.close.rawValue, message.payload.count >= 2 {
                    closeCode = Int(message.payload[0]) << 8 | Int(message.payload[1])
                }
                if let id { await recorder.webSocketMessage(id, direction: direction, message: message) }
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
