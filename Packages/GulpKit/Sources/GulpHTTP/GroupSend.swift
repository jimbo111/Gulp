// GulpHTTP — single-packet group sends (F03 HTTP-033/034/035), the race-condition workflow
// (F06 REP-010). Every request is sent except its final bytes; after a short warm-up the withheld
// final bytes of all requests are released together, so the server receives the requests as close
// to simultaneously as the network allows.
//
//   - HTTP/2 (HTTP-033), when every item goes to the same HTTPS target and the server negotiates
//     h2: one connection, one stream per request. HEADERS and all DATA but the last byte go out
//     first (a GET sends HEADERS without END_STREAM). The final DATA frames are then written in one
//     event-loop turn behind a `FlushBarrier`, so the stream channels' individual flushes are
//     swallowed and the connection is flushed exactly once: the frames leave in one write.
//   - HTTP/1 (HTTP-034, also the fallback): one connection per request, all on one event loop; each
//     holds back its last byte, then every last byte is written and flushed in one loop turn.
//
// Each request is recorded as its own exchange; `Timing.finalWriteOffsetMs` gives when its final
// bytes left relative to the first of the group (HTTP-035).

import Foundation
import GulpCore
import NIOConcurrencyHelpers
import NIOCore
import NIOHPACK
import NIOHTTP2

/// Holds the flushes passing through it while armed, then flushes once (HTTP-033 coalescing). It
/// sits just below `NIOHTTP2Handler`, so frames written by the stream channels queue in the
/// TLS/socket layer until `release`.
final class FlushBarrier: ChannelOutboundHandler, RemovableChannelHandler {
    typealias OutboundIn = IOData
    typealias OutboundOut = IOData

    private var context: ChannelHandlerContext?
    private var holding = false
    private var flushHeld = false

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
    }

    func flush(context: ChannelHandlerContext) {
        if holding {
            flushHeld = true
        } else {
            context.flush()
        }
    }

    /// Start holding flushes.
    func arm() {
        holding = true
    }

    /// Stop holding and flush once if anything asked to.
    func release() {
        holding = false
        if flushHeld, let context {
            flushHeld = false
            context.flush()
        }
    }
}

/// What happened to one stream of an HTTP/2 single-packet group.
struct SinglePacketOutcome: Sendable {
    var received: H2Received?
    var error: GulpNetworkError?
    var finalWrite: NIODeadline?
}

extension H2Connection {
    /// HTTP-033: send `requests` on new streams of this connection, withholding each one's final
    /// DATA frame; after `warmUp`, write all withheld frames and flush the connection once.
    func sendSinglePacket(
        _ requests: [H2RequestParts], maxResponseBytes: Int, deadline: NIODeadline, warmUp: TimeAmount
    ) async -> [SinglePacketOutcome] {
        let loop = channel.eventLoop
        let channel = self.channel
        let barrier: NIOLoopBound<FlushBarrier>
        do {
            barrier = try await loop.submit {
                let handler = FlushBarrier()
                let h2 = try channel.pipeline.syncOperations.handler(type: NIOHTTP2Handler.self)
                try channel.pipeline.syncOperations.addHandler(handler, position: .before(h2))
                return NIOLoopBound(handler, eventLoop: loop)
            }.get()
        } catch {
            let failure = GulpNetworkError.other("Could not prepare the connection: \(error)")
            return requests.map { _ in SinglePacketOutcome(error: failure) }
        }

        // 1. Open a stream per request and send all but its final frame.
        var outcomes = [SinglePacketOutcome](repeating: SinglePacketOutcome(), count: requests.count)
        var pending: [(index: Int, stream: any Channel, final: HTTP2Frame.FramePayload)] = []
        var responses: [(index: Int, future: EventLoopFuture<H2Received>)] = []
        for (index, parts) in requests.enumerated() {
            let done = loop.makePromise(of: H2Received.self)
            guard let stream = await openStream(done: done, maxResponseBytes: maxResponseBytes) else {
                done.fail(GulpNetworkError.connectionReset)
                outcomes[index].error = .connectionReset
                continue
            }
            var headers = HPACKHeaders()
            headers.add(name: ":method", value: parts.method)
            headers.add(name: ":scheme", value: parts.scheme)
            headers.add(name: ":authority", value: parts.authority)
            headers.add(name: ":path", value: parts.path)
            for header in parts.headers { headers.add(name: header.name, value: header.value) }
            do {
                let head = HTTP2Frame.FramePayload.Headers(headers: headers, endStream: false)
                try await stream.writeAndFlush(HTTP2Frame.FramePayload.headers(head))
                if parts.body.count > 1 {
                    let leading = IOData.byteBuffer(stream.allocator.buffer(bytes: parts.body.dropLast()))
                    let data = HTTP2Frame.FramePayload.Data(data: leading, endStream: false)
                    try await stream.writeAndFlush(HTTP2Frame.FramePayload.data(data))
                }
            } catch {
                done.fail(error)
                outcomes[index].error = HTTP1ClientHandler.networkError(error)
                continue
            }
            let lastByte = parts.body.last.map { [$0] } ?? []
            let last = IOData.byteBuffer(stream.allocator.buffer(bytes: lastByte))
            let final = HTTP2Frame.FramePayload.data(.init(data: last, endStream: true))
            pending.append((index, stream, final))
            responses.append((index, done.futureResult))
        }

        // 2. Warm up, then 3. release every final frame in one loop turn behind the barrier.
        try? await loop.scheduleTask(in: warmUp) {}.futureResult.get()
        let finals = pending.map { (stream: $0.stream, final: $0.final) }
        let released =
            try? await loop.submit { () -> NIODeadline in
                barrier.value.arm()
                for item in finals { item.stream.writeAndFlush(item.final, promise: nil) }
                let stamp = NIODeadline.now()
                barrier.value.release()
                return stamp
            }.get()
        for item in pending { outcomes[item.index].finalWrite = released }

        // 4. Collect the responses.
        let timeout = loop.scheduleTask(deadline: deadline) {
            for stream in finals.map(\.stream) { stream.close(promise: nil) }
        }
        defer { timeout.cancel() }
        for (index, future) in responses {
            do {
                outcomes[index].received = try await future.get()
            } catch let error as GulpNetworkError {
                outcomes[index].error = error
            } catch {
                outcomes[index].error = HTTP1ClientHandler.networkError(error)
            }
        }
        return outcomes
    }
}

extension NIOHTTPEngine {
    /// HTTP-033/034: a single-packet group send (see the file header).
    func sendSinglePacket(_ items: [GroupItem], options: SendOptions) async -> [ExchangeResult] {
        guard let first = items.first else { return [] }
        let sameTarget = items.allSatisfy { $0.target == first.target }
        if sameTarget, first.target.scheme == .https, options.httpVersion != .http1_1,
            let results = await sendSinglePacketH2(items, options: options)
        {
            return results
        }
        return await sendLastByteSync(items, options: options)
    }

    /// HTTP-033 over one HTTP/2 connection; nil when the server doesn't negotiate h2 (the caller
    /// falls back to HTTP-034) or a request can't be prepared.
    func sendSinglePacketH2(_ items: [GroupItem], options: SendOptions) async -> [ExchangeResult]? {
        let start = NIODeadline.now()
        let deadline = start + timeAmount(options.timeouts.total)
        var prepared: [(outgoing: OutgoingRequest, options: SendOptions)] = []
        for item in items {
            let (outgoing, itemOptions, failure) = await prepare(
                item.request, to: item.target, options: options)
            if failure != nil { return nil }
            prepared.append((outgoing, itemOptions))
        }
        let target = items[0].target
        for _ in items { await throttle.acquire(host: target.host) }  // HTTP-013: one slot per request
        let route = upstreamRoute(for: target, options: options)
        if unsupported(target, options, route: route) != nil { return nil }
        var connectOptions = options
        connectOptions.httpVersion = .http2
        var timing = Timing(start: Date())
        let channel: any Channel
        let tls: TLSInfo?
        do {
            (channel, tls) = try await connect(
                target, route: route, options: connectOptions, deadline: deadline, timing: &timing)
        } catch {
            return nil
        }
        guard tls?.alpn == "h2" else {
            channel.close(promise: nil)
            return nil
        }
        let connectionID = await pool.newConnectionID()
        let connection: H2Connection
        do {
            connection = try await H2Connection.start(on: channel, id: connectionID, tls: tls)
        } catch {
            channel.close(promise: nil)
            return nil
        }
        let authority = target.port == 443 ? target.host : "\(target.host):\(target.port)"
        let parts = prepared.map {
            HTTP2Text.requestParts($0.outgoing.request, scheme: target.scheme, defaultAuthority: authority)
        }
        let outcomes = await connection.sendSinglePacket(
            parts, maxResponseBytes: options.maxResponseBytes, deadline: deadline,
            warmUp: timeAmount(options.singlePacketWarmUp))
        channel.close(promise: nil)
        let firstFinal = outcomes.compactMap(\.finalWrite).min()
        var results: [ExchangeResult] = []
        for (index, outcome) in outcomes.enumerated() {
            var itemTiming = timing
            var wire: WireResponse?
            if let received = outcome.received {
                let text = HTTP2Text.response(received.parts)
                wire = WireResponse(
                    bytes: text.bytes.rawBytes, interim: [], error: nil, firstByteAt: received.firstByteAt,
                    lastByteAt: received.lastByteAt, reusable: false, receivedAny: true)
            }
            Self.stamp(&itemTiming, final: outcome.finalWrite, first: firstFinal, wire: wire, start: start)
            results.append(
                await finish(
                    prepared[index].outgoing, options: prepared[index].options, wire: wire,
                    error: outcome.error, connectionID: connectionID, timing: itemTiming, tls: tls,
                    httpVersion: .http2))
        }
        return results
    }

    /// HTTP-034: last-byte sync over HTTP/1 — one connection per request, on one event loop.
    func sendLastByteSync(_ items: [GroupItem], options: SendOptions) async -> [ExchangeResult] {
        struct Held: Sendable {
            let index: Int
            let channel: any Channel
            let tls: TLSInfo?
            let connectionID: UInt64
            let final: ByteBuffer
            let response: EventLoopFuture<WireResponse>
            let timing: Timing
        }
        let loop = group.next()
        let start = NIODeadline.now()
        let deadline = start + timeAmount(options.timeouts.total)
        var prepared: [(outgoing: OutgoingRequest, options: SendOptions)] = []
        var results = [ExchangeResult?](repeating: nil, count: items.count)

        // 1. Prepare and connect every request; failures are recorded right away.
        var held: [Held] = []
        for (index, item) in items.enumerated() {
            var timing = Timing(start: Date())
            var (outgoing, itemOptions, failure) = await prepare(
                item.request, to: item.target, options: options)
            prepared.append((outgoing, itemOptions))
            let route = upstreamRoute(for: outgoing.target, options: itemOptions)
            if failure == nil { failure = unsupported(outgoing.target, itemOptions, route: route) }
            if let route, route.kind == .http, !route.tunnelPlainHTTP, outgoing.target.scheme == .http {
                outgoing.request = outgoing.request.forPlainHTTPProxy(
                    target: outgoing.target, proxyAuthorization: route.basicAuthorization)
                prepared[index].outgoing = outgoing
            }
            if let failure {
                results[index] = await finish(
                    outgoing, options: itemOptions, wire: nil, error: failure, connectionID: 0,
                    timing: timing)
                continue
            }
            await throttle.acquire(host: outgoing.target.host)  // HTTP-013
            var connectOptions = itemOptions
            connectOptions.httpVersion = .http1_1
            let channel: any Channel
            let tls: TLSInfo?
            do {
                (channel, tls) = try await connect(
                    outgoing.target, route: route, options: connectOptions, deadline: deadline,
                    timing: &timing, on: loop)
            } catch {
                let mapped = (error as? GulpNetworkError) ?? HTTP1ClientHandler.networkError(error)
                results[index] = await finish(
                    outgoing, options: itemOptions, wire: nil, error: mapped, connectionID: 0,
                    timing: timing)
                continue
            }
            // 2. Send everything but the last byte; the response is framed when it comes.
            let bytes = outgoing.request.bytes.rawBytes
            let promise = channel.eventLoop.makePromise(of: WireResponse.self)
            let waitForFinal = timeAmount(options.singlePacketWarmUp) + .seconds(5)
            let command = RequestCommand(
                bytes: channel.allocator.buffer(bytes: bytes.dropLast()),
                isHead: outgoing.request.bytes[outgoing.request.parsed.method].string() == "HEAD",
                isConnect: false, maxResponseBytes: itemOptions.maxResponseBytes,
                firstByteTimeout: timeAmount(itemOptions.timeouts.firstByte) + waitForFinal,
                idleTimeout: timeAmount(itemOptions.timeouts.idleBetweenBytes), totalDeadline: deadline,
                promise: promise)
            let written = channel.eventLoop.makePromise(of: Void.self)
            written.futureResult.whenFailure { promise.fail($0) }
            channel.writeAndFlush(command, promise: written)
            _ = try? await written.futureResult.get()
            held.append(
                Held(
                    index: index, channel: channel, tls: tls, connectionID: await pool.newConnectionID(),
                    final: channel.allocator.buffer(bytes: bytes.suffix(1)), response: promise.futureResult,
                    timing: timing))
        }

        // 3. Warm up, then write every last byte in one loop turn and flush them together.
        try? await loop.scheduleTask(in: timeAmount(options.singlePacketWarmUp)) {}.futureResult.get()
        let finals = held.map { (channel: $0.channel, final: $0.final) }
        let stamps =
            (try? await loop.submit { () -> [NIODeadline] in
                for item in finals {
                    // A continuation only adds bytes to the request in flight; its own response
                    // promise is unused (the handler never sees it), so it is completed here.
                    let unused = loop.makePromise(of: WireResponse.self)
                    var command = RequestCommand(
                        bytes: item.final, isHead: false, isConnect: false, maxResponseBytes: 0,
                        firstByteTimeout: .seconds(0), idleTimeout: .seconds(0),
                        totalDeadline: .distantFuture, promise: unused)
                    command.continuation = true
                    item.channel.write(command, promise: nil)
                    unused.fail(GulpNetworkError.other("continuation"))
                }
                var stamps: [NIODeadline] = []
                for item in finals {
                    item.channel.flush()
                    stamps.append(.now())
                }
                return stamps
            }.get()) ?? []

        // 4. Collect the responses and record each exchange.
        let firstFinal = stamps.min()
        for (position, item) in held.enumerated() {
            let wire: WireResponse
            do {
                wire = try await item.response.get()
            } catch {
                wire = WireResponse(
                    bytes: [], interim: [], error: HTTP1ClientHandler.networkError(error), firstByteAt: nil,
                    lastByteAt: nil, reusable: false, receivedAny: false)
            }
            item.channel.close(promise: nil)
            var timing = item.timing
            let final = position < stamps.count ? stamps[position] : nil
            Self.stamp(&timing, final: final, first: firstFinal, wire: wire, start: start)
            let entry = prepared[item.index]
            results[item.index] = await finish(
                entry.outgoing, options: entry.options, wire: wire, error: wire.error,
                connectionID: item.connectionID, timing: timing, tls: item.tls)
        }
        return results.enumerated().map { index, result in
            result
                ?? ExchangeResult(
                    exchange: Exchange(
                        source: options.recordAs, target: items[index].target,
                        request: items[index].request),
                    error: .other("not sent"))
        }
    }

    /// Fill a group member's timing: time to first byte from its final write, download, total, and
    /// the final write's offset in the group (HTTP-035).
    static func stamp(
        _ timing: inout Timing, final: NIODeadline?, first: NIODeadline?, wire: WireResponse?,
        start: NIODeadline
    ) {
        if let final, let first { timing.finalWriteOffsetMs = milliseconds(from: first, to: final) }
        if let final, let firstByte = wire?.firstByteAt {
            timing.ttfbMs = milliseconds(from: final, to: firstByte)
            if let last = wire?.lastByteAt { timing.downloadMs = milliseconds(from: firstByte, to: last) }
        }
        timing.totalMs = milliseconds(from: start, to: .now())
    }
}

extension H2Connection {
    /// Open a stream whose response is collected into `done`; nil if the stream can't be opened.
    func openStream(done: EventLoopPromise<H2Received>, maxResponseBytes: Int) async -> (any Channel)? {
        let loop = channel.eventLoop
        let opened = loop.makePromise(of: (any Channel).self)
        let multiplexer = self.multiplexerForGroups
        loop.execute {
            multiplexer.value.createStreamChannel(promise: opened) { stream in
                stream.eventLoop.makeCompletedFuture {
                    let collector = H2ResponseCollector(done: done, maxBytes: maxResponseBytes)
                    try stream.pipeline.syncOperations.addHandler(collector)
                }
            }
        }
        return try? await opened.futureResult.get()
    }
}

extension NIOHTTPEngine {
    /// HTTP-011: write `requests` back to back on one HTTP/1.1 connection (one flush) and read the
    /// responses in order — the Fuzzer's Turbo mode (F07). Each request is recorded as its own
    /// exchange. If the server closes the connection early, the requests it never answered fail with
    /// `connectionReset` (re-send them on a new connection).
    public func sendPipelined(
        _ requests: [RawRequest], to target: HTTPTarget, options: SendOptions
    ) async -> [ExchangeResult] {
        guard !requests.isEmpty else { return [] }
        let start = NIODeadline.now()
        let deadline = start + timeAmount(options.timeouts.total)
        var prepared: [(outgoing: OutgoingRequest, options: SendOptions, failure: GulpNetworkError?)] = []
        for request in requests {
            prepared.append(await prepare(request, to: target, options: options))
            await throttle.acquire(host: target.host)  // HTTP-013
        }
        let route = upstreamRoute(for: target, options: options)
        var connectOptions = options
        connectOptions.httpVersion = .http1_1
        var timing = Timing(start: Date())
        let channel: any Channel
        let tls: TLSInfo?
        do {
            if let refusal = unsupported(target, options, route: route) { throw refusal }
            (channel, tls) = try await connect(
                target, route: route, options: connectOptions, deadline: deadline, timing: &timing)
        } catch {
            let mapped = (error as? GulpNetworkError) ?? HTTP1ClientHandler.networkError(error)
            var results: [ExchangeResult] = []
            for entry in prepared {
                results.append(
                    await finish(
                        entry.outgoing, options: entry.options, wire: nil, error: entry.failure ?? mapped,
                        connectionID: 0, timing: timing))
            }
            return results
        }
        let connectionID = await pool.newConnectionID()
        // Write every request (those a hook rejected are skipped), then flush once.
        let sendable = prepared.enumerated().filter { $0.element.failure == nil }
        let commands = sendable.map { index, entry -> (Int, RequestCommand) in
            let request = entry.outgoing.request
            var command = RequestCommand(
                bytes: channel.allocator.buffer(bytes: request.bytes.rawBytes),
                isHead: request.bytes[request.parsed.method].string() == "HEAD", isConnect: false,
                maxResponseBytes: entry.options.maxResponseBytes,
                firstByteTimeout: timeAmount(entry.options.timeouts.firstByte),
                idleTimeout: timeAmount(entry.options.timeouts.idleBetweenBytes), totalDeadline: deadline,
                promise: channel.eventLoop.makePromise(of: WireResponse.self))
            command.pipelined = true
            return (index, command)
        }
        let writeEnd =
            (try? await channel.eventLoop.submit { () -> NIODeadline in
                for (_, command) in commands {
                    let written = channel.eventLoop.makePromise(of: Void.self)
                    written.futureResult.whenFailure { command.promise.fail($0) }
                    channel.write(command, promise: written)
                }
                channel.flush()
                return .now()
            }.get()) ?? .now()
        var results = [ExchangeResult?](repeating: nil, count: prepared.count)
        for (index, command) in commands {
            let wire: WireResponse
            do {
                wire = try await command.promise.futureResult.get()
            } catch {
                wire = WireResponse(
                    bytes: [], interim: [], error: HTTP1ClientHandler.networkError(error), firstByteAt: nil,
                    lastByteAt: nil, reusable: false, receivedAny: false)
            }
            var itemTiming = timing
            if let first = wire.firstByteAt {
                itemTiming.ttfbMs = milliseconds(from: writeEnd, to: first)
                if let last = wire.lastByteAt { itemTiming.downloadMs = milliseconds(from: first, to: last) }
            }
            itemTiming.totalMs = milliseconds(from: start, to: .now())
            let entry = prepared[index]
            results[index] = await finish(
                entry.outgoing, options: entry.options, wire: wire, error: wire.error,
                connectionID: connectionID, timing: itemTiming, tls: tls)
        }
        channel.close(promise: nil)
        for (index, entry) in prepared.enumerated() where results[index] == nil {
            results[index] = await finish(
                entry.outgoing, options: entry.options, wire: nil, error: entry.failure, connectionID: 0,
                timing: timing)
        }
        return results.compactMap { $0 }
    }
}
