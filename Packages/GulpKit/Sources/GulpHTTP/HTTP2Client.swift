// GulpHTTP — HTTP/2 to servers (F03 HTTP-020, HTTP-023, HTTP-024, HTTP-027).
//
// One HTTP/2 connection per pool key carries many requests at once, each on its own stream
// (HTTP-023). swift-nio-http2 does the framing, HPACK, flow control (WINDOW_UPDATE as data is read)
// and the concurrent-stream limit (streams beyond SETTINGS_MAX_CONCURRENT_STREAMS wait); server push
// is refused with SETTINGS_ENABLE_PUSH=0 (HTTP-024). The engine's messages stay HTTP/1-style text
// (GulpCore `HTTP2Text`), converted at this boundary.
//
// Concept: in HTTP/2 a "request" is a stream — HEADERS (+ DATA) one way, HEADERS (+ DATA)
// (+ trailing HEADERS) back. Streams are cheap; connections are not, so they are shared.

import GulpCore
import NIOConcurrencyHelpers
import NIOCore
import NIOHPACK
import NIOHTTP2

/// What one HTTP/2 stream produced.
struct H2Received: Sendable {
    var parts: H2ResponseParts
    var firstByteAt: NIODeadline?
    var lastByteAt: NIODeadline
}

/// A live HTTP/2 connection shared by concurrent requests.
final class H2Connection: Sendable {
    let channel: any Channel
    let id: UInt64
    let tls: TLSInfo?
    private let multiplexer: NIOLoopBound<HTTP2StreamMultiplexer>
    /// The stream multiplexer, for group sends (GroupSend.swift).
    var multiplexerForGroups: NIOLoopBound<HTTP2StreamMultiplexer> { multiplexer }

    /// Local settings: no server push (HTTP-024), and NIO's defaults otherwise.
    static let settings: [HTTP2Setting] = [
        HTTP2Setting(parameter: .enablePush, value: 0),
        HTTP2Setting(parameter: .maxConcurrentStreams, value: 100),
        HTTP2Setting(parameter: .maxHeaderListSize, value: 1 << 20),
    ]

    private init(
        channel: any Channel, id: UInt64, tls: TLSInfo?, multiplexer: NIOLoopBound<HTTP2StreamMultiplexer>
    ) {
        self.channel = channel
        self.id = id
        self.tls = tls
        self.multiplexer = multiplexer
    }

    var isUsable: Bool { channel.isActive }

    /// Switch an open connection (TLS that negotiated `h2`, or cleartext prior knowledge) to HTTP/2.
    static func start(on channel: any Channel, id: UInt64, tls: TLSInfo?) async throws -> H2Connection {
        let loop = channel.eventLoop
        try await channel.pipeline.removeHandler(name: NIOHTTPEngine.http1HandlerName).get()
        let bound = try await channel.configureHTTP2Pipeline(
            mode: .client, initialLocalSettings: settings, inboundStreamInitializer: nil
        ).map { NIOLoopBound($0, eventLoop: loop) }.get()
        // Bytes the server sent right after the handshake were held back until now (TLS only).
        channel.pipeline.fireUserInboundEventTriggered(ReleaseHeldReads())
        return H2Connection(channel: channel, id: id, tls: tls, multiplexer: bound)
    }

    /// Send one request on a new stream and collect the response (HTTP-021 conversion is the
    /// caller's; this writes `parts` as HEADERS + DATA).
    func send(
        _ parts: H2RequestParts, maxResponseBytes: Int, deadline: NIODeadline
    ) async -> (received: H2Received?, error: GulpNetworkError?, writeEnd: NIODeadline) {
        let loop = channel.eventLoop
        let done = loop.makePromise(of: H2Received.self)
        let opened = loop.makePromise(of: (any Channel).self)
        let multiplexer = self.multiplexer
        loop.execute {
            multiplexer.value.createStreamChannel(promise: opened) { stream in
                stream.eventLoop.makeCompletedFuture {
                    let collector = H2ResponseCollector(done: done, maxBytes: maxResponseBytes)
                    try stream.pipeline.syncOperations.addHandler(collector)
                }
            }
        }
        let stream: any Channel
        do {
            stream = try await opened.futureResult.get()
        } catch {
            return (nil, .connectionReset, .now())
        }
        let timeout = loop.scheduleTask(deadline: deadline) {
            done.fail(GulpNetworkError.totalTimeout)
            stream.close(promise: nil)
        }
        defer { timeout.cancel() }

        var headers = HPACKHeaders()
        headers.add(name: ":method", value: parts.method)
        headers.add(name: ":scheme", value: parts.scheme)
        headers.add(name: ":authority", value: parts.authority)
        headers.add(name: ":path", value: parts.path)
        for header in parts.headers { headers.add(name: header.name, value: header.value) }
        do {
            let endStream = parts.body.isEmpty
            let head = HTTP2Frame.FramePayload.Headers(headers: headers, endStream: endStream)
            try await stream.writeAndFlush(HTTP2Frame.FramePayload.headers(head))
            if !endStream {
                let data = IOData.byteBuffer(stream.allocator.buffer(bytes: parts.body))
                let frame = HTTP2Frame.FramePayload.Data(data: data, endStream: true)
                try await stream.writeAndFlush(HTTP2Frame.FramePayload.data(frame))
            }
        } catch {
            done.fail(error)
        }
        let writeEnd = NIODeadline.now()
        do {
            return (try await done.futureResult.get(), nil, writeEnd)
        } catch let error as GulpNetworkError {
            return (nil, error, writeEnd)
        } catch {
            return (nil, HTTP1ClientHandler.networkError(error), writeEnd)
        }
    }
}

/// Collects one stream's response: HEADERS (interim 1xx skipped), DATA, trailing HEADERS (HTTP-027).
final class H2ResponseCollector: ChannelInboundHandler {
    typealias InboundIn = HTTP2Frame.FramePayload
    private let done: EventLoopPromise<H2Received>
    private let maxBytes: Int
    private var status: Int?
    private var headers: [H2Header] = []
    private var trailers: [H2Header] = []
    private var body: [UInt8] = []
    private var firstByteAt: NIODeadline?
    private var finished = false

    init(done: EventLoopPromise<H2Received>, maxBytes: Int) {
        self.done = done
        self.maxBytes = maxBytes
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if firstByteAt == nil { firstByteAt = .now() }
        switch unwrapInboundIn(data) {
        case .headers(let frame):
            let fields = frame.headers.map { H2Header($0.name, $0.value) }
            if status == nil {
                guard let code = frame.headers.first(name: ":status").flatMap({ Int($0) }) else {
                    fail(.other("HTTP/2 response without :status"), context: context)
                    return
                }
                if (100..<200).contains(code) { return }  // interim (e.g. 103 Early Hints)
                status = code
                headers = fields.filter { !$0.name.hasPrefix(":") }
            } else {
                trailers += fields
            }
            if frame.endStream { complete() }
        case .data(let frame):
            if case .byteBuffer(let buffer) = frame.data { body += buffer.readableBytesView }
            if body.count > maxBytes {
                fail(.tooLarge(limit: maxBytes), context: context)
                return
            }
            if frame.endStream { complete() }
        case .rstStream(let code):
            fail(.other("the server reset the HTTP/2 stream (\(code))"), context: context)
        default:
            break
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !finished {
            finished = true
            done.fail(GulpNetworkError.incompleteResponse)
        }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        fail(HTTP1ClientHandler.networkError(error), context: context)
    }

    private func complete() {
        guard !finished, let status else { return }
        finished = true
        let parts = H2ResponseParts(status: status, headers: headers, body: body, trailers: trailers)
        done.succeed(H2Received(parts: parts, firstByteAt: firstByteAt, lastByteAt: .now()))
    }

    private func fail(_ error: GulpNetworkError, context: ChannelHandlerContext) {
        guard !finished else { return }
        finished = true
        done.fail(error)
        context.close(promise: nil)
    }
}

/// HTTP/2 connections by pool key (HTTP-023: one per key, shared).
actor H2Pool {
    private var connections: [PoolKey: H2Connection] = [:]

    func connection(for key: PoolKey) -> H2Connection? {
        guard let connection = connections[key] else { return nil }
        if connection.isUsable { return connection }
        connections[key] = nil
        return nil
    }

    func add(_ connection: H2Connection, for key: PoolKey) {
        connections[key]?.channel.close(promise: nil)
        connections[key] = connection
    }

    /// Forget `connection` (it failed or was told to go away).
    func remove(_ connection: H2Connection, for key: PoolKey) {
        if connections[key]?.id == connection.id { connections[key] = nil }
        connection.channel.close(promise: nil)
    }

    func closeAll() {
        for connection in connections.values { connection.channel.close(promise: nil) }
        connections = [:]
    }
}
