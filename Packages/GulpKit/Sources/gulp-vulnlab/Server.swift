// gulp-vulnlab — two raw SwiftNIO listeners on 127.0.0.1 only:
//   :8088  the HTTP fixtures (keep-alive, routed by `VulnLab.respond`)
//   :8089  `/echo-raw`: writes back exactly the bytes it received, then closes (close-delimited)
//   :8443  the same fixtures over TLS (HTTP/2 or HTTP/1.1 by ALPN), with a certificate from a
//          throwaway CA (F02 acceptance #4: "upstream to VulnLab's self-signed :8443")

import GulpCore
import GulpTLS
import NIOConcurrencyHelpers
import NIOCore
import NIOHPACK
import NIOHTTP2
import NIOPosix
import NIOSSL
import NIOTLS

/// The running listeners.
struct VulnLabServer: Sendable {
    let app: any Channel
    let raw: any Channel
    let tls: any Channel

    static func start(appPort: Int, rawPort: Int, tlsPort: Int) async throws -> VulnLabServer {
        let app = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture(withResultOf: {
                    try channel.pipeline.syncOperations.addHandler(AppHandler())
                })
            }
            .bind(host: "127.0.0.1", port: appPort).get()
        let raw = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture(withResultOf: {
                    try channel.pipeline.syncOperations.addHandler(RawEchoHandler())
                })
            }
            .bind(host: "127.0.0.1", port: rawPort).get()
        // Not signed by anything a client trusts: a stand-in for a staging server's certificate.
        let minter = try LeafMinter(authority: CertificateAuthority.generate(keyType: .p256))
        let context = try await minter.serverContext(for: "localhost", alpn: ["h2", "http/1.1"])
        let tls = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture(withResultOf: {
                    try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
                    try channel.pipeline.syncOperations.addHandler(
                        ApplicationProtocolNegotiationHandler { result, channel in
                            guard case .negotiated("h2") = result else {
                                return channel.eventLoop.makeCompletedFuture {
                                    try channel.pipeline.syncOperations.addHandler(AppHandler())
                                }
                            }
                            return channel.configureHTTP2Pipeline(mode: .server) { stream in
                                stream.eventLoop.makeCompletedFuture {
                                    try stream.pipeline.syncOperations.addHandler(H2AppHandler())
                                }
                            }.map { _ in }
                        })
                })
            }
            .bind(host: "127.0.0.1", port: tlsPort).get()
        return VulnLabServer(app: app, raw: raw, tls: tls)
    }

    func waitUntilClosed() async throws {
        try await app.closeFuture.get()
    }
}

/// How an upgraded WebSocket answers messages.
enum WSHandlerMode: Equatable {
    /// `/ws`, `/safe/ws`: echo every message as `echo: …` (M4b).
    case echo
    /// `/ws/authz` (WSX-004): authorizes only at the handshake, so the privileged `secret` action
    /// succeeds on *any* upgraded connection — a replayed privileged message under a stripped identity
    /// still works.
    case authzHandshakeOnly
    /// `/safe/ws/authz` (WSX-004): re-checks identity on *each* message, so only an admin connection
    /// gets the secret; a stripped identity is refused per message.
    case authzPerMessage
}

/// Reads HTTP/1 requests (header block + Content-Length body) and writes routed replies.
final class AppHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var buffer: [UInt8] = []
    /// Set once `/ws` switched the connection to WebSocket.
    private var webSocket: WSFrameParser?
    /// How this upgraded socket answers messages (plain echo, or the per-message-authz twins).
    private var wsMode: WSHandlerMode = .echo
    /// Whether the handshake carried the `admin` identity (`Cookie: sid=admin`).
    private var wsIsAdmin = false

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if webSocket != nil {
            echoFrames(Array(unwrapInboundIn(data).readableBytesView), context: context)
            return
        }
        buffer.append(contentsOf: unwrapInboundIn(data).readableBytesView)
        while let next = Self.nextRequest(buffer) {
            let (request, used) = next
            buffer.removeFirst(used)
            let target = request.bytes[request.parsed.target].string()
            if target == "/sse" || target.hasPrefix("/sse?") {
                Self.streamEvents(request, context: context)  // the connection is the stream from now on
                return
            }
            let isWS = target == "/ws" || target.hasPrefix("/ws?")
            let isSafeWS = target == "/safe/ws" || target.hasPrefix("/safe/ws?")
            let isAuthzWS = target == "/ws/authz" || target.hasPrefix("/ws/authz?")
            let isSafeAuthzWS = target == "/safe/ws/authz" || target.hasPrefix("/safe/ws/authz?")
            if isWS || isSafeWS || isAuthzWS || isSafeAuthzWS,
                let key = request.headerValue("sec-websocket-key")?.string(),
                request.hasHeaderToken("upgrade", "websocket")
            {
                // CSWSH (WSX-003): the vulnerable `/ws` upgrades regardless of Origin; the safe
                // `/safe/ws` rejects a cross-site handshake (its Origin isn't the lab's own host).
                let origin = request.headerValue("origin")?.string()
                if isSafeWS, let origin, !origin.hasSuffix("127.0.0.1:8088"),
                    !origin.hasSuffix("localhost:8088")
                {
                    let reject =
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: 17\r\nConnection: close\r\n\r\nForbidden origin\n"
                    let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
                    context.writeAndFlush(NIOAny(context.channel.allocator.buffer(string: reject)))
                        .whenComplete { _ in bound.value.close(promise: nil) }
                    return
                }
                // WSX-004: both authz twins upgrade *any* connection (handshake is open); the identity
                // for per-message authorization is read from `Cookie: sid=…`.
                if isAuthzWS { wsMode = .authzHandshakeOnly }
                if isSafeAuthzWS { wsMode = .authzPerMessage }
                wsIsAdmin = Self.cookieValue(request, "sid") == "admin"
                acceptWebSocket(key: key, context: context)
                let rest = buffer
                buffer = []
                if !rest.isEmpty { echoFrames(rest, context: context) }
                return
            }
            let reply = VulnLab.respond(to: request)
            let close = request.hasHeaderToken("connection", "close")
            write(reply, context: context, close: close)
            if close { return }
        }
    }

    /// `/sse[?n=N]` (doc 06 §3, M4b): a chunked `text/event-stream` with a heartbeat comment and one
    /// numbered event every 200 ms, until `n` events were sent (then the stream ends) or the client
    /// goes away.
    static func streamEvents(_ request: RawRequest, context: ChannelHandlerContext) {
        let target = request.bytes[request.parsed.target].string()
        let limit = VulnLab.queryItems(target)["n"].flatMap(Int.init)
        let head =
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n"
            + "Transfer-Encoding: chunked\r\n\r\n"
        let channel = context.channel
        channel.writeAndFlush(channel.allocator.buffer(string: head), promise: nil)
        let sent = NIOLockedValueBox(0)
        let chunk: @Sendable (String) -> ByteBuffer = { text in
            channel.allocator.buffer(string: String(text.utf8.count, radix: 16) + "\r\n" + text + "\r\n")
        }
        let interval = TimeAmount.milliseconds(200)
        context.eventLoop.scheduleRepeatedTask(initialDelay: interval, delay: interval) { task in
            guard channel.isActive else {
                task.cancel()
                return
            }
            let number = sent.withLockedValue {
                $0 += 1
                return $0
            }
            channel.write(chunk(": heartbeat\n\n"), promise: nil)
            let event = "id: \(number)\nevent: tick\ndata: event \(number)\n\n"
            channel.writeAndFlush(chunk(event), promise: nil)
            if let limit, number >= limit {
                task.cancel()
                channel.writeAndFlush(channel.allocator.buffer(string: "0\r\n\r\n"), promise: nil)
            }
        }
    }

    /// `/ws` (doc 06 §3, M4b): a WebSocket echo. The 101 and a greeting go out in one write (so a
    /// proxy sees frames arrive together with the handshake); then text and binary messages come
    /// back as `echo: …`, pings get pongs, and a close is answered with the same close.
    private func acceptWebSocket(key: String, context: ChannelHandlerContext) {
        webSocket = WSFrameParser()
        let head =
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + "Sec-WebSocket-Accept: \(WebSocketWire.accept(forKey: key))\r\n\r\n"
        // The echo sockets greet; the authz twins stay silent so the first frame a client reads is the
        // reply to its own message.
        let greeting =
            wsMode == .echo
            ? WebSocketWire.frame(opcode: .text, payload: Array("hello from VulnLab".utf8)) : []
        let out = context.channel.allocator.buffer(bytes: Array(head.utf8) + greeting)
        context.writeAndFlush(NIOAny(out), promise: nil)
    }

    /// WSX-004: answer a message on an authz socket. `{"action":"whoami"}` echoes the handshake
    /// identity; `{"action":"secret"}` returns the secret. On the handshake-only twin every upgraded
    /// connection gets the secret (authorization happened once, at the handshake); on the per-message
    /// twin the server re-checks the connection's identity and refuses a non-admin — so a privileged
    /// message replayed under a stripped identity succeeds against the vulnerable socket and fails
    /// against the safe one.
    private func authzReply(to payload: [UInt8]) -> String {
        let text = String(decoding: payload, as: UTF8.self)
        if text.contains("whoami") {
            return "{\"identity\":\"\(wsIsAdmin ? "admin" : "guest")\"}"
        }
        if text.contains("secret") {
            let granted = wsMode == .authzHandshakeOnly || wsIsAdmin
            return granted
                ? "{\"secret\":\"TOP-SECRET-FLAG-7781\"}"
                : "{\"error\":\"forbidden\",\"need\":\"admin\"}"
        }
        return "{\"ok\":true}"
    }

    /// The value of a cookie by name from the request's `Cookie` header, or nil.
    static func cookieValue(_ request: RawRequest, _ name: String) -> String? {
        guard let header = request.headerValue("cookie")?.string() else { return nil }
        for pair in header.split(separator: ";") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            if kv.count == 2, kv[0].trimmingCharacters(in: .whitespaces) == name {
                return kv[1].trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    private func echoFrames(_ bytes: [UInt8], context: ChannelHandlerContext) {
        guard let frames = webSocket?.feed(bytes) else { return }
        for frame in frames {
            let reply: [UInt8]
            switch WSOpcode(rawValue: frame.opcode) {
            case .text, .binary, .continuation:
                if wsMode != .echo, frame.opcode == WSOpcode.text.rawValue {
                    let answer = authzReply(to: frame.payload)
                    reply = WebSocketWire.frame(opcode: .text, payload: Array(answer.utf8), fin: frame.fin)
                    break
                }
                let prefix = frame.opcode == WSOpcode.continuation.rawValue ? [] : Array("echo: ".utf8)
                let opcode = WSOpcode(rawValue: frame.opcode) ?? .binary
                reply = WebSocketWire.frame(opcode: opcode, payload: prefix + frame.payload, fin: frame.fin)
            case .ping:
                reply = WebSocketWire.frame(opcode: .pong, payload: frame.payload)
            case .close:
                let closing = WebSocketWire.frame(opcode: .close, payload: frame.payload)
                let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
                context.writeAndFlush(NIOAny(context.channel.allocator.buffer(bytes: closing)))
                    .whenComplete { _ in bound.value.close(promise: nil) }
                return
            case .pong, nil:
                continue
            }
            context.writeAndFlush(NIOAny(context.channel.allocator.buffer(bytes: reply)), promise: nil)
        }
    }

    /// The first complete request in `bytes` and how many bytes it used.
    static func nextRequest(_ bytes: [UInt8]) -> (RawRequest, Int)? {
        let (end, terminator) = HTTP1.headerBlockEnd(bytes)
        guard terminator != 0 else { return nil }
        let head = RawRequest(Bytes(Array(bytes[..<end])))
        let declared = head.headerValue("content-length").flatMap { Int($0.string()) } ?? 0
        let total = end + max(0, declared)
        guard bytes.count >= total else { return nil }
        return (RawRequest(Bytes(Array(bytes[..<total]))), total)
    }

    private func write(_ reply: VulnReply, context: ChannelHandlerContext, close: Bool) {
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        let send: @Sendable () -> Void = {
            let context = bound.value
            var out = context.channel.allocator.buffer(capacity: reply.bytes.count)
            out.writeBytes(reply.bytes)
            reply.onSend?()
            let written = context.writeAndFlush(NIOAny(out))
            if close { written.whenComplete { _ in bound.value.close(promise: nil) } }
        }
        if reply.delayMilliseconds > 0 {
            context.eventLoop.scheduleTask(in: .milliseconds(Int64(reply.delayMilliseconds))) { send() }
        } else {
            send()
        }
    }
}

/// `/echo-raw`: collects bytes until the client pauses for 150 ms, writes them back verbatim, closes.
/// The pause (not HTTP parsing) ends the request, so even malformed, unterminated input round-trips.
final class RawEchoHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var received: [UInt8] = []
    private var timer: Scheduled<Void>?
    private var context: ChannelHandlerContext?

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        received.append(contentsOf: unwrapInboundIn(data).readableBytesView)
        timer?.cancel()
        let bound = NIOLoopBound(self, eventLoop: context.eventLoop)
        timer = context.eventLoop.scheduleTask(in: .milliseconds(150)) { bound.value.echo() }
    }

    private func echo() {
        guard let context else { return }
        var out = context.channel.allocator.buffer(capacity: received.count)
        out.writeBytes(received)
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.writeAndFlush(wrapOutboundOut(out)).whenComplete { _ in bound.value.close(promise: nil) }
    }
}

/// The HTTP fixtures over HTTP/2: each stream becomes an `HTTP/2`-text request routed by
/// `VulnLab.respond`, and the HTTP/1 reply is sent back as frames (a chunked reply's trailer section
/// becomes real HTTP/2 trailers).
final class H2AppHandler: ChannelInboundHandler {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias OutboundOut = HTTP2Frame.FramePayload
    private var head: HPACKHeaders?
    private var body: [UInt8] = []

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .headers(let frame):
            if head == nil { head = frame.headers }
            if frame.endStream { respond(context) }
        case .data(let frame):
            if case .byteBuffer(let buffer) = frame.data { body += buffer.readableBytesView }
            if frame.endStream { respond(context) }
        default:
            break
        }
    }

    private func respond(_ context: ChannelHandlerContext) {
        guard let head else { return }
        let fields = head.filter { !$0.name.hasPrefix(":") }.map { H2Header($0.name, $0.value) }
        let parts = H2RequestParts(
            method: head.first(name: ":method") ?? "GET", scheme: "https",
            authority: head.first(name: ":authority") ?? "localhost",
            path: head.first(name: ":path") ?? "/", headers: fields, body: body)
        let reply = VulnLab.respond(to: HTTP2Text.request(parts))
        guard reply.delayMilliseconds > 0 else {
            write(reply, context)
            return
        }
        let bound = NIOLoopBound((self, context), eventLoop: context.eventLoop)
        context.eventLoop.scheduleTask(in: .milliseconds(Int64(reply.delayMilliseconds))) {
            bound.value.0.write(reply, bound.value.1)
        }
    }

    private func write(_ reply: VulnReply, _ context: ChannelHandlerContext) {
        reply.onSend?()
        let response = HTTP2Text.responseParts(RawResponse(Bytes(reply.bytes)))
        var headers = HPACKHeaders([(":status", String(response.status))])
        for header in response.headers { headers.add(name: header.name, value: header.value) }
        let trailing = !response.trailers.isEmpty
        let bodyless = response.body.isEmpty && !trailing
        let headFrame = HTTP2Frame.FramePayload.Headers(headers: headers, endStream: bodyless)
        context.write(wrapOutboundOut(.headers(headFrame)), promise: nil)
        if !response.body.isEmpty {
            let data = IOData.byteBuffer(context.channel.allocator.buffer(bytes: response.body))
            context.write(wrapOutboundOut(.data(.init(data: data, endStream: !trailing))), promise: nil)
        }
        if trailing {
            var trailers = HPACKHeaders()
            for trailer in response.trailers { trailers.add(name: trailer.name, value: trailer.value) }
            let tail = HTTP2Frame.FramePayload.Headers(headers: trailers, endStream: true)
            context.write(wrapOutboundOut(.headers(tail)), promise: nil)
        }
        context.flush()
    }
}
