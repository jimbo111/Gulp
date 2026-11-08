// GulpProxy — the HTTP/1 forward proxy (F01 PRX-001…PRX-007): absolute-form plain HTTP, and CONNECT
// tunnels that are intercepted (TLS MITM), spliced (pass-through) or carry plain HTTP (Tunnel.swift).
// HTTP/2 to the client arrives in M3b; invisible mode and the landing page later.

import Foundation
import GulpCore
import GulpHTTP
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix

/// One proxy listener (PRX-001). Stored in the project's `proxy.listeners` settings group.
public struct ProxyListenerConfig: Codable, Sendable, Hashable, Identifiable {
    /// Stable identity.
    public var id: UUID
    /// Bind address (default loopback only).
    public var bindAddress: String
    /// Port (0 picks a free port).
    public var port: Int
    /// Whether the listener should run.
    public var enabled: Bool

    /// Create a listener definition.
    public init(
        id: UUID = UUID(), bindAddress: String = "127.0.0.1", port: Int = 8080, enabled: Bool = true
    ) {
        self.id = id
        self.bindAddress = bindAddress
        self.port = port
        self.enabled = enabled
    }
}

/// Runs proxy listeners and forwards their traffic through the shared HTTP engine.
public actor ProxyServer {
    private let engine: any HTTPEngine
    private var tls: ProxyTLSOptions?
    private var listeners: [UUID: (server: any Channel, clients: ClientConnections)] = [:]

    /// Create a proxy that forwards (and, through the engine's recorder, records) via `engine`.
    /// Without `tls`, CONNECT is refused (no CA to intercept with).
    public init(engine: any HTTPEngine, tls: ProxyTLSOptions? = nil) {
        self.engine = engine
        self.tls = tls
    }

    /// Change TLS interception for connections accepted from now on.
    public func setTLS(_ options: ProxyTLSOptions?) {
        tls = options
    }

    /// Start a listener and return the port it is bound to. Bind failures (port in use, PRX-001)
    /// throw a `GulpError` with a user-facing message.
    @discardableResult
    public func start(_ config: ProxyListenerConfig) async throws -> Int {
        if listeners[config.id] != nil { await stop(config.id) }
        let engine = self.engine
        let tls = self.tls
        let clients = ClientConnections()
        let channel: any Channel
        do {
            channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
                .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .childChannelInitializer { channel in
                    clients.add(channel)
                    let (items, continuation) = AsyncStream.makeStream(of: ProxyItem.self)
                    let client = channel.remoteAddress.map { "\($0.ipAddress ?? "?"):\($0.port ?? 0)" }
                    let pressure = Backpressure()
                    Task {
                        await ProxyConnection.serve(
                            items, channel: channel, engine: engine, client: client, pressure: pressure,
                            intercepts: tls != nil)
                    }
                    return channel.eventLoop.makeCompletedFuture(withResultOf: {
                        let handler = ProxyConnectionHandler(
                            items: continuation, pressure: pressure, tls: tls)
                        try channel.pipeline.syncOperations.addHandler(handler)
                    })
                }
                .bind(host: config.bindAddress, port: config.port).get()
        } catch {
            throw GulpError(
                message: "Cannot listen on \(config.bindAddress):\(config.port): \(error)",
                recoverySuggestion: "Choose another port, or stop the program that is using it.")
        }
        listeners[config.id] = (channel, clients)
        return channel.localAddress?.port ?? config.port
    }

    /// Stop a listener and close the client connections it accepted.
    public func stop(_ id: UUID) async {
        guard let listener = listeners.removeValue(forKey: id) else { return }
        try? await listener.server.close().get()
        listener.clients.closeAll()
    }

    /// Stop every listener.
    public func stopAll() async {
        for id in Array(listeners.keys) { await stop(id) }
    }

    /// Whether a listener is running.
    public func isRunning(_ id: UUID) -> Bool {
        listeners[id] != nil
    }
}

/// The open client connections of one listener, so stopping the listener closes them too.
final class ClientConnections: Sendable {
    private let channels = NIOLockedValueBox<[ObjectIdentifier: any Channel]>([:])

    func add(_ channel: any Channel) {
        let key = ObjectIdentifier(channel)
        channels.withLockedValue { $0[key] = channel }
        channel.closeFuture.whenComplete { [channels] _ in
            _ = channels.withLockedValue { $0.removeValue(forKey: key) }
        }
    }

    func closeAll() {
        for channel in channels.withLockedValue({ Array($0.values) }) { channel.close(promise: nil) }
    }

    var count: Int { channels.withLockedValue { $0.count } }
}

/// Work for a connection's serving task, in arrival order.
enum ProxyItem: Sendable {
    /// Forward this request: absolute-form (`tunnel` nil) or inside a tunnel to `tunnel`.
    case request(RawRequest, tunnel: HTTPTarget?)
    /// Answer a CONNECT; the handler is already waiting for the tunnel to start.
    case connect(RawRequest)
    /// Answer `100 Continue` (after any earlier responses).
    case sendContinue
    /// Answer an error and close (unframeable input).
    case reject(status: Int, message: String)
}

/// Bounds how many framed items wait for the serving task; reading pauses beyond that, so a client
/// pipelining faster than the upstream answers cannot grow the proxy's memory without limit.
final class Backpressure: Sendable {
    static let maxQueued = 8
    private let queued = NIOLockedValueBox(0)

    /// Count one item; true when reading should pause.
    func enqueued() -> Bool {
        queued.withLockedValue {
            $0 += 1
            return $0 >= Self.maxQueued
        }
    }

    /// Uncount one item; true when reading should resume.
    func finished() -> Bool {
        queued.withLockedValue {
            $0 -= 1
            return $0 == Self.maxQueued - 1
        }
    }
}

/// Frames requests off a client connection and hands them, in order, to the connection's task.
final class ProxyConnectionHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private enum Mode {
        /// A forward proxy: absolute-form requests and CONNECT.
        case forward
        /// A CONNECT was framed; bytes wait until the tunnel starts.
        case tunnelPending
        /// Inside a tunnel: origin-form requests go to this target.
        case tunnel(HTTPTarget)
    }

    private let items: AsyncStream<ProxyItem>.Continuation
    private let pressure: Backpressure
    private let tls: ProxyTLSOptions?
    private var buffer: [UInt8] = []
    private var sentContinue = false
    private var rejected = false
    private var mode = Mode.forward

    init(items: AsyncStream<ProxyItem>.Continuation, pressure: Backpressure, tls: ProxyTLSOptions?) {
        self.items = items
        self.pressure = pressure
        self.tls = tls
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !rejected else { return }
        buffer.append(contentsOf: unwrapInboundIn(data).readableBytesView)
        frame(context: context)
    }

    private func frame(context: ChannelHandlerContext) {
        loop: while true {
            if case .tunnelPending = mode { return }
            switch RequestFramer.next(buffer) {
            case .request(let request, let length):
                buffer.removeFirst(length)
                sentContinue = false
                switch mode {
                case .tunnel(let target):
                    enqueue(.request(request, tunnel: target), context: context)
                case .forward where request.bytes[request.parsed.method].string() == "CONNECT":
                    mode = .tunnelPending  // the bytes after CONNECT belong to the tunnel
                    enqueue(.connect(request), context: context)
                    return
                case .forward, .tunnelPending:
                    enqueue(.request(request, tunnel: nil), context: context)
                }
            case .reject(let status, let message):
                rejected = true
                buffer = []
                enqueue(.reject(status: status, message: message), context: context)
                items.finish()
                return
            case .incomplete:
                break loop
            }
        }
        if !sentContinue, !buffer.isEmpty, RequestFramer.awaitsContinue(buffer) {
            // The client waits for this before sending its body (F01 §5 Expect: 100-continue).
            sentContinue = true
            enqueue(.sendContinue, context: context)
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let ready = event as? TunnelReady, let tls {
            // `200 Connection established` is out: let the sniffer decide what the tunnel carries.
            let sniffer = TunnelSniffer(host: ready.host, port: ready.port, tls: tls, initial: buffer)
            buffer = []
            do {
                try context.pipeline.syncOperations.addHandler(sniffer, position: .before(self))
            } catch {
                context.close(promise: nil)
            }
        } else if let tunnel = event as? TunnelTarget {
            mode = .tunnel(tunnel.target)
            frame(context: context)
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }

    private func enqueue(_ item: ProxyItem, context: ChannelHandlerContext) {
        items.yield(item)
        if pressure.enqueued() {
            context.channel.setOption(ChannelOptions.autoRead, value: false).whenComplete { _ in }
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        items.finish()
        context.fireChannelInactive()
    }
}

/// Serves one client connection: forward each request upstream and write the response back.
enum ProxyConnection {
    static func serve(
        _ items: AsyncStream<ProxyItem>, channel: any Channel, engine: any HTTPEngine, client: String?,
        pressure: Backpressure, intercepts: Bool
    ) async {
        for await item in items {
            let reply: (bytes: [UInt8], close: Bool)
            var tunnel: TunnelReady?
            switch item {
            case .request(let request, let target):
                reply = await forward(request, tunnel: target, engine: engine, client: client)
            case .connect(let request):
                if intercepts, let authority = connectAuthority(request) {
                    reply = (Array("HTTP/1.1 200 Connection established\r\n\r\n".utf8), false)
                    tunnel = TunnelReady(host: authority.host, port: authority.port)
                } else {
                    let message =
                        intercepts
                        ? "CONNECT needs a host:port target." : "HTTPS interception is off (no Gulp CA)."
                    reply = (errorPage(intercepts ? 400 : 502, message, close: true), true)
                }
            case .sendContinue: reply = (Array("HTTP/1.1 100 Continue\r\n\r\n".utf8), false)
            case .reject(let status, let message): reply = (errorPage(status, message, close: true), true)
            }
            if pressure.finished() {
                channel.setOption(ChannelOptions.autoRead, value: true).whenComplete { _ in }
            }
            var out = channel.allocator.buffer(capacity: reply.bytes.count)
            out.writeBytes(reply.bytes)
            do {
                try await channel.writeAndFlush(out)
            } catch {
                break
            }
            if let tunnel { channel.pipeline.fireUserInboundEventTriggered(tunnel) }
            if reply.close {
                channel.close(promise: nil)
                break
            }
        }
    }

    /// Forward one request (PRX-002) and decide whether the client connection stays open (PRX-003).
    static func forward(
        _ request: RawRequest, tunnel: HTTPTarget?, engine: any HTTPEngine, client: String?
    ) async -> (bytes: [UInt8], close: Bool) {
        let method = request.bytes[request.parsed.method].string()
        let version = request.bytes[request.parsed.version].string()
        let clientWantsClose =
            request.hasHeaderToken("connection", "close")
            || request.hasHeaderToken("proxy-connection", "close")
            || (version == "HTTP/1.0" && !request.hasHeaderToken("connection", "keep-alive"))
        if method == "CONNECT" {
            return (errorPage(400, "CONNECT inside a tunnel is not supported.", close: true), true)
        }
        let originForm: RawRequest
        let target: HTTPTarget
        if let tunnel {
            // Inside a tunnel the target is the CONNECT authority; the request goes as sent.
            (originForm, target) = (request, tunnel)
        } else if let rewritten = ForwardRewrite.originForm(request) {
            (originForm, target) = rewritten
        } else {
            let message = "Gulp is a forward proxy: configure it as your HTTP proxy (absolute-form requests)."
            return (errorPage(400, message, close: clientWantsClose), clientWantsClose)
        }
        var options = SendOptions(recordAs: .proxy)
        options.clientAddress = client
        let forwarded = ForwardRewrite.strippingHopByHop(originForm)
        let result = await engine.send(forwarded, to: target, options: options)
        if let response = result.exchange.response, result.error == nil {
            let close =
                clientWantsClose || response.parsed.bodyFraming == .closeDelimited
                || response.hasHeaderToken("connection", "close")
            // An HTTP/2 upstream response is stored as `HTTP/2 200` text; an HTTP/1.1 client needs
            // HTTP/1.1 framing (status line, content-length or chunked trailers).
            return (HTTP2Text.http1Response(from: response), close)
        }
        let reason = result.error?.userDescription ?? "no response"
        let message = "Gulp could not complete the request to \(target.host): \(reason)."
        return (errorPage(502, message, close: clientWantsClose), clientWantsClose)
    }

    /// A small HTML error response. `close` announces that the proxy will close the connection after
    /// it, so a keep-alive client doesn't reuse a connection that is about to go away.
    static func errorPage(_ status: Int, _ message: String, close: Bool = false) -> [UInt8] {
        let reasons = [
            400: "Bad Request", 413: "Content Too Large", 431: "Request Header Fields Too Large",
            501: "Not Implemented",
        ]
        let reason = reasons[status] ?? "Bad Gateway"
        let escaped = message.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
        let body = "<html><body><h1>Gulp: \(status) \(reason)</h1><p>\(escaped)</p></body></html>\n"
        let head =
            "HTTP/1.1 \(status) \(reason)\r\nContent-Type: text/html; charset=utf-8\r\n"
            + "Content-Length: \(body.utf8.count)\r\n" + (close ? "Connection: close\r\n" : "") + "\r\n"
        return Array((head + body).utf8)
    }
}

extension ProxyConnection {
    /// `host:port` from a CONNECT request-target (`[v6]:port` accepted; the port is required).
    static func connectAuthority(_ request: RawRequest) -> (host: String, port: Int)? {
        let text = request.bytes[request.parsed.target].string()
        guard let colon = text.lastIndex(of: ":"), let port = Int(text[text.index(after: colon)...]),
            (1...65_535).contains(port)
        else { return nil }
        var host = String(text[..<colon])
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        return host.isEmpty ? nil : (host, port)
    }
}
