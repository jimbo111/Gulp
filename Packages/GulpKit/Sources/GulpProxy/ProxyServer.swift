// GulpProxy — the HTTP/1 forward proxy (F01 PRX-001…PRX-004). M2 scope: plain HTTP (absolute-form
// requests). CONNECT/TLS interception arrives in M3, invisible mode and the landing page later.

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
    private var listeners: [UUID: (server: any Channel, clients: ClientConnections)] = [:]

    /// Create a proxy that forwards (and, through the engine's recorder, records) via `engine`.
    public init(engine: any HTTPEngine) {
        self.engine = engine
    }

    /// Start a listener and return the port it is bound to. Bind failures (port in use, PRX-001)
    /// throw a `GulpError` with a user-facing message.
    @discardableResult
    public func start(_ config: ProxyListenerConfig) async throws -> Int {
        if listeners[config.id] != nil { await stop(config.id) }
        let engine = self.engine
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
                            items, channel: channel, engine: engine, client: client, pressure: pressure)
                    }
                    return channel.eventLoop.makeCompletedFuture(withResultOf: {
                        let handler = ProxyConnectionHandler(items: continuation, pressure: pressure)
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
    /// Forward this request.
    case request(RawRequest)
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

    private let items: AsyncStream<ProxyItem>.Continuation
    private let pressure: Backpressure
    private var buffer: [UInt8] = []
    private var sentContinue = false
    private var rejected = false

    init(items: AsyncStream<ProxyItem>.Continuation, pressure: Backpressure) {
        self.items = items
        self.pressure = pressure
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !rejected else { return }
        buffer.append(contentsOf: unwrapInboundIn(data).readableBytesView)
        loop: while true {
            switch RequestFramer.next(buffer) {
            case .request(let request, let length):
                buffer.removeFirst(length)
                sentContinue = false
                enqueue(.request(request), context: context)
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
        pressure: Backpressure
    ) async {
        for await item in items {
            let reply: (bytes: [UInt8], close: Bool)
            switch item {
            case .request(let request): reply = await forward(request, engine: engine, client: client)
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
            if reply.close {
                channel.close(promise: nil)
                break
            }
        }
    }

    /// Forward one request (PRX-002) and decide whether the client connection stays open (PRX-003).
    static func forward(
        _ request: RawRequest, engine: any HTTPEngine, client: String?
    ) async -> (bytes: [UInt8], close: Bool) {
        let method = request.bytes[request.parsed.method].string()
        let version = request.bytes[request.parsed.version].string()
        let clientWantsClose =
            request.hasHeaderToken("connection", "close")
            || request.hasHeaderToken("proxy-connection", "close")
            || (version == "HTTP/1.0" && !request.hasHeaderToken("connection", "keep-alive"))
        if method == "CONNECT" {
            let message = "HTTPS interception (CONNECT) arrives in milestone M3."
            return (errorPage(501, message, close: true), true)
        }
        guard let rewritten = ForwardRewrite.originForm(request) else {
            let message = "Gulp is a forward proxy: configure it as your HTTP proxy (absolute-form requests)."
            return (errorPage(400, message, close: clientWantsClose), clientWantsClose)
        }
        let (originForm, target) = rewritten
        var options = SendOptions(recordAs: .proxy)
        options.clientAddress = client
        let forwarded = ForwardRewrite.strippingHopByHop(originForm)
        let result = await engine.send(forwarded, to: target, options: options)
        if let response = result.exchange.response, result.error == nil {
            let close =
                clientWantsClose || response.parsed.bodyFraming == .closeDelimited
                || response.hasHeaderToken("connection", "close")
            return (response.wireBytes.rawBytes, close)
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
