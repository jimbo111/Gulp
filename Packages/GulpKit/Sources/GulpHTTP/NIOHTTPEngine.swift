// GulpHTTP — the SwiftNIO implementation of `HTTPEngine`. M1 scope: HTTP/1 over plain TCP
// (HTTP-001…HTTP-005, HTTP-008…HTTP-010). TLS and HTTP/2 arrive in M3, WebSockets in M4,
// single-packet group sends in M5.

import Foundation
import GulpCore
import GulpTLS
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import NIOSOCKS
import NIOSSL
import NIOTLS

/// Convert a Swift `Duration` to NIO's `TimeAmount`.
func timeAmount(_ duration: Duration) -> TimeAmount {
    let (seconds, attoseconds) = duration.components
    return .nanoseconds(seconds * 1_000_000_000 + attoseconds / 1_000_000_000)
}

/// Milliseconds between two deadlines.
func milliseconds(from start: NIODeadline, to end: NIODeadline) -> Double {
    Double((end - start).nanoseconds) / 1_000_000
}

/// The engine every tool sends through: raw bytes out, raw bytes in.
public final class NIOHTTPEngine: HTTPEngine {
    /// Engine-wide settings.
    public struct Configuration: Sendable {
        /// Settings → Network → Hostname resolution: host → IP (HTTP-004).
        public var hostOverrides: [String: String] = [:]
        /// Connections per pool key (HTTP-003).
        public var maxConnectionsPerKey = 6
        /// Idle pooled connections older than this are closed instead of reused (HTTP-003).
        public var idleConnectionTimeout: Duration = .seconds(30)
        /// Upstream proxy rules, first match wins (PRX-041, HTTP-006). No match connects directly.
        public var upstreamRules: [UpstreamRule] = []

        /// Default settings.
        public init() {}
    }

    private let group: any EventLoopGroup
    private let configuration: Configuration
    private let pool: ConnectionPool
    private let tlsContexts = TLSContextCache()
    private let requestHooks: [any RequestHook]
    private let responseHooks: [any ResponseHook]
    private let recorder: (any ExchangeRecorder)?

    /// Create an engine. Hooks run in array order; `recorder` stores every exchange if given.
    public init(
        group: any EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
        configuration: Configuration = Configuration(), requestHooks: [any RequestHook] = [],
        responseHooks: [any ResponseHook] = [], recorder: (any ExchangeRecorder)? = nil
    ) {
        self.group = group
        self.configuration = configuration
        self.pool = ConnectionPool(
            maxPerKey: configuration.maxConnectionsPerKey,
            idleTimeout: timeAmount(configuration.idleConnectionTimeout))
        self.requestHooks = requestHooks
        self.responseHooks = responseHooks
        self.recorder = recorder
    }

    /// Close every pooled connection.
    public func shutdown() async {
        await pool.closeAll()
    }

    // MARK: HTTPEngine

    /// Send raw HTTP/1 bytes (HTTP-001). Failures are returned as data in the exchange.
    public func send(
        _ request: RawRequest, to target: HTTPTarget, options: SendOptions
    ) async -> ExchangeResult {
        await send(request, to: target, options: options, pool: pool)
    }

    /// HTTP/2 arrives in M3; until then this records a failed exchange.
    public func send(
        _ request: H2RequestSpec, to target: HTTPTarget, options: SendOptions
    ) async -> ExchangeResult {
        let outgoing = OutgoingRequest(request: RawRequest(Bytes()), target: target)
        return await finish(
            outgoing, options: options, wire: nil, error: .other("HTTP/2 is implemented in M3b"),
            connectionID: 0, timing: Timing())
    }

    /// Send a group (HTTP-030…HTTP-032). Single-packet mode arrives in M5.
    public func sendGroup(
        _ items: [GroupItem], mode: GroupSendMode, options: SendOptions
    ) async -> [ExchangeResult] {
        var adjusted = options
        switch mode {
        case .sequentialSingleConnection:
            // A private one-slot pool keeps every item on one keep-alive connection per target.
            let single = ConnectionPool(
                maxPerKey: 1, idleTimeout: timeAmount(configuration.idleConnectionTimeout))
            adjusted.connection = .reuse
            var results: [ExchangeResult] = []
            for item in items {
                results.append(await send(item.request, to: item.target, options: adjusted, pool: single))
            }
            await single.closeAll()
            return results
        case .sequentialSeparateConnections:
            adjusted.connection = .newAndClose
            var results: [ExchangeResult] = []
            for item in items {
                results.append(await send(item.request, to: item.target, options: adjusted))
            }
            return results
        case .parallel:
            adjusted.connection = .newAndClose
            let groupOptions = adjusted
            return await withTaskGroup(of: (Int, ExchangeResult).self) { group in
                for (index, item) in items.enumerated() {
                    group.addTask {
                        let result = await self.send(item.request, to: item.target, options: groupOptions)
                        return (index, result)
                    }
                }
                var ordered = [ExchangeResult?](repeating: nil, count: items.count)
                for await (index, result) in group { ordered[index] = result }
                return ordered.compactMap { $0 }
            }
        case .singlePacket:
            var results: [ExchangeResult] = []
            for item in items {
                let outgoing = OutgoingRequest(request: item.request, target: item.target)
                results.append(
                    await finish(
                        outgoing, options: options, wire: nil,
                        error: .other("Single-packet group sends (HTTP-033/034) are implemented in M5"),
                        connectionID: 0, timing: Timing()))
            }
            return results
        }
    }

    /// WebSockets arrive in M4 (F03 §2).
    public func openWebSocket(
        _ upgrade: RawRequest, to target: HTTPTarget, options: SendOptions
    ) async throws -> WebSocketSession {
        throw GulpError(message: "WebSockets are implemented in M4", underlying: nil)
    }

    // MARK: send pipeline

    func send(
        _ request: RawRequest, to target: HTTPTarget, options: SendOptions, pool: ConnectionPool
    ) async -> ExchangeResult {
        let start = NIODeadline.now()
        var timing = Timing(start: Date())
        var outgoing = OutgoingRequest(request: request, target: target)
        let context = HookContext(source: options.recordAs)
        do {
            for hook in requestHooks where options.applyHooks.contains(hook.kind) {
                try await hook.willSend(&outgoing, context: context)
            }
        } catch {
            return await finish(
                outgoing, options: options, wire: nil, error: .other("Request hook failed: \(error)"),
                connectionID: 0, timing: timing)
        }
        // The only byte rewrites, both opt-in (HTTP-008).
        if options.normalizeLineEndings { outgoing.request = outgoing.request.normalizingLineEndings() }
        if options.updateContentLength { outgoing.request = outgoing.request.updatingContentLength() }

        let route = upstreamRoute(for: outgoing.target, options: options)
        if let refusal = unsupported(outgoing.target, options, route: route) {
            return await finish(
                outgoing, options: options, wire: nil, error: refusal, connectionID: 0, timing: timing)
        }
        // Classic (non-tunnelled) HTTP proxying must rewrite the request line to absolute-form.
        if let route, route.kind == .http, !route.tunnelPlainHTTP, outgoing.target.scheme == .http {
            outgoing.request = outgoing.request.forPlainHTTPProxy(
                target: outgoing.target, proxyAuthorization: route.basicAuthorization)
        }
        let attempt = await perform(
            outgoing, options: options, route: route, pool: pool, start: start, timing: &timing)
        if let wire = attempt.wire {
            timing.requestWriteMs = milliseconds(from: attempt.writeStart, to: attempt.writeEnd)
            if let first = wire.firstByteAt {
                timing.ttfbMs = milliseconds(from: attempt.writeEnd, to: first)
                if let last = wire.lastByteAt { timing.downloadMs = milliseconds(from: first, to: last) }
            }
        }
        timing.totalMs = milliseconds(from: start, to: .now())
        return await finish(
            outgoing, options: options, wire: attempt.wire, error: attempt.error,
            connectionID: attempt.connectionID, timing: timing, tls: attempt.tls)
    }

    /// The upstream proxy for `target` (HTTP-006): the per-send override, else the first matching
    /// rule (PRX-041); nil connects directly.
    func upstreamRoute(for target: HTTPTarget, options: SendOptions) -> UpstreamProxy? {
        switch options.upstreamProxy {
        case .direct: return nil
        case .proxy(let proxy): return proxy
        case .useRules: return configuration.upstreamRules.first { $0.matches(target.host) }?.proxy
        }
    }

    private func unsupported(
        _ target: HTTPTarget, _ options: SendOptions, route: UpstreamProxy?
    ) -> GulpNetworkError? {
        switch options.httpVersion {
        case .http2, .http2PriorKnowledge: return .other("HTTP/2 is implemented in M3b")
        case .auto, .http1_1: break
        }
        if let route, route.kind == .socks5, route.username != nil {
            return .upstreamProxyError("SOCKS5 username/password authentication is not supported yet")
        }
        return nil
    }

    private struct Attempt {
        var wire: WireResponse?
        var error: GulpNetworkError?
        var connectionID: UInt64 = 0
        var writeStart = NIODeadline.now()
        var writeEnd = NIODeadline.now()
        var tls: TLSInfo?
    }

    /// Get a connection, write, read; retry once on a stale pooled connection (HTTP-003).
    private func perform(
        _ outgoing: OutgoingRequest, options: SendOptions, route: UpstreamProxy?, pool: ConnectionPool,
        start: NIODeadline, timing: inout Timing
    ) async -> Attempt {
        let request = outgoing.request
        let key = PoolKey(target: outgoing.target, options: options, route: route)
        let method = request.bytes[request.parsed.method].string()
        let idempotent = ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"].contains(method)
        let totalDeadline = start + timeAmount(options.timeouts.total)
        var policy = options.connection

        await pool.acquireSlot(key)
        for attemptNumber in 1...2 {
            if Task.isCancelled {
                await pool.releaseSlot(key)
                return Attempt(error: .cancelled)
            }
            let channel: any Channel
            let connectionID: UInt64
            let tls: TLSInfo?
            var reused = false
            if policy == .reuse, let idle = await pool.takeIdle(key) {
                channel = idle.channel
                connectionID = idle.id
                tls = idle.tls
                reused = true
                timing.dnsMs = nil
                timing.connectMs = nil
                timing.tlsMs = nil
            } else {
                do {
                    (channel, tls) = try await connect(
                        outgoing.target, route: route, options: options, deadline: totalDeadline,
                        timing: &timing)
                } catch {
                    await pool.releaseSlot(key)
                    let mapped = (error as? GulpNetworkError) ?? HTTP1ClientHandler.networkError(error)
                    return Attempt(error: Task.isCancelled ? .cancelled : mapped)
                }
                connectionID = await pool.newConnectionID()
            }

            // Cancelling the task closes the channel; the handler then fails the response (HTTP-009).
            let result = await withTaskCancellationHandler {
                await self.exchange(
                    on: channel, request: request, options: options, totalDeadline: totalDeadline)
            } onCancel: {
                channel.close(promise: nil)
            }
            let wire = result.wire

            if reused, attemptNumber == 1, !wire.receivedAny, idempotent, !Task.isCancelled,
                wire.error == .connectionReset || wire.error == .incompleteResponse
            {
                channel.close(promise: nil)
                policy = .new
                continue
            }

            let keep =
                wire.error == nil && wire.reusable && options.connection != .newAndClose
                && KeepAlive.requestAllowsReuse(request) && !Task.isCancelled
            if keep {
                let timeout = KeepAlive.serverTimeout(wire.bytes)
                await pool.putIdle(key, channel: channel, id: connectionID, serverTimeout: timeout, tls: tls)
            } else {
                channel.close(promise: nil)
            }
            await pool.releaseSlot(key)
            return Attempt(
                wire: wire, error: Task.isCancelled ? .cancelled : wire.error, connectionID: connectionID,
                writeStart: result.writeStart, writeEnd: result.writeEnd, tls: tls)
        }
        await pool.releaseSlot(key)
        return Attempt(error: .connectionReset)
    }

    /// The host to connect to for `target` after the override table and per-target IP (HTTP-004).
    private func effectiveHost(_ target: HTTPTarget) -> String {
        target.ipOverride ?? configuration.hostOverrides[target.host.lowercased()] ?? target.host
    }

    /// Resolve (with overrides, HTTP-004) and connect (HTTP-005 connect timeout), directly or through
    /// an upstream proxy (HTTP-006): SOCKS5 via NIOSOCKS, or an HTTP proxy's CONNECT tunnel.
    private func connect(
        _ target: HTTPTarget, route: UpstreamProxy?, options: SendOptions, deadline: NIODeadline,
        timing: inout Timing
    ) async throws -> (any Channel, TLSInfo?) {
        let proxyHost = route.map { configuration.hostOverrides[$0.host.lowercased()] ?? $0.host }
        let host = proxyHost ?? effectiveHost(target)
        let port = route?.port ?? target.port
        let dnsStart = NIODeadline.now()
        let address: SocketAddress
        do {
            address = try await NIOThreadPool.singleton.runIfActive {
                try SocketAddress.makeAddressResolvingHost(host, port: port)
            }
        } catch {
            throw GulpNetworkError.dnsFailure(route?.host ?? target.host)
        }
        let connectStart = NIODeadline.now()
        timing.dnsMs = milliseconds(from: dnsStart, to: connectStart)

        let configured = timeAmount(options.timeouts.connect)
        let remaining = max(deadline - connectStart, .milliseconds(1))
        let socksTarget: SOCKSAddress? =
            route?.kind == .socks5 ? .domain(effectiveHost(target), port: target.port) : nil
        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(min(configured, remaining))
            .channelOption(ChannelOptions.tcpOption(.tcp_nodelay), value: 1)
            .channelInitializer { [socksTarget] channel in
                channel.eventLoop.makeCompletedFuture(withResultOf: {
                    if let socksTarget {
                        // Buffers our writes until the SOCKS5 handshake completes.
                        let socks = SOCKSClientHandler(targetAddress: socksTarget)
                        try channel.pipeline.syncOperations.addHandler(socks)
                    }
                    try channel.pipeline.syncOperations.addHandler(HTTP1ClientHandler())
                })
            }
        let channel: any Channel
        do {
            channel = try await bootstrap.connect(to: address).get()
        } catch {
            let mapped = HTTP1ClientHandler.networkError(error)
            // A connect cut short by the total budget is a total timeout, not a connect timeout.
            if mapped == .connectTimeout && remaining < configured { throw GulpNetworkError.totalTimeout }
            guard route != nil else { throw mapped }
            throw GulpNetworkError.upstreamProxyError("Cannot reach proxy \(host):\(port): \(mapped.code)")
        }
        if let route, route.kind == .http, target.scheme == .https || route.tunnelPlainHTTP {
            try await establishTunnel(
                on: channel, to: target, via: route, options: options, deadline: deadline)
        }
        timing.connectMs = milliseconds(from: connectStart, to: .now())
        guard target.scheme == .https else { return (channel, nil) }
        let tlsStart = NIODeadline.now()
        do {
            let tls = try await startTLS(on: channel, target: target, options: options, deadline: deadline)
            timing.tlsMs = milliseconds(from: tlsStart, to: .now())
            return (channel, tls)
        } catch {
            channel.close(promise: nil)
            throw error
        }
    }

    /// TLS to the server (TLS-008/009), inserted under the HTTP handler on an open connection (direct,
    /// SOCKS, or inside a CONNECT tunnel). The chain is always captured and validated; validation
    /// is enforced only when `options.tls.validateCertificates` is on.
    private func startTLS(
        on channel: any Channel, target: HTTPTarget, options: SendOptions, deadline: NIODeadline
    ) async throws -> TLSInfo {
        let settings = options.tls
        let context: NIOSSLContext
        do {
            context = try await tlsContexts.context(for: settings)
        } catch {
            throw GulpNetworkError.tlsFailure("TLS settings rejected: \(error)")
        }
        let nameForChecks = target.sniOverride ?? target.host
        let serverName = UpstreamTLS.serverName(for: nameForChecks)
        let capture = HandshakeCapture()
        let done = channel.eventLoop.makePromise(of: String?.self)
        let budget = min(deadline, .now() + timeAmount(options.timeouts.tlsHandshake))
        try await channel.eventLoop.submit {
            let tls = try NIOSSLClientHandler(
                context: context, serverHostname: serverName,
                customVerificationCallback: { certificates, verdict in
                    let chain = certificates.compactMap { try? $0.toDERBytes() }
                    Task {
                        let validation = await UpstreamTLS.validate(chain: chain, host: nameForChecks)
                        capture.set(chain: chain, validation: validation)
                        let enforce = settings.validateCertificates && validation != .ok
                        verdict.succeed(enforce ? .failed : .certificateVerified)
                    }
                })
            let operations = channel.pipeline.syncOperations
            let http = try operations.handler(type: HTTP1ClientHandler.self)
            try operations.addHandler(tls, position: .before(http))
            try operations.addHandler(TLSHandshakeWaiter(done: done), position: .before(http))
        }.get()
        let timeout = channel.eventLoop.scheduleTask(deadline: budget) {
            done.fail(GulpNetworkError.tlsHandshakeTimeout)
            channel.close(promise: nil)
        }
        defer { timeout.cancel() }
        let negotiated: String?
        do {
            negotiated = try await done.futureResult.get()
        } catch let error as GulpNetworkError {
            throw error
        } catch {
            if case .failed(let reason) = capture.validation, settings.validateCertificates {
                throw GulpNetworkError.tlsFailure("certificate validation failed: \(reason)")
            }
            throw GulpNetworkError.tlsFailure("TLS handshake with \(target.host) failed: \(error)")
        }
        let version = try? await channel.nioSSL_tlsVersion().get()
        return TLSInfo(
            version: version.flatMap(TLSProtocolVersion.init)?.rawValue ?? "TLS",
            cipherSuite: "", alpn: negotiated, serverChainSHA256: UpstreamTLS.fingerprints(capture.chain),
            validation: capture.validation)
    }

    /// `CONNECT host:port` through an HTTP proxy; a 2xx turns the connection into a byte tunnel, so
    /// the request that follows is written exactly as given.
    private func establishTunnel(
        on channel: any Channel, to target: HTTPTarget, via proxy: UpstreamProxy, options: SendOptions,
        deadline: NIODeadline
    ) async throws {
        let host = effectiveHost(target)
        let authority = host.contains(":") ? "[\(host)]:\(target.port)" : "\(host):\(target.port)"
        var text = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\n"
        if let authorization = proxy.basicAuthorization {
            text += "Proxy-Authorization: \(authorization)\r\n"
        }
        text += "\r\n"
        let result = await exchange(
            on: channel, request: RawRequest(Bytes(text)), options: options, totalDeadline: deadline,
            isConnect: true)
        let status = RawResponse(Bytes(result.wire.bytes)).parsed.statusCode
        guard result.wire.error == nil, (200..<300).contains(status) else {
            channel.close(promise: nil)
            let reason = result.wire.error.map(\.code) ?? "status \(status)"
            let message = "CONNECT \(authority) via \(proxy.host) failed: \(reason)"
            throw GulpNetworkError.upstreamProxyError(message)
        }
    }

    private struct WireResult {
        var wire: WireResponse
        var writeStart: NIODeadline
        var writeEnd: NIODeadline
    }

    /// Write the exact request bytes and wait for the framed response.
    private func exchange(
        on channel: any Channel, request: RawRequest, options: SendOptions, totalDeadline: NIODeadline,
        isConnect: Bool = false
    ) async -> WireResult {
        var buffer = channel.allocator.buffer(capacity: request.bytes.count)
        buffer.writeBytes(request.bytes.rawBytes)
        let promise = channel.eventLoop.makePromise(of: WireResponse.self)
        let command = RequestCommand(
            bytes: buffer, isHead: request.bytes[request.parsed.method].string() == "HEAD",
            isConnect: isConnect, maxResponseBytes: options.maxResponseBytes,
            firstByteTimeout: timeAmount(options.timeouts.firstByte),
            idleTimeout: timeAmount(options.timeouts.idleBetweenBytes), totalDeadline: totalDeadline,
            promise: promise)
        let writeStart = NIODeadline.now()
        // The explicit-promise form: in an async context the plain `writeAndFlush(_:)` resolves to
        // NIO's `async throws` overload, but we need the future to chain a failure handler onto.
        let written = channel.eventLoop.makePromise(of: Void.self)
        // If the write never reaches the handler (channel already closed), fail the response here;
        // a second completion of the promise is ignored.
        written.futureResult.whenFailure { promise.fail($0) }
        // Stamp the write's completion on the event loop, at the moment it happens: the task resumes
        // later, by which time (on loopback) the first response byte may already have arrived, which
        // made time-to-first-byte negative (HTTP-010).
        let writeDone = written.futureResult.map { NIODeadline.now() }
        channel.writeAndFlush(command, promise: written)
        let writeEnd = (try? await writeDone.get()) ?? NIODeadline.now()
        let wire: WireResponse
        do {
            wire = try await promise.futureResult.get()
        } catch {
            wire = WireResponse(
                bytes: [], interim: [], error: HTTP1ClientHandler.networkError(error), firstByteAt: nil,
                lastByteAt: nil, reusable: false, receivedAny: false)
        }
        return WireResult(wire: wire, writeStart: writeStart, writeEnd: writeEnd)
    }

    /// Build the exchange (response hooks, derived fields), record it, and wrap it as a result.
    private func finish(
        _ outgoing: OutgoingRequest, options: SendOptions, wire: WireResponse?, error: GulpNetworkError?,
        connectionID: UInt64, timing: Timing, tls: TLSInfo? = nil
    ) async -> ExchangeResult {
        let isHead = outgoing.request.bytes[outgoing.request.parsed.method].string() == "HEAD"
        var response: RawResponse?
        if let wire, !wire.bytes.isEmpty {
            let interim = wire.interim.map { RawResponse(Bytes($0)) }
            response = RawResponse(Bytes(wire.bytes), interim: interim, headRequest: isHead)
        }
        var edited: EditInfo?
        if let original = response, error == nil, !responseHooks.isEmpty {
            var modified = original
            let context = HookContext(source: options.recordAs)
            for hook in responseHooks where options.applyHooks.contains(hook.kind) {
                try? await hook.didReceive(&modified, for: outgoing, context: context)
            }
            if modified != original {
                edited = EditInfo(originalResponse: original, editedBy: options.recordAs)
                response = modified
            }
        }
        let state: ExchangeState
        if let error {
            state = .failed(error)
        } else {
            state = .complete
        }
        var exchange = Exchange(
            source: options.recordAs, target: outgoing.target, request: outgoing.request, response: response,
            state: state, timing: timing, clientAddress: options.clientAddress, connectionID: connectionID,
            edited: edited)
        exchange.tls = tls
        if let recorder { exchange.id = await recorder.record(exchange) }
        return ExchangeResult(exchange: exchange, error: error)
    }
}

extension UpstreamProxy {
    /// `Basic <base64(user:pass)>` when credentials are configured.
    var basicAuthorization: String? {
        guard let username else { return nil }
        return "Basic " + Data("\(username):\(password ?? "")".utf8).base64EncodedString()
    }
}

/// Keep-alive decisions that depend on the request and on the server's hints (HTTP-003).
enum KeepAlive {
    /// False when the request itself ends the connection: `Connection: close`, or HTTP/1.0 without
    /// `Connection: keep-alive` (the server will close after responding).
    static func requestAllowsReuse(_ request: RawRequest) -> Bool {
        if request.hasHeaderToken("connection", "close") { return false }
        let version = request.bytes[request.parsed.version].string()
        return version != "HTTP/1.0" || request.hasHeaderToken("connection", "keep-alive")
    }

    /// The server's `Keep-Alive: timeout=N` minus a one-second margin, read from the response's
    /// header block only.
    static func serverTimeout(_ response: [UInt8]) -> TimeAmount? {
        let (end, terminator) = HTTP1.headerBlockEnd(response)
        guard terminator != 0 else { return nil }
        let head = RawResponse(Bytes(Array(response[..<end])))
        guard let value = head.headerValue("keep-alive")?.string().lowercased() else { return nil }
        for parameter in value.split(separator: ",") {
            let pair = parameter.split(separator: "=", maxSplits: 1).map {
                String($0).trimmingCharacters(in: .whitespaces)
            }
            if pair.count == 2, pair[0] == "timeout", let seconds = Int(pair[1]), seconds >= 0 {
                return .seconds(Int64(max(0, seconds - 1)))
            }
        }
        return nil
    }
}

/// One NIOSSL client context per distinct settings (building contexts is the expensive part).
actor TLSContextCache {
    private var contexts: [UpstreamTLSSettings: NIOSSLContext] = [:]

    func context(for settings: UpstreamTLSSettings) throws -> NIOSSLContext {
        if let context = contexts[settings] { return context }
        let context = try UpstreamTLS.makeContext(settings)
        contexts[settings] = context
        return context
    }
}

/// What the verification callback saw, read after the handshake.
final class HandshakeCapture: Sendable {
    private let state = NIOLockedValueBox<(chain: [[UInt8]], validation: TLSValidation)>(([], .notChecked))

    func set(chain: [[UInt8]], validation: TLSValidation) {
        state.withLockedValue { $0 = (chain, validation) }
    }

    var chain: [[UInt8]] { state.withLockedValue { $0.chain } }
    var validation: TLSValidation { state.withLockedValue { $0.validation } }
}

/// Completes `done` with the negotiated ALPN protocol when the TLS handshake finishes, or with the
/// error that ended it. Afterwards it only passes events through.
final class TLSHandshakeWaiter: ChannelInboundHandler {
    typealias InboundIn = NIOAny
    private let done: EventLoopPromise<String?>

    init(done: EventLoopPromise<String?>) {
        self.done = done
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? TLSUserEvent, case .handshakeCompleted(let negotiated) = event {
            done.succeed(negotiated)  // later completions of the promise are ignored by NIO
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        done.fail(error)
        context.fireErrorCaught(error)
    }

    func channelInactive(context: ChannelHandlerContext) {
        done.fail(GulpNetworkError.connectionReset)
        context.fireChannelInactive()
    }
}
