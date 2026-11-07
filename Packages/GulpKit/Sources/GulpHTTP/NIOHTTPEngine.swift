// GulpHTTP — the SwiftNIO implementation of `HTTPEngine`. M1 scope: HTTP/1 over plain TCP
// (HTTP-001…HTTP-005, HTTP-008…HTTP-010). TLS and HTTP/2 arrive in M3, WebSockets in M4,
// single-packet group sends in M5.

import Foundation
import GulpCore
import NIOCore
import NIOPosix

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

        /// Default settings.
        public init() {}
    }

    private let group: any EventLoopGroup
    private let configuration: Configuration
    private let pool: ConnectionPool
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
            outgoing, options: options, wire: nil, error: .other("HTTP/2 is implemented in M3"),
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

        if let refusal = unsupported(outgoing.target, options) {
            return await finish(
                outgoing, options: options, wire: nil, error: refusal, connectionID: 0, timing: timing)
        }
        let attempt = await perform(outgoing, options: options, pool: pool, start: start, timing: &timing)
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
            connectionID: attempt.connectionID, timing: timing)
    }

    private func unsupported(_ target: HTTPTarget, _ options: SendOptions) -> GulpNetworkError? {
        if target.scheme == .https {
            return .tlsFailure("HTTPS is implemented in M3 (GulpTLS); M1 sends plaintext HTTP/1 only")
        }
        switch options.httpVersion {
        case .http2, .http2PriorKnowledge: return .other("HTTP/2 is implemented in M3")
        case .auto, .http1_1: break
        }
        if case .proxy = options.upstreamProxy {
            return .upstreamProxyError("Upstream proxies (HTTP-006) are not implemented yet")
        }
        return nil
    }

    private struct Attempt {
        var wire: WireResponse?
        var error: GulpNetworkError?
        var connectionID: UInt64 = 0
        var writeStart = NIODeadline.now()
        var writeEnd = NIODeadline.now()
    }

    /// Get a connection, write, read; retry once on a stale pooled connection (HTTP-003).
    private func perform(
        _ outgoing: OutgoingRequest, options: SendOptions, pool: ConnectionPool, start: NIODeadline,
        timing: inout Timing
    ) async -> Attempt {
        let request = outgoing.request
        let key = PoolKey(target: outgoing.target, options: options)
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
            var reused = false
            if policy == .reuse, let idle = await pool.takeIdle(key) {
                channel = idle.channel
                connectionID = idle.id
                reused = true
                timing.dnsMs = nil
                timing.connectMs = nil
            } else {
                do {
                    channel = try await connect(
                        outgoing.target, options: options, deadline: totalDeadline, timing: &timing)
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
                && !request.hasHeaderToken("connection", "close") && !Task.isCancelled
            if keep {
                await pool.putIdle(key, channel: channel, id: connectionID)
            } else {
                channel.close(promise: nil)
            }
            await pool.releaseSlot(key)
            return Attempt(
                wire: wire, error: Task.isCancelled ? .cancelled : wire.error, connectionID: connectionID,
                writeStart: result.writeStart, writeEnd: result.writeEnd)
        }
        await pool.releaseSlot(key)
        return Attempt(error: .connectionReset)
    }

    /// Resolve (with overrides, HTTP-004) and connect (HTTP-005 connect timeout).
    private func connect(
        _ target: HTTPTarget, options: SendOptions, deadline: NIODeadline, timing: inout Timing
    ) async throws -> any Channel {
        let host = target.ipOverride ?? configuration.hostOverrides[target.host.lowercased()] ?? target.host
        let port = target.port
        let dnsStart = NIODeadline.now()
        let address: SocketAddress
        do {
            address = try await NIOThreadPool.singleton.runIfActive {
                try SocketAddress.makeAddressResolvingHost(host, port: port)
            }
        } catch {
            throw GulpNetworkError.dnsFailure(target.host)
        }
        let connectStart = NIODeadline.now()
        timing.dnsMs = milliseconds(from: dnsStart, to: connectStart)

        let configured = timeAmount(options.timeouts.connect)
        let remaining = max(deadline - connectStart, .milliseconds(1))
        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(min(configured, remaining))
            .channelOption(ChannelOptions.socketOption(.tcp_nodelay), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture(withResultOf: {
                    try channel.pipeline.syncOperations.addHandler(HTTP1ClientHandler())
                })
            }
        do {
            let channel = try await bootstrap.connect(to: address).get()
            timing.connectMs = milliseconds(from: connectStart, to: .now())
            return channel
        } catch {
            let mapped = HTTP1ClientHandler.networkError(error)
            // A connect cut short by the total budget is a total timeout, not a connect timeout.
            if mapped == .connectTimeout && remaining < configured { throw GulpNetworkError.totalTimeout }
            throw mapped
        }
    }

    private struct WireResult {
        var wire: WireResponse
        var writeStart: NIODeadline
        var writeEnd: NIODeadline
    }

    /// Write the exact request bytes and wait for the framed response.
    private func exchange(
        on channel: any Channel, request: RawRequest, options: SendOptions, totalDeadline: NIODeadline
    ) async -> WireResult {
        var buffer = channel.allocator.buffer(capacity: request.bytes.count)
        buffer.writeBytes(request.bytes.rawBytes)
        let promise = channel.eventLoop.makePromise(of: WireResponse.self)
        let command = RequestCommand(
            bytes: buffer, isHead: request.bytes[request.parsed.method].string() == "HEAD",
            maxResponseBytes: options.maxResponseBytes,
            firstByteTimeout: timeAmount(options.timeouts.firstByte),
            idleTimeout: timeAmount(options.timeouts.idleBetweenBytes), totalDeadline: totalDeadline,
            promise: promise)
        let writeStart = NIODeadline.now()
        let write = channel.writeAndFlush(command)
        // If the write never reaches the handler (channel already closed), fail the response here;
        // a second completion of the promise is ignored.
        write.whenFailure { promise.fail($0) }
        _ = try? await write.get()
        let writeEnd = NIODeadline.now()
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
        connectionID: UInt64, timing: Timing
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
            state: state, timing: timing, connectionID: connectionID, edited: edited)
        if let recorder { exchange.id = await recorder.record(exchange) }
        return ExchangeResult(exchange: exchange, error: error)
    }
}
