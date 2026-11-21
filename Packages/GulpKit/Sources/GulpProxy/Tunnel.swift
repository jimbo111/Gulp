// GulpProxy — what happens inside a CONNECT tunnel (F01 PRX-005…PRX-007).
//
// After answering `200 Connection established`, the proxy looks at the first bytes the client sends:
// a TLS ClientHello (0x16) is intercepted with a leaf minted for its SNI (or spliced through untouched
// when the host is on the pass-through list); anything else is plain HTTP inside the tunnel (F01 §5).
//
// Concept: the sniffer sits in front of the HTTP handler, buffers until it can decide, then inserts
// the TLS server handler behind itself, hands it the buffered bytes, and removes itself — so the TLS
// handler sees the ClientHello exactly as the client sent it.

import GulpCore
import GulpHTTP
import GulpTLS
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import NIOSSL

/// TLS interception settings for a proxy (F01 PRX-006/PRX-007, F02).
public struct ProxyTLSOptions: Sendable {
    /// Mints leaves signed by the Gulp CA.
    public var minter: LeafMinter
    /// Host globs (`*.apple.com`) whose TLS is spliced through without decrypting (PRX-007).
    public var passThroughHosts: [String]
    /// PRX-008 "Force HTTP/1.1 to client": never offer h2 to the client.
    public var forceHTTP1ToClient: Bool
    /// PRX-008 "Force HTTP/1.1 to server": never offer h2 upstream.
    public var forceHTTP1ToServer: Bool

    /// Interception with `minter`; hosts matching `passThroughHosts` are not decrypted.
    public init(
        minter: LeafMinter, passThroughHosts: [String] = [], forceHTTP1ToClient: Bool = false,
        forceHTTP1ToServer: Bool = false
    ) {
        self.minter = minter
        self.passThroughHosts = passThroughHosts
        self.forceHTTP1ToClient = forceHTTP1ToClient
        self.forceHTTP1ToServer = forceHTTP1ToServer
    }

    /// Whether `host` is on the pass-through list.
    public func passesThrough(_ host: String) -> Bool {
        passThroughHosts.contains { UpstreamRule(hostPattern: $0, proxy: nil).matches(host) }
    }
}

/// How the proxy talks to servers for one client connection: the engine and the send options every
/// forwarded request (and the ALPN pre-connect) uses, so they share pooled connections.
struct ProxyUpstream: Sendable {
    let engine: any HTTPEngine
    let client: String?
    let forceHTTP1: Bool
    var intercept: InterceptQueue?
    var matchReplace: MatchReplaceHook?
    /// Where WebSocket connections and messages are recorded (PRX-031).
    var webSockets: (any WebSocketRecorder)?

    var options: SendOptions {
        var options = SendOptions(recordAs: .proxy)
        options.clientAddress = client
        options.httpVersion = forceHTTP1 ? .http1_1 : .auto
        return options
    }

    /// What the client gets back for one forwarded request.
    enum Reply: Sendable {
        case response(RawResponse)
        /// Already written to the client as it arrived (PRX-050); `complete` is false when the
        /// upstream failed part-way (the client connection must then be closed).
        case streamed(RawResponse?, complete: Bool)
        case failed(String)
        case dropped
    }

    /// Forward `request` to `target` through the engine, with intercept (PRX-010…PRX-014) on both
    /// legs: a held request may come back edited (sent with an updated Content-Length, PRX-018, and
    /// recorded with its original, PRX-012) or dropped; a held response may be edited or dropped.
    func send(
        _ request: RawRequest, to target: HTTPTarget, streamTo client: (any Channel)? = nil
    ) async -> Reply {
        var options = self.options
        let streamed = StreamedFlag()
        if let client, await canStream() {
            options.onResponseBytes = { bytes in
                streamed.set()
                client.writeAndFlush(client.allocator.buffer(bytes: bytes), promise: nil)
            }
        }
        var outgoing = request
        var requestWasHeld = false
        if let intercept {
            let (decision, held) = await intercept.holdRequest(request, target: target)
            requestWasHeld = held
            switch decision {
            case .drop:
                return .dropped
            case .forward(let edited?):
                outgoing = RawRequest(edited).updatingContentLength()
                if outgoing != request { options.originalRequest = request }
            case .forward(nil):
                break
            }
        }
        let result = await engine.send(outgoing, to: target, options: options)
        if streamed.isSet { return .streamed(result.exchange.response, complete: result.error == nil) }
        guard let response = result.exchange.response, result.error == nil else {
            return .failed(result.error?.userDescription ?? "no response")
        }
        guard let intercept else { return .response(response) }
        let (decision, _) = await intercept.holdResponse(
            response, for: outgoing, target: target, requestWasHeld: requestWasHeld)
        switch decision {
        case .drop: return .dropped
        case .forward(let edited?):
            return .response(RawResponse(edited, headRequest: response.isHeadResponse))
        case .forward(nil): return .response(response)
        }
    }
}

extension ProxyUpstream {
    /// Responses stream to the client unless something must see the whole response first: response
    /// interception or a response Match & Replace rule (F01 §4.3).
    func canStream() async -> Bool {
        if let intercept, await intercept.interceptResponses { return false }
        return !(matchReplace?.rewritesResponses(for: .proxy) ?? false)
    }
}

/// Set once the first streamed byte has gone to the client.
final class StreamedFlag: Sendable {
    private let value = NIOLockedValueBox(false)

    func set() { value.withLockedValue { $0 = true } }

    var isSet: Bool { value.withLockedValue { $0 } }
}

/// Sent down the pipeline once `200 Connection established` is written: start sniffing.
struct TunnelReady: Sendable {
    let host: String
    let port: Int
}

/// Sent by the sniffer: requests on this connection now go to `target` (origin-form).
struct TunnelTarget: Sendable {
    let target: HTTPTarget
}

/// Decides what a tunnel carries, then gets out of the way.
final class TunnelSniffer: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer

    private enum State {
        case sniffing
        case preparing
        case done
    }

    private let host: String
    private let port: Int
    private let tls: ProxyTLSOptions
    private let upstream: ProxyUpstream
    private var pending: [UInt8]
    private var state = State.sniffing

    init(host: String, port: Int, tls: ProxyTLSOptions, upstream: ProxyUpstream, initial: [UInt8]) {
        self.host = host
        self.port = port
        self.tls = tls
        self.upstream = upstream
        pending = initial
    }

    func handlerAdded(context: ChannelHandlerContext) {
        if !pending.isEmpty { sniff(context: context) }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let bytes = unwrapInboundIn(data)
        switch state {
        case .sniffing:
            pending += bytes.readableBytesView
            sniff(context: context)
        case .preparing:
            pending += bytes.readableBytesView
        case .done:
            context.fireChannelRead(data)
        }
    }

    private func sniff(context: ChannelHandlerContext) {
        switch ClientHelloParser.sniff(pending) {
        case .needMoreData:
            if pending.count > ClientHelloParser.maxBytes { context.close(promise: nil) }
        case .malformed:
            context.close(promise: nil)
        case .notTLS:
            // Plain HTTP inside the tunnel (e.g. a WebSocket to port 80 via CONNECT).
            handOver(context: context, to: HTTPTarget(scheme: .http, host: host, port: port), adding: nil)
        case .hello(let hello):
            state = .preparing
            let name = hello.serverName.map(HostName.normalize) ?? host
            if tls.passesThrough(name) || tls.passesThrough(host) {
                startRelay(context: context)
            } else {
                startInterception(context: context, serverName: name, clientALPN: hello.alpn)
            }
        }
    }

    /// Mint (off the event loop), then install the TLS server handler and hand over the ClientHello.
    private func startInterception(
        context: ChannelHandlerContext, serverName: String, clientALPN: [String]
    ) {
        let loop = context.eventLoop
        let bound = NIOLoopBound((self, context), eventLoop: loop)
        let minter = tls.minter
        var target = HTTPTarget(scheme: .https, host: host, port: port)
        if serverName != HostName.normalize(host) { target.sniOverride = serverName }
        let upstream = target
        let engine = self.upstream.engine
        let options = self.upstream.options
        let mayOfferH2 = clientALPN.contains("h2") && !tls.forceHTTP1ToClient
        Task {
            do {
                // PRX-008 ALPN mirroring: offer the client h2 only if it asked for h2 AND the real
                // server chose h2 (the pre-connect stays pooled for the requests that follow).
                var alpn = ["http/1.1"]
                if mayOfferH2, await engine.negotiatedProtocol(for: upstream, options: options) == "h2" {
                    alpn = ["h2"]
                }
                let ssl = try await minter.serverContext(for: serverName, alpn: alpn)
                loop.execute {
                    let (sniffer, context) = bound.value
                    let server = NIOSSLServerHandler(context: ssl)
                    sniffer.handOver(context: context, to: upstream, adding: server)
                }
            } catch {
                loop.execute { bound.value.1.close(promise: nil) }
            }
        }
    }

    /// Point the HTTP handler at `target`, optionally insert `handler` behind the sniffer, replay
    /// the buffered bytes into whatever follows, and leave the pipeline.
    private func handOver(
        context: ChannelHandlerContext, to target: HTTPTarget, adding handler: (any ChannelHandler)?
    ) {
        let operations = context.pipeline.syncOperations
        do {
            if let handler { try operations.addHandler(handler, position: .after(self)) }
        } catch {
            context.close(promise: nil)
            return
        }
        state = .done
        context.fireUserInboundEventTriggered(TunnelTarget(target: target))
        if !pending.isEmpty {
            var buffer = context.channel.allocator.buffer(capacity: pending.count)
            buffer.writeBytes(pending)
            pending = []
            context.fireChannelRead(wrapInboundOut(buffer))
        }
        context.pipeline.removeHandler(context: context, promise: nil)
    }

    /// PRX-007: splice the bytes to the real server without decrypting: a `RelayHandler` on each
    /// side, the buffered ClientHello first.
    private func startRelay(context: ChannelHandlerContext) {
        let client = context.channel
        let bound = NIOLoopBound((self, context), eventLoop: context.eventLoop)
        ClientBootstrap(group: context.eventLoop)
            .channelInitializer { upstream in
                upstream.eventLoop.makeCompletedFuture {
                    try upstream.pipeline.syncOperations.addHandler(RelayHandler(peer: client))
                }
            }
            .connect(host: host, port: port)
            .whenComplete { result in
                let (sniffer, context) = bound.value
                switch result {
                case .success(let upstream):
                    guard client.isActive else {
                        upstream.close(promise: nil)  // the client left while we connected
                        return
                    }
                    sniffer.state = .done
                    upstream.writeAndFlush(upstream.allocator.buffer(bytes: sniffer.pending), promise: nil)
                    sniffer.pending = []
                    do {
                        let relay = RelayHandler(peer: upstream)
                        try context.pipeline.syncOperations.addHandler(relay, position: .after(sniffer))
                        context.pipeline.removeHandler(context: context, promise: nil)
                    } catch {
                        upstream.close(promise: nil)
                        context.close(promise: nil)
                    }
                case .failure:
                    context.close(promise: nil)
                }
            }
    }
}

/// One side of a pass-through splice (PRX-007): copies the bytes read here to `peer`, closes `peer`
/// when this side ends, and stops `peer` reading while this side can't take more writes — so a fast
/// sender and a slow receiver can't grow the proxy's buffers without bound. Both channels share an
/// event loop.
final class RelayHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private let peer: any Channel

    init(peer: any Channel) {
        self.peer = peer
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        peer.writeAndFlush(unwrapInboundIn(data), promise: nil)
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        peer.setOption(ChannelOptions.autoRead, value: context.channel.isWritable).whenComplete { _ in }
        context.fireChannelWritabilityChanged()
    }

    func channelInactive(context: ChannelHandlerContext) {
        peer.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        context.close(promise: nil)
    }
}
