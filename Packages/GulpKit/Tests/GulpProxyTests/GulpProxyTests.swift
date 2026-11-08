import GulpCore
import GulpHTTP
import GulpTLS
import NIOConcurrencyHelpers
import NIOCore
import NIOHPACK
import NIOHTTP2
import NIOPosix
import NIOSSL
import Testing

@testable import GulpProxy

// F01 PRX-001…PRX-004: a scripted origin server, the proxy under test, and our own engine as the
// client (so the client side is byte-exact too).

/// A scripted origin server that logs every byte it receives per connection.
final class Origin: Sendable {
    let channel: any Channel
    private let log: NIOLockedValueBox<[[UInt8]]>

    private init(channel: any Channel, log: NIOLockedValueBox<[[UInt8]]>) {
        self.channel = channel
        self.log = log
    }

    var port: Int { channel.localAddress?.port ?? 0 }
    var connections: Int { log.withLockedValue { $0.count } }
    func received(_ index: Int = 0) -> [UInt8] { log.withLockedValue { index < $0.count ? $0[index] : [] } }

    /// Replies `reply` to every complete request.
    static func start(reply: String, tls: NIOSSLContext? = nil) async throws -> Origin {
        let log = NIOLockedValueBox<[[UInt8]]>([])
        let bytes = Array(reply.utf8)
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let index = log.withLockedValue { list -> Int in
                    list.append([])
                    return list.count - 1
                }
                return channel.eventLoop.makeCompletedFuture(withResultOf: {
                    if let tls {
                        try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tls))
                    }
                    let handler = OriginHandler(reply: bytes, log: log, index: index)
                    try channel.pipeline.syncOperations.addHandler(handler)
                })
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return Origin(channel: channel, log: log)
    }

    func stop() async { try? await channel.close().get() }
}

final class OriginHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    private let reply: [UInt8]
    private let log: NIOLockedValueBox<[[UInt8]]>
    private let index: Int
    private var pending: [UInt8] = []

    init(reply: [UInt8], log: NIOLockedValueBox<[[UInt8]]>, index: Int) {
        self.reply = reply
        self.log = log
        self.index = index
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let bytes = Array(unwrapInboundIn(data).readableBytesView)
        let index = self.index
        log.withLockedValue { $0[index] += bytes }
        pending += bytes
        while case .request(_, let length) = RequestFramer.next(pending) {
            pending.removeFirst(length)
            var out = context.channel.allocator.buffer(capacity: reply.count)
            out.writeBytes(reply)
            context.writeAndFlush(wrapOutboundOut(out), promise: nil)
        }
    }
}

actor Recorded: ExchangeRecorder {
    var exchanges: [Exchange] = []
    func record(_ exchange: Exchange) -> ExchangeID {
        var stored = exchange
        stored.id = ExchangeID(exchanges.count + 1)
        exchanges.append(stored)
        return stored.id
    }

    func update(_ exchange: Exchange) {
        if let index = exchanges.firstIndex(where: { $0.id == exchange.id }) { exchanges[index] = exchange }
    }

    /// The exchanges once `count` of them are finished (streamed responses are recorded as pending
    /// first and completed a moment after the client has the bytes, PRX-050).
    func settled(_ count: Int) async -> [Exchange] {
        for _ in 0..<200 {
            if exchanges.filter({ $0.state != .pending }).count >= count { break }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return exchanges
    }
}

/// A proxy (with its own recording engine) on an ephemeral port.
func startProxy(recorder: Recorded) async throws -> (ProxyServer, HTTPTarget) {
    let proxy = ProxyServer(engine: NIOHTTPEngine(recorder: recorder))
    let port = try await proxy.start(ProxyListenerConfig(port: 0))
    return (proxy, HTTPTarget(scheme: .http, host: "127.0.0.1", port: port))
}

func clientOptions() -> SendOptions {
    var o = SendOptions(recordAs: .repeater)
    o.timeouts.firstByte = .seconds(5)
    o.timeouts.total = .seconds(10)
    return o
}

let okReply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

@Suite("GulpProxy — HTTP/1 forward proxy (F01)", .serialized)
struct ProxyTests {
    @Test("PRX-002: absolute-form becomes origin-form; every other byte is preserved")
    func test_PRX002_originForm() async throws {
        let origin = try await Origin.start(reply: okReply)
        let (proxy, proxyTarget) = try await startProxy(recorder: Recorded())
        let client = NIOHTTPEngine()
        let sent =
            "GET http://127.0.0.1:\(origin.port)/p/a?q=1 HTTP/1.1\r\n"
            + "Host: 127.0.0.1\r\nX-Case: KeEp\r\n"
            + "Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic dTpw\r\nConnection: X-Hop\r\n"
            + "X-Hop: drop me\r\n\r\n"
        let result = await client.send(RawRequest(Bytes(sent)), to: proxyTarget, options: clientOptions())
        #expect(result.exchange.response?.bytes.string() == okReply)
        let expected =
            "GET /p/a?q=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Case: KeEp\r\n"
            + "Connection: X-Hop\r\n\r\n"
        #expect(Bytes(origin.received()).string() == expected)
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-003: client keep-alive and upstream connection reuse")
    func test_PRX003_keepAlive() async throws {
        let origin = try await Origin.start(reply: okReply)
        let (proxy, proxyTarget) = try await startProxy(recorder: Recorded())
        let client = NIOHTTPEngine()
        let request = RawRequest(Bytes("GET http://127.0.0.1:\(origin.port)/ HTTP/1.1\r\nHost: x\r\n\r\n"))
        let first = await client.send(request, to: proxyTarget, options: clientOptions())
        let second = await client.send(request, to: proxyTarget, options: clientOptions())
        #expect(first.error == nil && second.error == nil)
        #expect(first.exchange.connectionID == second.exchange.connectionID)  // client side kept alive
        #expect(origin.connections == 1)  // upstream reused through the engine pool
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-004: every exchange is recorded as .proxy with the client address")
    func test_PRX004_recording() async throws {
        let origin = try await Origin.start(reply: okReply)
        let recorder = Recorded()
        let (proxy, proxyTarget) = try await startProxy(recorder: recorder)
        let client = NIOHTTPEngine()
        let request = RawRequest(Bytes("GET http://127.0.0.1:\(origin.port)/rec HTTP/1.1\r\nHost: x\r\n\r\n"))
        _ = await client.send(request, to: proxyTarget, options: clientOptions())
        let recorded = await recorder.settled(1)
        #expect(recorded.count == 1)
        #expect(recorded.first?.source == .proxy)
        #expect(recorded.first?.clientAddress?.hasPrefix("127.0.0.1:") == true)
        #expect(recorded.first?.derived.path == "/rec")
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-001: listeners bind, report bind errors, and stop")
    func test_PRX001_listeners() async throws {
        let proxy = ProxyServer(engine: NIOHTTPEngine())
        let config = ProxyListenerConfig(port: 0)
        let port = try await proxy.start(config)
        #expect(port > 0)
        let clash = ProxyServer(engine: NIOHTTPEngine())
        await #expect(throws: GulpError.self) {
            try await clash.start(ProxyListenerConfig(port: port))
        }
        await proxy.stop(config.id)
        let running = await proxy.isRunning(config.id)
        #expect(!running)
    }

    @Test("PRX-001: stopping a listener also closes the client connections it accepted")
    func test_PRX001_stopClosesClients() async throws {
        let proxy = ProxyServer(engine: NIOHTTPEngine())
        let config = ProxyListenerConfig(port: 0)
        let port = try await proxy.start(config)
        let client = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .connect(host: "127.0.0.1", port: port).get()
        try await Task.sleep(for: .milliseconds(100))
        #expect(client.isActive)
        await proxy.stop(config.id)
        for _ in 0..<50 where client.isActive { try await Task.sleep(for: .milliseconds(20)) }
        #expect(!client.isActive)
    }

    @Test("Unreachable upstream → 502; CONNECT without a CA → 502; origin-form → 400")
    func test_errors() async throws {
        let (proxy, proxyTarget) = try await startProxy(recorder: Recorded())
        let client = NIOHTTPEngine()
        let unreachable = RawRequest(Bytes("GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: x\r\n\r\n"))
        let bad = await client.send(unreachable, to: proxyTarget, options: clientOptions())
        #expect(bad.exchange.response?.parsed.statusCode == 502)
        let connect = RawRequest(Bytes("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"))
        let tunnel = await client.send(connect, to: proxyTarget, options: clientOptions())
        #expect(tunnel.exchange.response?.parsed.statusCode == 502)
        let originForm = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        let refused = await client.send(originForm, to: proxyTarget, options: clientOptions())
        let status = refused.exchange.response?.parsed.statusCode
        #expect(status == 400, "error: \(String(describing: refused.error))")
        await client.shutdown()
        await proxy.stopAll()
    }

    @Test("Framing: chunked and Content-Length bodies are forwarded whole; pipelined requests in order")
    func test_framing() {
        let chunkedText = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET"
        let chunked = Array(chunkedText.utf8)
        guard case .request(let first, let length) = RequestFramer.next(chunked) else {
            Issue.record("chunked request not framed")
            return
        }
        #expect(length == chunked.count - 3)
        #expect(first.bytes.count == length)
        let partial = Array("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab".utf8)
        #expect(RequestFramer.next(partial) == .incomplete)
        let list = Array("POST / HTTP/1.1\r\nContent-Length: 2, 2\r\n\r\nab".utf8)
        #expect(RequestFramer.next(list) == .request(RawRequest(Bytes(list)), length: list.count))
        let expect = Array("POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n".utf8)
        #expect(RequestFramer.awaitsContinue(expect))
    }

    @Test(
        "F01 §4.1: hostile framing is refused instead of guessed (no overflow, no desync)",
        arguments: [
            ("POST / HTTP/1.1\r\nContent-Length: 9223372036854775807\r\n\r\n", 400),
            ("POST / HTTP/1.1\r\nContent-Length: 99999999999999999\r\n\r\n", 413),
            ("POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd", 400),
            ("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400),
            ("POST / HTTP/1.1\r\nContent-Length: +3\r\n\r\nabc", 400),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n", 400),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n", 400),
        ])
    func test_framingRejects(request: String, status: Int) {
        guard case .reject(let got, _) = RequestFramer.next(Array(request.utf8)) else {
            Issue.record("not rejected: \(request)")
            return
        }
        #expect(got == status)
    }

    @Test("F01 §4.1: chunked wins over Content-Length for delimiting, and the conflict is flagged")
    func test_conflictingFramingFlagged() {
        let text = "POST / HTTP/1.1\r\nContent-Length: 50\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        guard case .request(let request, let length) = RequestFramer.next(Array(text.utf8)) else {
            Issue.record("not framed")
            return
        }
        #expect(length == text.utf8.count)
        #expect(request.parsed.warnings.contains(.conflictingFraming))
    }

    @Test("Request bodies over the limit get 413 before they are buffered")
    func test_bodyLimit() {
        let head = Array("POST / HTTP/1.1\r\nContent-Length: 11\r\n\r\n".utf8)
        guard case .reject(let status, _) = RequestFramer.next(head, maxBody: 10) else {
            Issue.record("not rejected")
            return
        }
        #expect(status == 413)
        let chunked = Array("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nb\r\n0123456789A".utf8)
        guard case .reject(let chunkedStatus, _) = RequestFramer.next(chunked, maxBody: 10) else {
            Issue.record("chunked not rejected")
            return
        }
        #expect(chunkedStatus == 413)
    }

    @Test("Hop-by-hop stripping never removes framing or routing headers named in Connection")
    func test_hopByHopProtected() {
        let text =
            "GET / HTTP/1.1\r\nHost: h\r\nConnection: content-length, host, x-drop\r\n"
            + "Content-Length: 0\r\nX-Drop: 1\r\n\r\n"
        let stripped = ForwardRewrite.strippingHopByHop(RawRequest(Bytes(text)))
        let out = stripped.bytes.string()
        #expect(out.contains("Host: h\r\n"))
        #expect(out.contains("Content-Length: 0\r\n"))
        #expect(!out.contains("X-Drop"))
    }

}

@Suite("GulpProxy — CONNECT tunnels (PRX-005…PRX-007)", .serialized)
struct TunnelTests {
    /// A TLS origin for `localhost` with its own CA (so its certificate differs from Gulp's).
    static func tlsOrigin() async throws -> (Origin, MintedLeaf) {
        let minter = try LeafMinter(authority: CertificateAuthority.generate(keyType: .p256))
        let context = try await minter.serverContext(for: "localhost", alpn: ["http/1.1"])
        let origin = try await Origin.start(reply: okReply, tls: context)
        return (origin, try await minter.leaf(for: "localhost"))
    }

    /// A proxy that intercepts with a fresh Gulp CA.
    static func interceptingProxy(
        recorder: Recorded, passThrough: [String] = []
    ) async throws -> (ProxyServer, Int, LeafMinter) {
        let minter = try LeafMinter(authority: CertificateAuthority.generate(keyType: .p256))
        let proxy = ProxyServer(
            engine: NIOHTTPEngine(recorder: recorder),
            tls: ProxyTLSOptions(minter: minter, passThroughHosts: passThrough))
        let port = try await proxy.start(ProxyListenerConfig(port: 0))
        return (proxy, port, minter)
    }

    func viaProxy(_ port: Int) -> SendOptions {
        var options = clientOptions()
        options.upstreamProxy = .proxy(UpstreamProxy(kind: .http, host: "127.0.0.1", port: port))
        return options
    }

    @Test("PRX-005/006: CONNECT + MITM — the client sees a Gulp-minted leaf; the exchange is decrypted")
    func test_PRX006_mitm() async throws {
        let (origin, originLeaf) = try await Self.tlsOrigin()
        let recorded = Recorded()
        let (proxy, port, minter) = try await Self.interceptingProxy(recorder: recorded)
        let client = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: origin.port)
        let request = RawRequest(Bytes("GET /secret HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        let result = await client.send(request, to: target, options: viaProxy(port))
        #expect(result.error == nil, "error: \(String(describing: result.error))")
        #expect(result.exchange.response?.bytes.string().hasSuffix("ok") == true)
        let gulpLeaf = try await minter.leaf(for: "localhost")
        let presented = result.exchange.tls?.serverChainSHA256.first
        #expect(presented == CertificateAuthority.fingerprint(gulpLeaf.der))
        // The origin received the decrypted request bytes exactly.
        #expect(origin.received() == Array("GET /secret HTTP/1.1\r\nHost: localhost\r\n\r\n".utf8))
        // The proxy recorded the decrypted exchange, with the origin's own chain.
        try await Task.sleep(for: .milliseconds(100))
        let exchanges = await recorded.settled(1)
        let proxied = try #require(exchanges.first)
        #expect(proxied.source == .proxy)
        #expect(proxied.target.scheme == .https && proxied.target.port == origin.port)
        #expect(proxied.tls?.serverChainSHA256.first == CertificateAuthority.fingerprint(originLeaf.der))
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-007: a pass-through host is spliced — the client sees the origin's real certificate")
    func test_PRX007_passThrough() async throws {
        let (origin, originLeaf) = try await Self.tlsOrigin()
        let recorded = Recorded()
        let (proxy, port, _) = try await Self.interceptingProxy(recorder: recorded, passThrough: ["local*"])
        let client = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: origin.port)
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        let result = await client.send(request, to: target, options: viaProxy(port))
        #expect(result.error == nil, "error: \(String(describing: result.error))")
        let presented = result.exchange.tls?.serverChainSHA256.first
        #expect(presented == CertificateAuthority.fingerprint(originLeaf.der))
        let exchanges = await recorded.exchanges
        #expect(exchanges.isEmpty)  // not decrypted, so nothing to record as an exchange
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("F01 §5: plain HTTP inside a CONNECT tunnel is proxied and recorded")
    func test_plainHTTPInTunnel() async throws {
        let origin = try await Origin.start(reply: okReply)
        let recorded = Recorded()
        let (proxy, port, _) = try await Self.interceptingProxy(recorder: recorded)
        let client = NIOHTTPEngine()
        var options = clientOptions()
        options.upstreamProxy = .proxy(
            UpstreamProxy(kind: .http, host: "127.0.0.1", port: port, tunnelPlainHTTP: true))
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: origin.port)
        let request = RawRequest(Bytes("GET /plain HTTP/1.1\r\nHost: x\r\n\r\n"))
        let result = await client.send(request, to: target, options: options)
        #expect(result.error == nil, "error: \(String(describing: result.error))")
        #expect(result.exchange.response?.parsed.statusCode == 200)
        #expect(origin.received() == Array("GET /plain HTTP/1.1\r\nHost: x\r\n\r\n".utf8))
        try await Task.sleep(for: .milliseconds(100))
        let exchanges = await recorded.settled(1)
        #expect(exchanges.first?.target.port == origin.port)
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("CONNECT authority parsing")
    func authority() {
        func parse(_ text: String) -> (String, Int)? {
            ProxyConnection.connectAuthority(RawRequest(Bytes("CONNECT \(text) HTTP/1.1\r\n\r\n")))
                .map { ($0.host, $0.port) }
        }
        #expect(parse("example.com:443")! == ("example.com", 443))
        #expect(parse("[::1]:8443")! == ("::1", 8443))
        #expect(parse("example.com") == nil)
        #expect(parse("example.com:0") == nil)
    }
}

/// An HTTP/2-only TLS origin: each stream answers `<method> <path>`; `/trailers` adds trailers.
final class H2Origin: Sendable {
    let channel: any Channel

    private init(channel: any Channel) {
        self.channel = channel
    }

    var port: Int { channel.localAddress?.port ?? 0 }

    static func start() async throws -> H2Origin {
        let minter = try LeafMinter(authority: CertificateAuthority.generate(keyType: .p256))
        let tls = try await minter.serverContext(for: "localhost", alpn: ["h2"])
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let secured: EventLoopFuture<Void> = channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tls))
                }
                return secured.flatMap {
                    channel.configureHTTP2Pipeline(mode: .server) { stream in
                        stream.eventLoop.makeCompletedFuture {
                            try stream.pipeline.syncOperations.addHandler(H2OriginHandler())
                        }
                    }.map { _ in }
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return H2Origin(channel: channel)
    }

    func stop() async { try? await channel.close().get() }
}

final class H2OriginHandler: ChannelInboundHandler {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias OutboundOut = HTTP2Frame.FramePayload

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard case .headers(let frame) = unwrapInboundIn(data), frame.endStream else { return }
        let path = frame.headers.first(name: ":path") ?? ""
        let text = "\(frame.headers.first(name: ":method") ?? "") \(path)"
        let trailers = path == "/trailers"
        let head = HPACKHeaders([(":status", "200"), ("content-type", "text/plain")])
        context.write(wrapOutboundOut(.headers(.init(headers: head))), promise: nil)
        let body = IOData.byteBuffer(context.channel.allocator.buffer(string: text))
        context.write(wrapOutboundOut(.data(.init(data: body, endStream: !trailers))), promise: nil)
        if trailers {
            let tail = HPACKHeaders([("grpc-status", "0")])
            context.write(wrapOutboundOut(.headers(.init(headers: tail, endStream: true))), promise: nil)
        }
        context.flush()
    }
}

@Suite("GulpProxy — HTTP/2 through the proxy (PRX-008, PRX-009)", .serialized)
struct ProxyHTTP2Tests {
    func viaProxy(_ port: Int, _ version: HTTPVersionPreference) -> SendOptions {
        var options = clientOptions()
        options.httpVersion = version
        options.upstreamProxy = .proxy(UpstreamProxy(kind: .http, host: "127.0.0.1", port: port))
        return options
    }

    @Test("PRX-008/009: an h2 client gets h2 (ALPN mirrored from an h2 server); streams become exchanges")
    func test_PRX009_h2Client() async throws {
        let origin = try await H2Origin.start()
        let recorded = Recorded()
        let (proxy, port, _) = try await TunnelTests.interceptingProxy(recorder: recorded)
        let client = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: origin.port)
        let request = RawRequest(Bytes("GET /trailers HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        let result = await client.send(request, to: target, options: viaProxy(port, .auto))
        #expect(result.error == nil, "error: \(String(describing: result.error))")
        #expect(result.exchange.httpVersion == .http2)
        #expect(result.exchange.tls?.alpn == "h2")
        let parts = HTTP2Text.responseParts(try #require(result.exchange.response))
        #expect(parts.body == Array("GET /trailers".utf8))
        #expect(parts.trailers == [H2Header("grpc-status", "0")])
        try await Task.sleep(for: .milliseconds(100))
        let proxied = await recorded.settled(1)
        #expect(proxied.first?.httpVersion == .http2)
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("An HTTP/1.1-only client still works against an h2 server (the proxy re-frames the reply)")
    func test_h1ClientToH2Server() async throws {
        let origin = try await H2Origin.start()
        let (proxy, port, _) = try await TunnelTests.interceptingProxy(recorder: Recorded())
        let client = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: origin.port)
        let request = RawRequest(Bytes("GET /trailers HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        let result = await client.send(request, to: target, options: viaProxy(port, .http1_1))
        #expect(result.error == nil, "error: \(String(describing: result.error))")
        #expect(result.exchange.httpVersion == .http1_1)
        let response = try #require(result.exchange.response)
        #expect(response.bytes.string().hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(HTTP2Text.responseParts(response).trailers == [H2Header("grpc-status", "0")])
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }
}
