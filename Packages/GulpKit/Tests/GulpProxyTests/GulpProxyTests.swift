import GulpCore
import GulpHTTP
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
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
    static func start(reply: String) async throws -> Origin {
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
        exchanges.append(exchange)
        return ExchangeID(exchanges.count)
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
        let recorded = await recorder.exchanges
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

    @Test("Unreachable upstream → 502; CONNECT → 501 until M3; origin-form → 400")
    func test_errors() async throws {
        let (proxy, proxyTarget) = try await startProxy(recorder: Recorded())
        let client = NIOHTTPEngine()
        let unreachable = RawRequest(Bytes("GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: x\r\n\r\n"))
        let bad = await client.send(unreachable, to: proxyTarget, options: clientOptions())
        #expect(bad.exchange.response?.parsed.statusCode == 502)
        let connect = RawRequest(Bytes("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"))
        let tunnel = await client.send(connect, to: proxyTarget, options: clientOptions())
        #expect(tunnel.exchange.response?.parsed.statusCode == 501)
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
