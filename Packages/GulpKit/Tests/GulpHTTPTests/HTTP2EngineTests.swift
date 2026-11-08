import GulpCore
import GulpTLS
import NIOConcurrencyHelpers
import NIOCore
import NIOHPACK
import NIOHTTP2
import NIOPosix
import NIOSSL
import Testing

@testable import GulpHTTP

// F03 HTTP-020…HTTP-024, HTTP-027: the engine speaks HTTP/2 when the server negotiates it.

/// An HTTP/2-only test server (TLS with ALPN h2, or cleartext prior knowledge). Each stream answers
/// `<method> <path> <body length>`; `/trailers` adds gRPC-style trailers.
final class H2TestServer: Sendable {
    let channel: any Channel
    private let accepted: NIOLockedValueBox<Int>

    private init(channel: any Channel, accepted: NIOLockedValueBox<Int>) {
        self.channel = channel
        self.accepted = accepted
    }

    var port: Int { channel.localAddress?.port ?? 0 }
    var connections: Int { accepted.withLockedValue { $0 } }

    static func start(tls: NIOSSLContext?) async throws -> H2TestServer {
        let accepted = NIOLockedValueBox(0)
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                accepted.withLockedValue { $0 += 1 }
                let secured: EventLoopFuture<Void> = channel.eventLoop.makeCompletedFuture {
                    if let tls {
                        try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tls))
                    }
                }
                return secured.flatMap {
                    channel.configureHTTP2Pipeline(mode: .server) { stream in
                        stream.eventLoop.makeCompletedFuture {
                            try stream.pipeline.syncOperations.addHandler(H2EchoHandler())
                        }
                    }.map { _ in }
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return H2TestServer(channel: channel, accepted: accepted)
    }

    func stop() async { try? await channel.close().get() }
}

final class H2EchoHandler: ChannelInboundHandler {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias OutboundOut = HTTP2Frame.FramePayload
    private var method = ""
    private var path = ""
    private var bodyCount = 0

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .headers(let frame):
            method = frame.headers.first(name: ":method") ?? ""
            path = frame.headers.first(name: ":path") ?? ""
            if frame.endStream { respond(context) }
        case .data(let frame):
            if case .byteBuffer(let buffer) = frame.data { bodyCount += buffer.readableBytes }
            if frame.endStream { respond(context) }
        default:
            break
        }
    }

    private func respond(_ context: ChannelHandlerContext) {
        let text = "\(method) \(path) \(bodyCount)"
        let trailers = path == "/trailers"
        let head = HPACKHeaders([(":status", "200"), ("content-type", "text/plain")])
        context.write(wrapOutboundOut(.headers(.init(headers: head))), promise: nil)
        let body = IOData.byteBuffer(context.channel.allocator.buffer(string: text))
        context.write(wrapOutboundOut(.data(.init(data: body, endStream: !trailers))), promise: nil)
        if trailers {
            let fields = HPACKHeaders([("grpc-status", "0"), ("grpc-message", "fine")])
            context.write(wrapOutboundOut(.headers(.init(headers: fields, endStream: true))), promise: nil)
        }
        context.flush()
    }
}

@Suite("GulpHTTP — HTTP/2 upstream (HTTP-020…HTTP-024, HTTP-027)", .serialized)
struct HTTP2EngineTests {
    static func tlsServer() async throws -> H2TestServer {
        let minter = try LeafMinter(authority: CertificateAuthority.generate(keyType: .p256))
        let context = try await minter.serverContext(for: "localhost", alpn: ["h2"])
        return try await H2TestServer.start(tls: context)
    }

    func options(_ version: HTTPVersionPreference = .auto) -> SendOptions {
        var options = SendOptions(recordAs: .repeater)
        options.httpVersion = version
        options.timeouts.total = .seconds(10)
        return options
    }

    @Test("HTTP-020/022: ALPN picks h2; the response is stored as `HTTP/2 200` text")
    func test_HTTP020_alpn() async throws {
        let server = try await Self.tlsServer()
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: server.port)
        let request = RawRequest(
            Bytes("POST /hello HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc"))
        let result = await engine.send(request, to: target, options: options())
        #expect(result.error == nil, "error: \(String(describing: result.error))")
        #expect(result.exchange.httpVersion == .http2)
        #expect(result.exchange.tls?.alpn == "h2")
        let text = result.exchange.response?.bytes.string() ?? ""
        #expect(text.hasPrefix("HTTP/2 200\r\n"))
        #expect(text.hasSuffix("POST /hello 3"))
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTP-023: concurrent requests share one HTTP/2 connection")
    func test_HTTP023_multiplexing() async throws {
        let server = try await Self.tlsServer()
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: server.port)
        let first = await engine.send(
            RawRequest(Bytes("GET /0 HTTP/1.1\r\nHost: localhost\r\n\r\n")), to: target, options: options())
        #expect(first.error == nil)
        let options = self.options()
        let statuses = await withTaskGroup(of: Int?.self) { group in
            for index in 1...20 {
                group.addTask {
                    let request = RawRequest(Bytes("GET /\(index) HTTP/1.1\r\nHost: localhost\r\n\r\n"))
                    let result = await engine.send(request, to: target, options: options)
                    return result.exchange.response?.parsed.statusCode
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        #expect(statuses.allSatisfy { $0 == 200 })
        #expect(server.connections == 1)
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTP-027: trailers are kept and come back out as trailers")
    func test_HTTP027_trailers() async throws {
        let server = try await Self.tlsServer()
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: server.port)
        let request = RawRequest(Bytes("GET /trailers HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        let result = await engine.send(request, to: target, options: options())
        let response = try #require(result.exchange.response)
        let parts = HTTP2Text.responseParts(response)
        #expect(parts.body == Array("GET /trailers 0".utf8))
        #expect(parts.trailers == [H2Header("grpc-status", "0"), H2Header("grpc-message", "fine")])
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTP-020: cleartext HTTP/2 with prior knowledge (h2c)")
    func test_HTTP020_priorKnowledge() async throws {
        let server = try await H2TestServer.start(tls: nil)
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        let result = await engine.send(
            RawRequest(Bytes("GET /plain HTTP/1.1\r\nHost: x\r\n\r\n")), to: target,
            options: options(.http2PriorKnowledge))
        #expect(result.error == nil, "error: \(String(describing: result.error))")
        #expect(result.exchange.httpVersion == .http2)
        #expect(result.exchange.response?.bytes.string().hasSuffix("GET /plain 0") == true)
        await engine.shutdown()
        await server.stop()
    }

    @Test("Forcing HTTP/1.1 offers only http/1.1; an h2-only server then can't be used")
    func test_forcedHTTP1() async throws {
        #expect(NIOHTTPEngine.alpnOffer(.http1_1) == ["http/1.1"])
        #expect(NIOHTTPEngine.alpnOffer(.auto) == ["h2", "http/1.1"])
        #expect(NIOHTTPEngine.alpnOffer(.http2) == ["h2"])
    }
}
