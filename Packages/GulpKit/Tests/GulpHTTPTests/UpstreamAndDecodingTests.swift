import GulpCore
import Testing

@testable import GulpHTTP

// HTTP-006 upstream proxies and HTTP-007 decompression. The "proxies" are TestServer scripts, so the
// exact bytes the engine sends to them can be asserted.

/// A minimal SOCKS5 server script: no-auth greeting, CONNECT by domain, then an HTTP reply.
let socks5Script: ServerScript = { b, _ in
    if b.count == 3, b[0] == 0x05, b[1] == 0x01 {  // greeting: VER NMETHODS METHODS
        return ServerReply(bytes: [0x05, 0x00])  // choose "no authentication"
    }
    if b.count > 5, b[0] == 0x05, b[1] == 0x01, b[3] == 0x03, b.count == 5 + Int(b[4]) + 2 {
        return ServerReply(bytes: [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])  // CONNECT succeeded
    }
    return headersComplete(b) ? ok("via socks") : nil
}

/// Options that send through `proxy`.
func via(_ proxy: UpstreamProxy) -> SendOptions {
    options { $0.upstreamProxy = .proxy(proxy) }
}

/// An upstream HTTP/SOCKS proxy definition pointing at a local test server.
func localProxy(_ kind: UpstreamProxy.Kind, _ server: TestServer, tunnel: Bool = false) -> UpstreamProxy {
    UpstreamProxy(kind: kind, host: "127.0.0.1", port: server.port, tunnelPlainHTTP: tunnel)
}

extension ServerReply {
    init(bytes: [UInt8], close: Bool = false) {
        self.init("", close: close)
        self.bytes = bytes
    }
}

@Suite("GulpHTTP — upstream proxies (HTTP-006)", .serialized)
struct UpstreamProxyTests {
    @Test("HTTP-006: a plain HTTP proxy gets the absolute-form request and Proxy-Authorization")
    func test_HTTP006_plainProxy() async throws {
        let proxy = try await TestServer.start { b, _ in headersComplete(b) ? ok("proxied") : nil }
        let engine = NIOHTTPEngine()
        var upstream = localProxy(.http, proxy)
        upstream.username = "u"
        upstream.password = "p"
        let target = HTTPTarget(scheme: .http, host: "app.test", port: 8080)
        let result = await engine.send(get("/a?b=1"), to: target, options: via(upstream))
        #expect(result.error == nil)
        let sent = Bytes(proxy.received()).string()
        #expect(sent.hasPrefix("GET http://app.test:8080/a?b=1 HTTP/1.1\r\n"))
        #expect(sent.contains("Proxy-Authorization: Basic dTpw\r\n"))  // base64("u:p")
        await engine.shutdown()
        await proxy.stop()
    }

    @Test("HTTP-006: tunnelled plain HTTP goes through CONNECT and stays byte-exact")
    func test_HTTP006_connectTunnel() async throws {
        let proxy = try await TestServer.start { b, _ in
            guard headersComplete(b) else { return nil }
            return Bytes(b).string().hasPrefix("CONNECT ")
                ? ServerReply("HTTP/1.1 200 Connection established\r\n\r\n") : ok("tunnelled")
        }
        let engine = NIOHTTPEngine()
        let upstream = localProxy(.http, proxy, tunnel: true)
        let target = HTTPTarget(scheme: .http, host: "app.test", port: 8080)
        let raw = Bytes("GET /exact HTTP/1.1\nhost: app.test\n\n")
        let result = await engine.send(RawRequest(raw), to: target, options: via(upstream))
        #expect(result.error == nil)
        let connect = "CONNECT app.test:8080 HTTP/1.1\r\nHost: app.test:8080\r\n\r\n"
        #expect(proxy.received() == Array(connect.utf8) + raw.rawBytes)
        #expect(result.exchange.response?.bytes.string().hasSuffix("tunnelled") == true)
        await engine.shutdown()
        await proxy.stop()
    }

    @Test("HTTP-006: a refused CONNECT is a typed upstream-proxy error")
    func test_HTTP006_connectRefused() async throws {
        let proxy = try await TestServer.start { b, _ in
            let refusal = "HTTP/1.1 407 Proxy Auth Required\r\nContent-Length: 0\r\n\r\n"
            return headersComplete(b) ? ServerReply(refusal) : nil
        }
        let engine = NIOHTTPEngine()
        let upstream = localProxy(.http, proxy, tunnel: true)
        let target = HTTPTarget(scheme: .http, host: "app.test", port: 8080)
        let result = await engine.send(get(), to: target, options: via(upstream))
        #expect(result.error?.code == "upstream_proxy_error")
        await engine.shutdown()
        await proxy.stop()
    }

    @Test("HTTP-006: SOCKS5 proxies the exact request bytes after the handshake")
    func test_HTTP006_socks5() async throws {
        let proxy = try await TestServer.start(socks5Script)
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .http, host: "app.test", port: 8080)
        let result = await engine.send(get(), to: target, options: via(localProxy(.socks5, proxy)))
        #expect(result.error == nil)
        #expect(result.exchange.response?.bytes.string().hasSuffix("via socks") == true)
        let received = proxy.received()
        let host = Array("app.test".utf8)
        let connectRequest: [UInt8] = [0x05, 0x01, 0x00, 0x03, UInt8(host.count)] + host + [0x1F, 0x90]
        #expect(Array(received.prefix(3)) == [0x05, 0x01, 0x00])
        #expect(Array(received.dropFirst(3).prefix(connectRequest.count)) == connectRequest)
        #expect(Array(received.suffix(get().bytes.count)) == get().bytes.rawBytes)
        await engine.shutdown()
        await proxy.stop()
    }

    @Test("PRX-041: upstream rules route matching hosts through the proxy, others directly")
    func test_PRX041_rules() async throws {
        let proxy = try await TestServer.start { b, _ in headersComplete(b) ? ok("proxy") : nil }
        let origin = try await TestServer.start { b, _ in headersComplete(b) ? ok("direct") : nil }
        var config = NIOHTTPEngine.Configuration()
        let rule = UpstreamRule(hostPattern: "*.via-proxy.test", proxy: localProxy(.http, proxy))
        config.upstreamRules = [rule]
        let engine = NIOHTTPEngine(configuration: config)
        let routed = await engine.send(
            get(), to: HTTPTarget(scheme: .http, host: "a.via-proxy.test", port: 80), options: options())
        let direct = await engine.send(get(), to: origin.target, options: options())
        #expect(routed.exchange.response?.bytes.string().hasSuffix("proxy") == true)
        #expect(direct.exchange.response?.bytes.string().hasSuffix("direct") == true)
        #expect(UpstreamRule(hostPattern: "*.Example.com", proxy: nil).matches("api.example.COM"))
        #expect(!UpstreamRule(hostPattern: "*.example.com", proxy: nil).matches("example.com"))
        await engine.shutdown()
        await proxy.stop()
        await origin.stop()
    }
}

@Suite("GulpHTTP — decompression helpers (HTTP-007)")
struct DecompressionTests {
    static let gzip: [UInt8] = [
        0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xF3, 0x48, 0xCD, 0xC9, 0xC9, 0x57, 0x48,
        0x2B, 0xCA, 0xCF, 0x55, 0x70, 0x2F, 0xCD, 0x29, 0x50, 0x08, 0x2B, 0xCD, 0xC9, 0xF3, 0x49, 0x4C, 0x52,
        0xD0, 0x48, 0xAF, 0xCA, 0x2C, 0xD0, 0xE4, 0x02, 0x00, 0x03, 0x30, 0xE4, 0xED, 0x1F, 0x00, 0x00, 0x00,
    ]
    static let zlibDeflate: [UInt8] = [
        0x78, 0x9C, 0x4B, 0x49, 0x4D, 0xCB, 0x49, 0x2C, 0x49, 0x4D, 0x51, 0x48, 0xCA, 0x4F, 0xA9, 0xE4, 0x02,
        0x00, 0x28, 0x63, 0x05, 0x12,
    ]
    static let rawDeflate: [UInt8] = [
        0x2B, 0x4A, 0x2C, 0x57, 0x48, 0x49, 0x4D, 0xCB, 0x49, 0x2C, 0x49, 0xE5, 0x02, 0x00,
    ]

    @Test("HTTP-007: gzip, zlib-wrapped deflate and raw deflate decode; identity is a no-op")
    func test_HTTP007_codings() throws {
        let gunzipped = try ContentDecoding.decode(Bytes(Self.gzip), contentEncoding: "gzip")
        #expect(gunzipped.string() == "Hello from Gulp VulnLab (gzip)\n")
        let wrapped = try ContentDecoding.decode(Bytes(Self.zlibDeflate), contentEncoding: "deflate")
        #expect(wrapped.string() == "deflated body\n")
        let raw = try ContentDecoding.decode(Bytes(Self.rawDeflate), contentEncoding: "Deflate")
        #expect(raw.string() == "raw deflate\n")
        #expect(try ContentDecoding.decode(Bytes("as is"), contentEncoding: "identity").string() == "as is")
    }

    @Test("HTTP-007: decodedBody undoes chunking then gzip, and the raw response is untouched")
    func test_HTTP007_decodedBody() throws {
        let hex = String(Self.gzip.count, radix: 16)
        let head = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n\(hex)\r\n"
        let wire = Array(head.utf8) + Self.gzip + Array("\r\n0\r\n\r\n".utf8)
        let response = RawResponse(Bytes(wire))
        #expect(try response.decodedBody()?.string() == "Hello from Gulp VulnLab (gzip)\n")
        #expect(response.bytes.rawBytes == wire)
    }

    @Test("HTTP-007: unsupported or damaged encodings are typed errors")
    func test_HTTP007_errors() {
        #expect(throws: ContentDecodingError.unsupported("br")) {
            try ContentDecoding.decode(Bytes("x"), contentEncoding: "br")
        }
        #expect(throws: ContentDecodingError.truncated) {
            try ContentDecoding.decode(Bytes(Array(Self.gzip.prefix(20))), contentEncoding: "gzip")
        }
        #expect(throws: ContentDecodingError.tooLarge(limit: 4)) {
            try ContentDecoding.decode(Bytes(Self.gzip), contentEncoding: "gzip", limit: 4)
        }
    }
}
