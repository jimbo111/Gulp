import GulpCore
import Testing

@testable import GulpHTTP

// F03 HTTP-012: platform authentication — challenges parsed, Digest per RFC 7616, one retry.

@Suite("GulpHTTP — platform authentication (HTTP-012)", .serialized)
struct PlatformAuthTests {
    let mufasa = PlatformCredential(host: "example.org", username: "Mufasa", password: "Circle of Life")

    func challenge(_ algorithm: String) -> AuthChallenge {
        AuthChallenge(
            scheme: "digest",
            parameters: [
                "realm": "http-auth@example.org", "qop": "auth, auth-int", "algorithm": algorithm,
                "nonce": "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
                "opaque": "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
            ])
    }

    @Test("RFC 7616 §3.9.1: the MD5 and SHA-256 responses match the published vectors")
    func test_HTTP012_digestVectors() throws {
        let cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
        let md5 = try #require(
            PlatformAuthorization.digest(
                challenge("MD5"), credential: mufasa, method: "GET", uri: "/dir/index.html", nonceCount: 1,
                cnonce: cnonce))
        #expect(md5.contains("response=\"8ca523f5e9506fed4657c9700eebdbec\""))
        #expect(md5.contains("qop=auth, nc=00000001"))
        let sha = try #require(
            PlatformAuthorization.digest(
                challenge("SHA-256"), credential: mufasa, method: "GET", uri: "/dir/index.html",
                nonceCount: 1,
                cnonce: cnonce))
        #expect(sha.contains("response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\""))
        #expect(sha.hasPrefix("Digest username=\"Mufasa\", realm=\"http-auth@example.org\""))
    }

    @Test("Challenges: several in one header, quoted values with commas and escapes, token68")
    func test_HTTP012_parse() {
        let parsed = AuthChallenge.parse(
            #"Digest realm="a, b", nonce="x\"y", qop="auth", Basic realm="site", Negotiate abc=="#)
        #expect(parsed.map(\.scheme) == ["digest", "basic", "negotiate"])
        #expect(parsed[0].parameters["realm"] == "a, b")
        #expect(parsed[0].parameters["nonce"] == "x\"y")
        #expect(parsed[1].parameters["realm"] == "site")
    }

    @Test("settingHeader replaces the first field, drops duplicates, or adds one")
    func test_settingHeader() {
        let twice = RawRequest(
            Bytes("GET / HTTP/1.1\r\nAuthorization: a\r\nX: 1\r\nauthorization: b\r\n\r\n"))
        #expect(
            twice.settingHeader("Authorization", to: "new").bytes.string()
                == "GET / HTTP/1.1\r\nAuthorization: new\r\nX: 1\r\n\r\n")
        let none = RawRequest(Bytes("POST / HTTP/1.1\r\nHost: h\r\n\r\nbody"))
        #expect(
            none.settingHeader("Authorization", to: "v").bytes.string()
                == "POST / HTTP/1.1\r\nHost: h\r\nAuthorization: v\r\n\r\nbody")
    }

    @Test("HTTP-012: a 401 is answered once with the credential; both exchanges are kept")
    func test_HTTP012_retry() async throws {
        let server = try await TestServer.start { received, _ in
            guard headersComplete(received) else { return nil }
            let text = String(decoding: received, as: UTF8.self)
            if text.contains("Authorization: Basic YWRtaW46czNjcmV0\r\n") { return ok("welcome admin") }
            return ServerReply(
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"lab\"\r\nContent-Length: 0\r\n\r\n"
            )
        }
        let engine = NIOHTTPEngine()
        await engine.platformAuth.set([
            PlatformCredential(host: "127.0.0.1", username: "admin", password: "s3cret")
        ])
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        var options = SendOptions(recordAs: .repeater)
        options.timeouts.total = .seconds(10)
        let result = await engine.send(
            RawRequest(Bytes("GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")), to: target, options: options)
        #expect(result.exchange.response?.bytes.string().hasSuffix("welcome admin") == true)
        #expect(result.redirectChain.first?.response?.parsed.statusCode == 401)
        // A request that already carries Authorization is never second-guessed.
        let own = RawRequest(Bytes("GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic bm9wZQ==\r\n\r\n"))
        let untouched = await engine.send(own, to: target, options: options)
        #expect(untouched.exchange.response?.parsed.statusCode == 401 && untouched.redirectChain.isEmpty)
        await engine.shutdown()
        await server.stop()
    }
}
