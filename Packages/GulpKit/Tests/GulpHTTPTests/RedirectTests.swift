import GulpCore
import Testing

@testable import GulpHTTP

// F03 RedirectPolicy / F06 REP-006: redirect planning and the engine following a chain.

@Suite("GulpHTTP — redirects (REP-006)", .serialized)
struct RedirectTests {
    let target = HTTPTarget(scheme: .http, host: "site.test", port: 80)

    func response(_ status: Int, location: String, extra: String = "") -> RawResponse {
        RawResponse(
            Bytes("HTTP/1.1 \(status) X\r\nLocation: \(location)\r\n\(extra)Content-Length: 0\r\n\r\n"))
    }

    @Test("303 and POST→301/302 become GET without the body; 307/308 keep method and body")
    func test_REP006_methods() async throws {
        let post = RawRequest(
            Bytes(
                "POST /a/b HTTP/1.1\r\nHost: site.test\r\nContent-Type: x\r\nContent-Length: 3\r\n"
                    + "X-K: v\r\n\r\nabc"))
        let all = RedirectPolicy(mode: .always)
        func hop(_ status: Int, _ location: String, _ policy: RedirectPolicy) async -> (
            RawRequest, HTTPTarget
        )? {
            await Redirects.next(
                after: response(status, location: location), request: post, target: target, policy: policy
            ).map { ($0.request, $0.target) }
        }
        let see = try #require(await hop(303, "/done", all))
        #expect(see.0.bytes.string() == "GET /done HTTP/1.1\r\nHost: site.test\r\nX-K: v\r\n\r\n")
        let temp = try #require(await hop(307, "c?d=1", all))
        #expect(temp.0.bytes.string().hasPrefix("POST /a/c?d=1 HTTP/1.1\r\n"))
        #expect(temp.0.bytes.string().hasSuffix("Content-Length: 3\r\nX-K: v\r\n\r\nabc"))
        #expect(await hop(200, "/x", all) == nil)
        #expect(await hop(302, "/x", .never) == nil)
    }

    @Test("in-scope follows only to in-scope URLs (other hosts included); without a scope, on-site")
    func test_REP006_inScope() async throws {
        let get = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: site.test\r\n\r\n"))
        let policy = RedirectPolicy(mode: .inScope)
        let scope = ScopeService(rules: [
            ScopeRule(host: "site.test", path: "^/app"), ScopeRule(host: "sso.test"),
        ])
        func follows(_ location: String, _ scope: ScopeService?) async -> Bool {
            await Redirects.next(
                after: response(302, location: location), request: get, target: target, policy: policy,
                scope: scope.map { service in { @Sendable in service.isInScope($0, path: $1) } })
                != nil
        }
        #expect(await follows("/app/home", scope))
        #expect(await !follows("/logout", scope))  // same host, but out of scope
        #expect(await follows("https://sso.test/login", scope))  // another host, in scope
        #expect(await !follows("https://evil.test/", scope))
        #expect(await follows("/logout", nil))  // no scope: on-site
        #expect(await !follows("https://sso.test/login", nil))
    }

    @Test("on-site stays on the host; absolute/scheme-relative locations rewrite Host; cookies carry over")
    func test_REP006_scope() async throws {
        let get = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: site.test\r\nCookie: a=1; b=2\r\n\r\n"))
        let onSite = RedirectPolicy(mode: .onSite)
        let elsewhere = await Redirects.next(
            after: response(302, location: "https://other.test/"), request: get, target: target,
            policy: onSite)
        #expect(elsewhere == nil)
        let https = try #require(
            await Redirects.next(
                after: response(301, location: "https://site.test:8443/p#frag"), request: get, target: target,
                policy: onSite))
        #expect(https.target == HTTPTarget(scheme: .https, host: "site.test", port: 8443))
        #expect(https.request.bytes.string().hasPrefix("GET /p HTTP/1.1\r\nHost: site.test:8443\r\n"))
        let cookies = RedirectPolicy(mode: .always, processCookies: true)
        let away = try #require(
            await Redirects.next(
                after: response(
                    302, location: "//cdn.test/x", extra: "Set-Cookie: b=9; Path=/\r\nSet-Cookie: c=3\r\n"),
                request: get, target: target, policy: cookies))
        #expect(away.target == HTTPTarget(scheme: .http, host: "cdn.test", port: 80))
        // Another host: neither this host's cookies nor the ones it just set go along.
        #expect(away.request.bytes.string() == "GET /x HTTP/1.1\r\nHost: cdn.test\r\n\r\n")
        let stay = try #require(
            await Redirects.next(
                after: response(302, location: "/y", extra: "Set-Cookie: b=9; Path=/\r\nSet-Cookie: c=3\r\n"),
                request: get, target: target, policy: cookies))
        #expect(
            stay.request.bytes.string()
                == "GET /y HTTP/1.1\r\nHost: site.test\r\nCookie: a=1; b=9; c=3\r\n\r\n")
    }

    @Test(
        "REP-006: credentials stay with their origin, cookies with their host; other lines are kept as written"
    )
    func test_REP006_credentialsStayHome() async throws {
        let get = RawRequest(
            Bytes(
                "GET /a HTTP/1.1\r\nhost:  site.test\r\nAuthorization: Basic eDp5\r\n"
                    + "Proxy-Authorization: Basic cDpx\r\nCookie: s=1\r\nX-Odd :  spaced  \r\n\r\n"))
        let always = RedirectPolicy(mode: .always)
        func hop(_ location: String) async throws -> String {
            try #require(
                await Redirects.next(
                    after: response(302, location: location), request: get, target: target, policy: always)
            ).request.bytes.string()
        }
        let kept = "Authorization: Basic eDp5\r\nProxy-Authorization: Basic cDpx\r\nCookie: s=1\r\n"
        #expect(
            try await hop("/b") == "GET /b HTTP/1.1\r\nhost:  site.test\r\n\(kept)X-Odd :  spaced  \r\n\r\n")
        // Same host, another scheme/port: a new origin, so the credentials go; the cookie stays.
        #expect(
            try await hop("https://site.test/b")
                == "GET /b HTTP/1.1\r\nhost:  site.test\r\nCookie: s=1\r\nX-Odd :  spaced  \r\n\r\n")
        #expect(
            try await hop("http://other.test/b")
                == "GET /b HTTP/1.1\r\nhost:  other.test\r\nX-Odd :  spaced  \r\n\r\n")
        // A bare-LF request keeps its line ending.
        let lf = RawRequest(Bytes("GET /a HTTP/1.1\nHost: site.test\nX: 1\n\n"))
        let next = try #require(
            await Redirects.next(
                after: response(302, location: "/c"), request: lf, target: target, policy: always))
        #expect(next.request.bytes.string() == "GET /c HTTP/1.1\nHost: site.test\nX: 1\n\n")
    }

    @Test(
        "TGT-023: with a scope every hop must be in scope, whatever the mode (another port, an excluded path)"
    )
    func test_TGT023_everyHopInScope() async throws {
        let get = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: site.test\r\n\r\n"))
        let service = ScopeService(rules: [
            ScopeRule(host: "site.test", port: "80"),
            ScopeRule(kind: .exclude, host: "site.test", path: "^/admin"),
        ])
        let scope: ScopeCheck = { service.isInScope($0, path: $1) }
        for mode in [RedirectPolicy.Mode.onSite, .inScope, .always] {
            func follows(_ location: String) async -> Bool {
                await Redirects.next(
                    after: response(302, location: location), request: get, target: target,
                    policy: RedirectPolicy(mode: mode), scope: scope) != nil
            }
            #expect(await follows("/home"))
            #expect(await !follows("/admin/users"))
            #expect(await !follows("http://site.test:8080/home"))
        }
    }

    @Test("TGT-023: the engine checks every hop against SendOptions.scope; an out-of-scope hop is never sent")
    func test_TGT023_engineScopesHops() async throws {
        let server = try await TestServer.start { received, _ in
            guard headersComplete(received) else { return nil }
            if String(decoding: received, as: UTF8.self).hasPrefix("GET /start ") {
                return ServerReply("HTTP/1.1 302 Found\r\nLocation: /admin\r\nContent-Length: 0\r\n\r\n")
            }
            return ok("admin")
        }
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        var options = SendOptions(recordAs: .fuzzer)
        options.timeouts.total = .seconds(10)
        options.followRedirects = RedirectPolicy(mode: .onSite)
        options.scope = { _, path in !path.hasPrefix("/admin") }
        let request = RawRequest(Bytes("GET /start HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
        let result = await engine.send(request, to: target, options: options)
        #expect(result.exchange.response?.parsed.statusCode == 302 && result.redirectChain.isEmpty)
        #expect(!String(decoding: server.received(), as: UTF8.self).contains("/admin"))
        await engine.shutdown()
        await server.stop()
    }

    @Test("REP-006: the engine follows a chain hop by hop and reports the hops")
    func test_REP006_engineFollows() async throws {
        let server = try await TestServer.start { received, _ in
            guard headersComplete(received) else { return nil }
            let text = String(decoding: received, as: UTF8.self)
            if text.hasPrefix("GET /start ") {
                return ServerReply("HTTP/1.1 302 Found\r\nLocation: /middle\r\nContent-Length: 0\r\n\r\n")
            }
            if text.hasPrefix("GET /middle ") {
                return ServerReply("HTTP/1.1 301 Moved\r\nLocation: end\r\nContent-Length: 0\r\n\r\n")
            }
            return ok("arrived")
        }
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        var options = SendOptions(recordAs: .repeater)
        options.timeouts.total = .seconds(10)
        options.followRedirects = RedirectPolicy(mode: .onSite, maxHops: 5)
        let request = RawRequest(Bytes("GET /start HTTP/1.1\r\nHost: 127.0.0.1:\(server.port)\r\n\r\n"))
        let result = await engine.send(request, to: target, options: options)
        #expect(result.error == nil)
        #expect(result.exchange.response?.bytes.string().hasSuffix("arrived") == true)
        #expect(result.exchange.request.bytes.string().hasPrefix("GET /end HTTP/1.1\r\n"))
        #expect(result.redirectChain.map { $0.response?.parsed.statusCode } == [302, 301])
        options.followRedirects = RedirectPolicy(mode: .onSite, maxHops: 1)
        let capped = await engine.send(request, to: target, options: options)
        #expect(capped.exchange.response?.parsed.statusCode == 301 && capped.redirectChain.count == 1)
        await engine.shutdown()
        await server.stop()
    }
}
