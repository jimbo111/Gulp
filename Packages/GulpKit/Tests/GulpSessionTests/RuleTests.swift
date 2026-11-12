import Foundation
import GulpCore
import Testing

@testable import GulpSession

// F15 SES-010/011/013: rule scope matching and the non-network actions (cookies, headers, params,
// token following) applied to a request.

@Suite("Session rules (SES-010/011)")
struct RuleTests {
    func request(_ raw: String) -> RawRequest {
        RawRequest(
            Bytes(Array(raw.replacingOccurrences(of: "\n", with: "\r\n").utf8) + Array("\r\n\r\n".utf8)))
    }

    @Test("SES-010: scope matches on tool, host glob and path prefix")
    func test_SES010_scope() {
        let scope = RuleScope(tools: [.scanner, .fuzzer], hostGlob: "*.example.com", pathPrefix: "/api/")
        let target = HTTPTarget(scheme: .https, host: "app.example.com")
        #expect(scope.matches(source: .scanner, target: target, path: "/api/users"))
        #expect(!scope.matches(source: .proxy, target: target, path: "/api/users"), "wrong tool")
        #expect(!scope.matches(source: .scanner, target: target, path: "/public"), "wrong path")
        #expect(
            !scope.matches(
                source: .scanner, target: HTTPTarget(scheme: .https, host: "evil.com"), path: "/api/x"))
        #expect(
            RuleScope().matches(source: .ai, target: target, path: "/anything"), "empty scope matches all")
        #expect(
            RuleScope(hostGlob: "*.example.com").matches(
                source: .proxy, target: HTTPTarget(scheme: .http, host: "example.com"), path: "/"),
            "*.example.com also matches the apex")
    }

    @Test("SES-011/013: actions set cookies, headers, params and follow a captured token")
    func test_SES011_actions() {
        var identity = Identity(name: "admin", variables: ["key": "secret"])
        identity.headers = ["X-Env": "prod"]
        identity.captured = ["csrf": "tok-9"]
        identity.cookies.store(setCookies: ["sid=abc; Path=/"], from: "example.com")
        let target = HTTPTarget(scheme: .https, host: "example.com")
        let actions: [SessionAction] = [
            .useCookies, .useIdentityHeaders, .setHeader(name: "Authorization", value: "Bearer ${key}"),
            .setParam(name: "lang", value: "en"), .followToken(variable: "csrf", into: .header("X-CSRF")),
            .removeHeader(name: "X-Debug"),
        ]
        let result = RuleApplication.apply(
            actions, to: request("GET /app?x=1 HTTP/1.1\nHost: example.com\nX-Debug: 1"), target: target,
            identity: identity)
        let text = String(decoding: result.request.bytes.rawBytes, as: UTF8.self)
        #expect(text.contains("Cookie: sid=abc"))
        #expect(text.contains("X-Env: prod"))
        #expect(text.contains("Authorization: Bearer secret"), "variable expanded")
        #expect(text.contains("X-CSRF: tok-9"), "followed the captured token")
        #expect(text.contains("/app?x=1&lang=en"))
        #expect(!text.contains("X-Debug"), "removed")
    }

    @Test("SES-013: setting an existing query parameter replaces it")
    func test_SES013_replaceParam() {
        let identity = Identity.unauthenticated
        let target = HTTPTarget(scheme: .http, host: "lab.test")
        let result = RuleApplication.apply(
            [.setParam(name: "page", value: "2")],
            to: request("GET /list?page=1&q=a HTTP/1.1\nHost: lab.test"),
            target: target, identity: identity)
        let line = String(
            decoding: result.request.bytes.rawBytes[result.request.parsed.target], as: UTF8.self)
        #expect(line == "/list?page=2&q=a")
    }
}
