import Foundation
import GulpCore
import Testing

@testable import GulpSession

// F15 SES-020/021: the macro runner replays steps, carries cookies forward, expands ${var} and
// captures values for later steps. The sender is a small in-process fake login flow.

/// A fake two-step login: GET /login returns a CSRF token and a session cookie; POST /login with the
/// right token and a carried cookie returns an auth cookie; anything else is a 403.
struct FakeLogin: Sendable {
    func send(_ request: RawRequest, _ target: HTTPTarget) async -> (RawResponse?, ExchangeID, String?) {
        let line = String(decoding: request.bytes.rawBytes[request.parsed.target], as: UTF8.self)
        let method = String(decoding: request.bytes.rawBytes[request.parsed.method], as: UTF8.self)
        let body = String(decoding: request.bytes.rawBytes[request.parsed.body], as: UTF8.self)
        let cookie = request.headerValue("cookie")?.string() ?? ""
        func response(_ status: Int, headers: [String] = [], body: String = "") -> RawResponse {
            let head = (["HTTP/1.1 \(status) X"] + headers + ["Content-Length: \(body.utf8.count)"]).joined(
                separator: "\r\n")
            return RawResponse(Bytes(head + "\r\n\r\n" + body))
        }
        if method == "GET", line == "/login" {
            return (
                response(200, headers: ["Set-Cookie: pre=sess1; Path=/"], body: #"{"csrf":"tok-42"}"#), 1, nil
            )
        }
        if method == "POST", line == "/login" {
            guard cookie.contains("pre=sess1"), body.contains("csrf=tok-42") else {
                return (response(403, body: "bad csrf or cookie"), 2, nil)
            }
            return (response(200, headers: ["Set-Cookie: auth=welcome; Path=/"], body: "ok"), 2, nil)
        }
        return (response(404), 3, nil)
    }
}

@Suite("Macros (SES-020/021)")
struct MacroTests {
    func target() -> HTTPTarget { HTTPTarget(scheme: .http, host: "lab.test") }

    @Test("SES-020/021: a login macro chains a CSRF token and carries cookies forward")
    func test_SES020_loginChain() async {
        let fake = FakeLogin()
        let runner = MacroRunner(send: { req, tgt in await fake.send(req, tgt) })
        let step1 = MacroStep(
            request: Array("GET /login HTTP/1.1\r\nHost: lab.test\r\n\r\n".utf8), target: target(),
            extractions: [MacroExtraction(variable: "csrf", from: .jsonPath("csrf"))])
        let step2 = MacroStep(
            request: Array(
                "POST /login HTTP/1.1\r\nHost: lab.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\ncsrf=${csrf}"
                    .utf8),
            target: target())
        let macro = Macro(name: "login", steps: [step1, step2])
        let result = await runner.run(macro)
        #expect(result.failure == nil, "\(result.log)")
        #expect(result.variables["csrf"] == "tok-42")
        #expect(result.cookies.cookies.contains { $0.name == "auth" && $0.value == "welcome" })
        #expect(result.cookies.cookies.contains { $0.name == "pre" })
        #expect(result.exchangeIDs == [1, 2])
    }

    @Test("SES-020: a missing capture fails the macro and names the step")
    func test_SES020_captureFailure() async {
        let fake = FakeLogin()
        let runner = MacroRunner(send: { req, tgt in await fake.send(req, tgt) })
        let step = MacroStep(
            request: Array("GET /login HTTP/1.1\r\nHost: lab.test\r\n\r\n".utf8), target: target(),
            extractions: [MacroExtraction(variable: "missing", from: .regex(#"nothing-(\d+)"#))])
        let result = await runner.run(Macro(name: "m", steps: [step]))
        #expect(result.failure == "step 1: capture missing failed")
    }

    @Test("SES-020: capture reads cookies, headers, regex groups and JSON paths")
    func test_SES020_captureKinds() async {
        let body = #"{"data":{"access_token":"T9"}}"#
        let head =
            "HTTP/1.1 200 X\r\nSet-Cookie: s=zz; Path=/\r\nX-Request-Id: req-7\r\nContent-Length: \(body.utf8.count)\r\n\r\n"
        let response = RawResponse(Bytes(head + body))
        var jar = CookieJar()
        jar.store(setCookies: ["s=zz; Path=/"], from: "lab.test")
        #expect(MacroRunner.capture(.cookie("s"), response: response, cookies: jar, host: "lab.test") == "zz")
        #expect(
            MacroRunner.capture(.header("x-request-id"), response: response, cookies: jar, host: "lab.test")
                == "req-7")
        #expect(
            MacroRunner.capture(
                .regex(#""access_token":"([^"]+)""#), response: response, cookies: jar, host: "lab.test")
                == "T9")
        #expect(
            MacroRunner.capture(
                .jsonPath("data.access_token"), response: response, cookies: jar, host: "lab.test") == "T9")
    }
}
