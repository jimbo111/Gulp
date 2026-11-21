import Foundation
import GulpCore
import GulpHTTP
import GulpQuery
import Testing

@testable import GulpProxy

// F05 HIS-027: GulpQL in proxy rules — intercept rules as an expression (PRX-015) and Match & Replace
// conditions (PRX-025).

@Suite("GulpProxy — GulpQL rules (HIS-027, PRX-015, PRX-025)", .serialized)
struct ProxyQueryTests {
    let api = HTTPTarget(scheme: .https, host: "api.lab")
    let www = HTTPTarget(scheme: .https, host: "www.lab")

    func request(_ line: String, host: String) -> RawRequest {
        RawRequest(Bytes("\(line) HTTP/1.1\r\nHost: \(host)\r\n\r\n"))
    }

    @Test("PRX-025: a `when` condition picks which messages a rule rewrites")
    func test_PRX025_conditions() async throws {
        let hook = MatchReplaceHook(rules: [
            MatchReplaceRule(
                kind: .requestHeader, match: "", replace: "X-Api: 1", when: #"req.host ~ "^api\.""#),
            MatchReplaceRule(kind: .requestHeader, match: "", replace: "X-All: 1"),
            MatchReplaceRule(kind: .requestHeader, match: "", replace: "X-Bad: 1", when: "req.hots == x"),
            MatchReplaceRule(
                kind: .responseBody, match: "secret", replace: "[redacted]",
                when: "resp.status >= 500 and in_scope"),
        ])
        hook.setScope(ScopeService(rules: [ScopeRule(host: "api.lab")]))
        // Proxy requests: rewritten by the proxy before Intercept (F01 §4.2).
        let apiText = hook.rewrite(request("GET /v1", host: "api.lab"), target: api, source: .proxy).bytes
            .string()
        #expect(apiText.contains("X-Api: 1") && apiText.contains("X-All: 1") && !apiText.contains("X-Bad"))
        let wwwText = hook.rewrite(request("GET /", host: "www.lab"), target: www, source: .proxy).bytes
            .string()
        #expect(!wwwText.contains("X-Api") && wwwText.contains("X-All: 1"))

        func respond(_ status: Int, _ target: HTTPTarget) async throws -> String {
            var response = RawResponse(Bytes("HTTP/1.1 \(status) X\r\nContent-Length: 9\r\n\r\nsecret ok"))
            let sent = OutgoingRequest(request: request("GET /", host: target.host), target: target)
            try await hook.didReceive(&response, for: sent, context: HookContext(source: .proxy))
            return response.bytes.string()
        }
        #expect(try await respond(500, api).hasSuffix("[redacted] ok"))
        #expect(try await respond(200, api).hasSuffix("secret ok"))
        #expect(try await respond(500, www).hasSuffix("secret ok"))  // out of scope
    }

    @Test("PRX-025: rules saved before conditions existed still decode")
    func test_PRX025_decodeOld() throws {
        let old =
            #"{"id":"6E3F2D0A-8D7C-4E59-9F3A-1A2B3C4D5E6F","enabled":true,"kind":"requestHeader","#
            + #""match":"","replace":"X: 1","isRegex":false,"comment":"","applyToTools":false}"#
        let rule = try JSONDecoder().decode(MatchReplaceRule.self, from: Data(old.utf8))
        #expect(rule.when == "" && rule.replace == "X: 1")
    }

    @Test("PRX-015: an intercept query replaces the rule builder; it sees the scope")
    func test_PRX015_interceptQuery() async throws {
        let queue = InterceptQueue()
        await queue.setIntercepting(requests: true)
        await queue.setRules(requests: [])  // the builder would hold everything…
        await queue.setQueries(
            request: try GulpQLPredicate(#"req.method == POST and in_scope"#), response: nil)
        await queue.setScope(ScopeService(rules: [ScopeRule(host: "api.lab")]))
        // …but the query holds only in-scope POSTs.
        let held = try await holds(queue, request("POST /order", host: "api.lab"), api)
        #expect(held)
        #expect(try await !holds(queue, request("GET /order", host: "api.lab"), api))
        #expect(try await !holds(queue, request("POST /order", host: "www.lab"), www))
        await queue.setQueries(request: nil, response: nil)
        #expect(try await holds(queue, request("GET /x", host: "www.lab"), www))  // back to the builder
    }
}

/// Whether `queue` holds `request` (a held request is forwarded right away).
func holds(_ queue: InterceptQueue, _ request: RawRequest, _ target: HTTPTarget) async throws -> Bool {
    let decision = Task { await queue.holdRequest(request, target: target).held }
    for _ in 0..<100 {
        if await !queue.items.isEmpty {
            await queue.decideAll(.forward(nil))
            break
        }
        try await Task.sleep(for: .milliseconds(2))
    }
    return await decision.value
}
