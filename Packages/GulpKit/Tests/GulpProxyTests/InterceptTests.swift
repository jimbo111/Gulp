import Foundation
import GulpCore
import GulpHTTP
import Testing

@testable import GulpProxy

// F01 PRX-010…PRX-014, PRX-018: the intercept queue and its rules.

@Suite("GulpProxy — Intercept rules (PRX-013, PRX-014)")
struct InterceptRuleTests {
    let target = HTTPTarget(scheme: .http, host: "app.test", port: 80)

    func request(_ line: String, headers: String = "") -> RawRequest {
        RawRequest(Bytes("\(line) HTTP/1.1\r\nHost: app.test\r\n\(headers)\r\n"))
    }

    @Test("PRX-013: the default rule skips static assets")
    func test_PRX013_default() {
        let rules = InterceptCondition.defaultRequestRules
        #expect(InterceptRules.matches(rules, request: request("POST /login"), target: target))
        #expect(!InterceptRules.matches(rules, request: request("GET /logo.PNG?v=2"), target: target))
        #expect(!InterceptRules.matches(rules, request: request("GET /app.js"), target: target))
    }

    @Test("PRX-013: conditions combine left to right with AND/OR; negation; disabled ones skipped")
    func test_PRX013_combination() {
        let post = InterceptCondition(field: .method, pattern: "^POST$")
        let api = InterceptCondition(join: .or, field: .url, pattern: "^/api/")
        let notAdmin = InterceptCondition(join: .and, field: .url, pattern: "admin", negate: true)
        let rules = [post, api, notAdmin]
        #expect(InterceptRules.matches(rules, request: request("POST /login"), target: target))
        #expect(InterceptRules.matches(rules, request: request("GET /api/users"), target: target))
        #expect(!InterceptRules.matches(rules, request: request("GET /api/admin"), target: target))
        #expect(!InterceptRules.matches(rules, request: request("GET /home"), target: target))
        var off = post
        off.enabled = false
        #expect(InterceptRules.matches([off], request: request("GET /x"), target: target))
        let header = InterceptCondition(field: .header, pattern: "^cookie: session=")
        let withCookie = request("GET /", headers: "Cookie: session=1\r\n")
        #expect(InterceptRules.matches([header], request: withCookie, target: target))
    }

    @Test("PRX-013: the in-scope field follows the project scope; the default in-scope rule ships off")
    func test_PRX013_inScope() async {
        let scope = ScopeService(rules: [ScopeRule(host: "app.test", path: "^/api")])
        let inScope = [InterceptCondition(field: .inScope, pattern: "^true$")]
        let api = request("POST /api/login")
        #expect(InterceptRules.matches(inScope, request: api, target: target, scope: scope))
        #expect(
            !InterceptRules.matches(inScope, request: request("POST /login"), target: target, scope: scope))
        let elsewhere = HTTPTarget(scheme: .http, host: "other.test", port: 80)
        #expect(!InterceptRules.matches(inScope, request: api, target: elsewhere, scope: scope))
        #expect(!InterceptRules.matches(inScope, request: api, target: target))  // no scope: nothing is in
        // The default "only in-scope" rule is there but off, so a project without a scope still intercepts.
        let defaults = InterceptCondition.defaultRequestRules
        #expect(defaults.contains { $0.field == .inScope && !$0.enabled })
        #expect(InterceptRules.matches(defaults, request: request("POST /login"), target: target))
        let scoped = defaults.map { rule -> InterceptCondition in
            var on = rule
            on.enabled = true
            return on
        }
        #expect(InterceptRules.matches(scoped, request: api, target: target, scope: scope))
        #expect(
            !InterceptRules.matches(scoped, request: request("GET /api/app.js"), target: target, scope: scope)
        )
        // The queue evaluates its rules against the scope it was given.
        let queue = InterceptQueue()
        await queue.setIntercepting(requests: true)
        await queue.setRules(requests: scoped)
        await queue.setScope(scope)
        let (_, held) = await queue.holdRequest(request("POST /login"), target: target)
        #expect(!held)
    }

    @Test("PRX-014: response conditions see status, MIME and whether the request was held")
    func test_PRX014_responseFields() {
        let response = RawResponse(Bytes("HTTP/1.1 302 Found\r\nContent-Type: text/html\r\n\r\n"))
        let redirects = [InterceptCondition(field: .status, pattern: "^3")]
        let get = request("GET /")
        #expect(InterceptRules.matches(redirects, request: get, target: target, response: response))
        let afterHeld = [InterceptCondition(field: .requestWasIntercepted, pattern: "true")]
        #expect(!InterceptRules.matches(afterHeld, request: get, target: target, response: response))
        let held = InterceptRules.matches(
            afterHeld, request: get, target: target, response: response, requestWasHeld: true)
        #expect(held)
    }
}

@Suite("GulpProxy — Intercept through the proxy (PRX-010…PRX-012, PRX-018)", .serialized)
struct InterceptProxyTests {
    static func proxy(
        _ queue: InterceptQueue, recorder: Recorded
    ) async throws -> (ProxyServer, HTTPTarget) {
        let proxy = ProxyServer(engine: NIOHTTPEngine(recorder: recorder), intercept: queue)
        let port = try await proxy.start(ProxyListenerConfig(port: 0))
        return (proxy, HTTPTarget(scheme: .http, host: "127.0.0.1", port: port))
    }

    /// Wait until the queue holds an item.
    static func nextItem(_ queue: InterceptQueue) async throws -> InterceptItem {
        for _ in 0..<200 {
            if let item = await queue.items.first { return item }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw GulpError(message: "nothing was intercepted")
    }

    @Test("PRX-010/011/012/018: a held request is edited and forwarded; the original is recorded")
    func test_PRX012_editAndForward() async throws {
        let origin = try await Origin.start(reply: okReply)
        let queue = InterceptQueue()
        await queue.setIntercepting(requests: true)
        let recorded = Recorded()
        let (proxy, proxyTarget) = try await Self.proxy(queue, recorder: recorded)
        let client = NIOHTTPEngine()
        let text =
            "POST http://127.0.0.1:\(origin.port)/login HTTP/1.1\r\nHost: x\r\n"
            + "Content-Length: 10\r\n\r\nuser=alice"
        let login = RawRequest(Bytes(text))
        let sending = Task { await client.send(login, to: proxyTarget, options: clientOptions()) }
        let item = try await Self.nextItem(queue)
        #expect(item.kind == .request)
        let edited = item.request.bytes.string()
            .replacingOccurrences(of: "user=alice", with: "user=administrator")
        await queue.decide(item.id, .forward(Bytes(edited)))
        let result = await sending.value
        #expect(result.exchange.response?.parsed.statusCode == 200)
        let received = String(decoding: origin.received(), as: UTF8.self)
        #expect(received.hasSuffix("Content-Length: 18\r\n\r\nuser=administrator"))  // PRX-018
        try await Task.sleep(for: .milliseconds(50))
        let proxied = await recorded.settled(1)
        #expect(proxied.first?.edited?.originalRequest?.bytes.string().hasSuffix("user=alice") == true)
        #expect(proxied.first?.request.bytes.string().hasSuffix("user=administrator") == true)
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-012/020: request Match & Replace runs before Intercept; the user's edit is sent as is")
    func test_PRX020_matchReplaceBeforeIntercept() async throws {
        let origin = try await Origin.start(reply: okReply)
        let queue = InterceptQueue()
        await queue.setIntercepting(requests: true)
        let hook = MatchReplaceHook(rules: [
            MatchReplaceRule(kind: .requestBody, match: "role=user", replace: "role=guest"),
            MatchReplaceRule(kind: .requestHeader, match: "", replace: "X-Gulp: 1"),
        ])
        let recorded = Recorded()
        let engine = NIOHTTPEngine(requestHooks: [hook], responseHooks: [hook], recorder: recorded)
        let proxy = ProxyServer(engine: engine, intercept: queue, matchReplace: hook)
        let port = try await proxy.start(ProxyListenerConfig(port: 0))
        let proxyTarget = HTTPTarget(scheme: .http, host: "127.0.0.1", port: port)
        let client = NIOHTTPEngine()
        let text =
            "POST http://127.0.0.1:\(origin.port)/p HTTP/1.1\r\nHost: x\r\n"
            + "Content-Length: 9\r\n\r\nrole=user"
        let sending = Task {
            await client.send(RawRequest(Bytes(text)), to: proxyTarget, options: clientOptions())
        }
        let item = try await Self.nextItem(queue)
        // The held request is what goes on the wire: already rewritten.
        let held = item.request.bytes.string()
        #expect(held.contains("X-Gulp: 1\r\n") && held.hasSuffix("role=guest"))
        // The user puts the value back; Match & Replace must not rewrite the edit again.
        await queue.decide(
            item.id, .forward(Bytes(held.replacingOccurrences(of: "role=guest", with: "role=user"))))
        #expect(await sending.value.exchange.response?.parsed.statusCode == 200)
        let received = String(decoding: origin.received(), as: UTF8.self)
        #expect(received.hasSuffix("\r\n\r\nrole=user"))
        #expect(received.components(separatedBy: "X-Gulp: 1\r\n").count == 2)  // added once
        let proxied = await recorded.settled(1)
        let original = proxied.first?.edited?.originalRequest?.bytes.string() ?? ""
        #expect(original.hasSuffix("role=user") && !original.contains("X-Gulp"))  // what the client sent
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-011: Drop answers the client with a clear page and sends nothing upstream")
    func test_PRX011_drop() async throws {
        let origin = try await Origin.start(reply: okReply)
        let queue = InterceptQueue()
        await queue.setIntercepting(requests: true)
        let (proxy, proxyTarget) = try await Self.proxy(queue, recorder: Recorded())
        let client = NIOHTTPEngine()
        let request = RawRequest(Bytes("GET http://127.0.0.1:\(origin.port)/ HTTP/1.1\r\nHost: x\r\n\r\n"))
        let sending = Task { await client.send(request, to: proxyTarget, options: clientOptions()) }
        let item = try await Self.nextItem(queue)
        await queue.decide(item.id, .drop)
        let result = await sending.value
        #expect(result.exchange.response?.bytes.string().contains("dropped") == true)
        #expect(origin.connections == 0)
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-014: a held response is edited before the client sees it; switching off releases items")
    func test_PRX014_response() async throws {
        let origin = try await Origin.start(reply: okReply)
        let queue = InterceptQueue()
        await queue.setIntercepting(responses: true)
        let (proxy, proxyTarget) = try await Self.proxy(queue, recorder: Recorded())
        let client = NIOHTTPEngine()
        let request = RawRequest(Bytes("GET http://127.0.0.1:\(origin.port)/ HTTP/1.1\r\nHost: x\r\n\r\n"))
        let sending = Task { await client.send(request, to: proxyTarget, options: clientOptions()) }
        let item = try await Self.nextItem(queue)
        #expect(item.kind == .response)
        await queue.decide(item.id, .forward(Bytes("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nedited")))
        let result = await sending.value
        #expect(result.exchange.response?.bytes.string().hasSuffix("edited") == true)

        let second = Task { await client.send(request, to: proxyTarget, options: clientOptions()) }
        _ = try await Self.nextItem(queue)
        await queue.setIntercepting(responses: false)  // releases what is held, unchanged
        let released = await second.value
        #expect(released.exchange.response?.bytes.string().hasSuffix("ok") == true)
        await client.shutdown()
        await proxy.stopAll()
        await origin.stop()
    }
}
