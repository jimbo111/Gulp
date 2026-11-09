import Testing

@testable import GulpCore

// F04 TGT-020…TGT-023 and ADR-011: last-match-wins scope rules and ScopeGuard.

@Suite("GulpCore — scope (TGT-020…TGT-023)")
struct ScopeTests {
    let https = HTTPTarget(scheme: .https, host: "example.com", port: 443)
    let http = HTTPTarget(scheme: .http, host: "example.com", port: 80)

    @Test("ADR-011: last match wins; no match (and no rules) is out of scope")
    func test_TGT020_lastMatchWins() {
        #expect(!ScopeService().isInScope(https, path: "/"))
        let rules = [
            ScopeRule(kind: .include, host: "example.com"),
            ScopeRule(kind: .exclude, host: "example.com", path: "^/logout"),
            ScopeRule(kind: .include, host: "example.com", path: "^/logout/help"),
        ]
        let scope = ScopeService(rules: rules)
        #expect(scope.isInScope(https, path: "/app"))
        #expect(!scope.isInScope(https, path: "/logout"))
        #expect(scope.isInScope(https, path: "/logout/help"))  // the later include wins again
        #expect(scope.decidingRule(for: https, path: "/logout")?.kind == .exclude)
        #expect(!scope.isInScope(HTTPTarget(scheme: .https, host: "other.com", port: 443), path: "/"))
        var disabled = rules
        disabled[1].enabled = false
        #expect(ScopeService(rules: disabled).isInScope(https, path: "/logout"))
    }

    @Test("F04 acceptance 2: Add to scope on https://example.com/app — /app/x in, /other out, http out")
    func test_TGT021_addToScope() throws {
        let rule = try #require(ScopeRule.include(url: "https://example.com/app"))
        #expect(rule.scheme == .https && rule.host == "example.com" && rule.port.isEmpty)
        let scope = ScopeService(rules: [rule])
        #expect(scope.isInScope(https, path: "/app"))
        #expect(scope.isInScope(https, path: "/app/x?y=1"))
        #expect(scope.isInScope(https, path: "/app?q"))
        #expect(!scope.isInScope(https, path: "/application"))  // a prefix, not a substring
        #expect(!scope.isInScope(https, path: "/other"))
        #expect(!scope.isInScope(http, path: "/app"))  // https only
        // A non-default port is kept; the whole host for a bare URL.
        let port = try #require(ScopeRule.include(url: "http://LAB.test:8088"))
        #expect(port.port == "8088" && port.host == "lab.test" && port.path.isEmpty)
        #expect(
            ScopeService(rules: [port]).isInScope(
                HTTPTarget(scheme: .http, host: "lab.test", port: 8088), path: "/x"))
        #expect(
            !ScopeService(rules: [port]).isInScope(
                HTTPTarget(scheme: .http, host: "lab.test", port: 80), path: "/x"))
        #expect(ScopeRule.include(url: "not a url") == nil)
    }

    @Test("Hosts: exact (case-insensitive), *.wildcard, regex; ports: exact and ranges")
    func test_TGT020_matching() {
        let wildcard = ScopeService(rules: [ScopeRule(host: "*.example.com")])
        #expect(wildcard.isInScope(HTTPTarget(scheme: .https, host: "API.Example.com", port: 443), path: "/"))
        #expect(wildcard.isInScope(https, path: "/"))  // the bare domain too
        #expect(!wildcard.isInScope(HTTPTarget(scheme: .https, host: "badexample.com", port: 443), path: "/"))
        let regex = ScopeService(rules: [ScopeRule(host: "(api|www)\\.example\\.com", hostIsRegex: true)])
        #expect(regex.isInScope(HTTPTarget(scheme: .http, host: "www.example.com", port: 80), path: "/"))
        #expect(
            !regex.isInScope(HTTPTarget(scheme: .http, host: "www.example.com.evil", port: 80), path: "/"))
        let range = ScopeService(rules: [ScopeRule(host: "example.com", port: "8000-8100")])
        #expect(range.isInScope(HTTPTarget(scheme: .http, host: "example.com", port: 8080), path: "/"))
        #expect(!range.isInScope(HTTPTarget(scheme: .http, host: "example.com", port: 8443), path: "/"))
    }

    @Test("Regex safety: invalid and nested-quantifier patterns are reported and never match")
    func test_TGT022_regexSafety() {
        #expect(ScopeRule.problem(with: "^/app") == nil)
        #expect(ScopeRule.problem(with: "([a-z") != nil)
        #expect(ScopeRule.problem(with: "^(a+)+$") != nil)
        #expect(ScopeRule.problem(with: "(\\w*)*x") != nil)
        let unsafe = ScopeService(rules: [ScopeRule(host: "example.com", path: "^(a+)+$")])
        #expect(!unsafe.isInScope(https, path: "/" + String(repeating: "a", count: 40) + "!"))
    }

    @Test("TGT-025: a readable summary")
    func test_TGT025_summary() {
        let scope = ScopeService(rules: [
            ScopeRule(scheme: .https, host: "example.com"),
            ScopeRule(kind: .exclude, host: "example.com", path: "^/logout"),
        ])
        #expect(scope.summary == "In scope: https://example.com. Excluded: example.com path ~ ^/logout")
        #expect(ScopeService().summary == "Nothing is in scope.")
    }

    @Test("TGT-023: ScopeGuard refuses out-of-scope sends unless overridden or allowed")
    func test_TGT023_guard() async throws {
        let guardian = ScopeGuard(ScopeService(rules: [ScopeRule(host: "example.com")]))
        try await guardian.require(https, path: "/")
        let other = HTTPTarget(scheme: .https, host: "other.com", port: 443)
        await #expect(throws: OutOfScope.self) { try await guardian.require(other, path: "/") }
        try await guardian.require(other, path: "/", override: true)
        await guardian.allowWithoutAsking(host: "OTHER.com")
        #expect(await guardian.permits(other, path: "/x"))
    }
}
