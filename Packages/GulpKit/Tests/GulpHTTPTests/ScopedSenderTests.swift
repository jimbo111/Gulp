// ScopedSender (AGENTS.md "Scope safety"): an out-of-scope send throws before anything is sent.

import GulpCore
import Testing

@testable import GulpHTTP

@Suite("ScopedSender refuses out-of-scope sends")
struct ScopedSenderTests {
    let pinnedTarget = HTTPTarget(scheme: .http, host: "Lab.Example", port: 8088)

    func request(_ target: String) -> RawRequest {
        RawRequest(Bytes("GET \(target) HTTP/1.1\r\nHost: x\r\n\r\n"))
    }

    @Test func pinnedPermitsOnlyTheNamedTarget() async {
        let sender = ScopedSender(scope: .pinned(pinnedTarget))
        defer { Task { await sender.shutdown() } }
        #expect(await sender.permits(HTTPTarget(scheme: .http, host: "lab.example", port: 8088), path: "/"))
        #expect(
            !(await sender.permits(HTTPTarget(scheme: .http, host: "other.example", port: 8088), path: "/")))
        #expect(
            !(await sender.permits(HTTPTarget(scheme: .http, host: "lab.example", port: 9999), path: "/")))
        #expect(
            !(await sender.permits(HTTPTarget(scheme: .https, host: "lab.example", port: 8088), path: "/")))
    }

    // Port 1 on 192.0.2.1 (TEST-NET-1) would hang or fail if anything were sent; the refusal comes first.
    @Test func pinnedSendThrowsBeforeSending() async {
        let sender = ScopedSender(scope: .pinned(pinnedTarget))
        defer { Task { await sender.shutdown() } }
        let elsewhere = HTTPTarget(scheme: .http, host: "192.0.2.1", port: 1)
        do {
            _ = try await sender.send(
                request("/admin?x=1"), to: elsewhere, options: SendOptions(recordAs: .automation))
            Issue.record("an out-of-scope send went through")
        } catch {
            #expect(error == OutOfScope(target: elsewhere, path: "/admin?x=1"))
        }
        do {
            _ = try await sender.engine(checkedFor: elsewhere)
            Issue.record("the engine was released for an out-of-scope target")
        } catch {
            #expect(error.target == elsewhere)
        }
    }

    @Test func guardedConsultsTheProjectScope() async {
        let scopeGuard = ScopeGuard(ScopeService(rules: [ScopeRule(host: "lab.example", path: "^/api")]))
        let sender = ScopedSender(scope: .guarded(scopeGuard))
        defer { Task { await sender.shutdown() } }
        #expect(await sender.permits(pinnedTarget, path: "/api/users"))
        #expect(!(await sender.permits(pinnedTarget, path: "/admin")))
    }

    @Test func overriddenPermitsAnything() async {
        let sender = ScopedSender(scope: .overridden(reason: "test"))
        defer { Task { await sender.shutdown() } }
        #expect(
            await sender.permits(HTTPTarget(scheme: .https, host: "anywhere.example", port: 443), path: "/"))
    }

    // Scope rules match the path and query, as the engines check them, so a query exclude holds.
    @Test func guardedMatchesThePathAndQuery() async {
        let scopeGuard = ScopeGuard(
            ScopeService(rules: [
                ScopeRule(host: "192.0.2.1"),
                ScopeRule(kind: .exclude, host: "192.0.2.1", path: "[?&]debug="),
            ]))
        let sender = ScopedSender(scope: .guarded(scopeGuard))
        defer { Task { await sender.shutdown() } }
        let lab = HTTPTarget(scheme: .http, host: "192.0.2.1", port: 1)
        do {
            _ = try await sender.send(
                request("/api?debug=1"), to: lab, options: SendOptions(recordAs: .automation))
            Issue.record("a send excluded by its query went through")
        } catch {
            #expect(error == OutOfScope(target: lab, path: "/api?debug=1"))
        }
    }

    @Test func hostHeaderOmitsDefaultPorts() {
        #expect(HTTPTarget(scheme: .https, host: "h", port: 443).hostHeader == "h")
        #expect(HTTPTarget(scheme: .http, host: "h", port: 80).hostHeader == "h")
        #expect(HTTPTarget(scheme: .http, host: "h", port: 443).hostHeader == "h:443")
        #expect(HTTPTarget(scheme: .https, host: "h", port: 8443).hostHeader == "h:8443")
    }
}
