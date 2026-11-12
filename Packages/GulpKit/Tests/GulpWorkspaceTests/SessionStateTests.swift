import Foundation
import GulpCore
import GulpSession
import Testing

@testable import GulpWorkspace

// F15 SES-011/012: SessionState's single-flight re-authentication — under concurrency, an expired
// session runs the login macro exactly once while every waiting request awaits it.

@Suite("Session re-auth (SES-012)")
struct SessionStateTests {
    @Test("SES-012: concurrent stale requests trigger exactly one login macro (single-flight)")
    func test_SES012_singleFlightReauth() async throws {
        let counter = Counter()
        let macro = Macro(
            name: "login",
            steps: [
                MacroStep(
                    request: Array("GET /login HTTP/1.1\r\nHost: lab.test\r\n\r\n".utf8),
                    target: HTTPTarget(scheme: .http, host: "lab.test"))
            ])
        var identity = Identity(name: "admin")
        identity.loginMacro = macro.id
        let rule = SessionRule(
            name: "stay logged in", scope: RuleScope(pathPrefix: "/app"), identity: identity.id,
            actions: [.checkValidity(ValidityCheck(statusIn: [200])), .useCookies])
        let state = SessionState(
            SessionSettings(
                identities: [identity], rules: [rule], macros: [macro], activeIdentity: identity.id))
        // The sender counts calls and returns a response that sets a fresh session cookie.
        await state.setSender { _, _ in
            await counter.bump()
            let head = "HTTP/1.1 200 OK\r\nSet-Cookie: session=fresh; Path=/\r\nContent-Length: 2\r\n\r\nok"
            return (RawResponse(Bytes(head)), 1, nil)
        }
        await state.markStale(identity.id)
        // 20 concurrent in-scope requests all see the stale session at once.
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<20 {
                group.addTask {
                    _ = await state.prepare(
                        RawRequest(Bytes("GET /app/data HTTP/1.1\r\nHost: lab.test\r\n\r\n")),
                        target: HTTPTarget(scheme: .http, host: "lab.test"), source: .scanner)
                }
            }
        }
        #expect(await counter.value == 1, "the login macro ran once under concurrency")
        // The fresh cookie is now attached to in-scope requests.
        let prepared = await state.prepare(
            RawRequest(Bytes("GET /app/data HTTP/1.1\r\nHost: lab.test\r\n\r\n")),
            target: HTTPTarget(scheme: .http, host: "lab.test"), source: .scanner)
        #expect(String(decoding: prepared.bytes.rawBytes, as: UTF8.self).contains("Cookie: session=fresh"))
    }
}

/// Counts macro sends.
actor Counter {
    private(set) var value = 0
    func bump() { value += 1 }
}
