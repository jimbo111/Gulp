import Foundation
import GulpCore
import GulpSession
import Testing

@testable import GulpWorkspace

// F23 ADV-003: the pure Authz Matrix verdict analysis.

@Suite("Authz Matrix analysis (ADV-003)")
struct AuthzMatrixTests {
    func response(_ status: Int, _ body: String) -> AuthzResponse {
        AuthzResponse(status: status, body: body)
    }

    @Test("ADV-003: an authenticated non-owner matching the authorized response is a bypass")
    func test_ADV003_bypass() {
        let authorized = response(200, #"{"id":2,"owner":"bob","total":20}"#)
        let alice = response(200, #"{"id":2,"owner":"bob","total":20}"#)  // alice sees bob's order
        #expect(
            AuthzAnalysis.verdict(candidate: alice, authorized: authorized, isAuthorized: false) == .bypassed)
    }

    @Test("ADV-003: a denied response is enforced")
    func test_ADV003_enforced() {
        let authorized = response(200, #"{"id":2,"owner":"bob","total":20}"#)
        let denied = response(403, #"{"error":"forbidden"}"#)
        #expect(
            AuthzAnalysis.verdict(candidate: denied, authorized: authorized, isAuthorized: false) == .enforced
        )
    }

    @Test("ADV-003: the unauthenticated column matching is public, not a bypass")
    func test_ADV003_public() {
        let authorized = response(200, "<h1>Home</h1>")
        let unauth = response(200, "<h1>Home</h1>")
        #expect(
            AuthzAnalysis.verdict(
                candidate: unauth, authorized: authorized, isAuthorized: false, isUnauthenticated: true)
                == .sameAsAuthorized)
    }

    @Test("ADV-003: the authorized identity's own cell is the baseline")
    func test_ADV003_authorized() {
        let r = response(200, "x")
        #expect(AuthzAnalysis.verdict(candidate: r, authorized: r, isAuthorized: true) == .authorized)
    }

    @Test("ADV-003: a same-status but different body needs review; similarity honours the threshold")
    func test_ADV003_review() {
        let authorized = response(200, String(repeating: "a", count: 100))
        let different = response(200, String(repeating: "b", count: 100))
        #expect(
            AuthzAnalysis.verdict(candidate: different, authorized: authorized, isAuthorized: false)
                == .needsReview)
        // A tiny difference (one reflected id) still counts as a match at the default threshold.
        let almost = response(200, String(repeating: "a", count: 98))
        #expect(AuthzAnalysis.similar(almost, authorized, threshold: 0.95))
        #expect(!AuthzAnalysis.similar(different, authorized, threshold: 0.95))
    }
}

@Suite("Authz Matrix run (ADV-001)")
struct AuthzMatrixRunTests {
    @Test("ADV-001: a run with its own identities leaves the project's session config alone")
    func test_ADV001_runIdentitiesArentStored() async throws {
        let session = try await open(isolatedEnvironment(), "authz-run")
        let tester = Identity(name: "tester")
        let result = try await session.runAuthzMatrix([], identities: [tester])
        #expect(result.columns == [tester.id, nil])
        #expect(await session.sessionSettings().identities.isEmpty)
        try await session.close()
    }
}
