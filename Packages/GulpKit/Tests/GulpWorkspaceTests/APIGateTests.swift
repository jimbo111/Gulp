import Foundation
import GulpCore
import Testing

@testable import GulpStore
@testable import GulpWorkspace

// Architecture §3 rule 6 / F21 AUT-023: the one gate every agent tool call goes through.

/// Make every audit write fail, as a full disk or a broken store would.
func breakAuditLog(_ session: ProjectSession) async throws {
    try await session.store.pool.write { db in
        try db.execute(
            sql:
                "CREATE TRIGGER audit_offline BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'offline'); END"
        )
    }
}

func errorCode(_ result: AgentToolResult) -> String? {
    let object = try? JSONSerialization.jsonObject(with: result.json) as? [String: Any]
    return (object?["error"] as? [String: Any])?["code"] as? String
}

@Suite("APIGate — the agent tool surface (rule 6, AUT-023)", .serialized)
struct APIGateTests {
    let raw = Data(#"{"raw":"GET /in HTTP/1.1\nHost: 127.0.0.1:1\n\n","target":"http://127.0.0.1:1"}"#.utf8)

    @Test("AUT-023: an allowed send whose audit write fails fails the call (the send is still recorded)")
    func test_AUT023_auditFailureFailsAllowedSend() async throws {
        let session = try await open(isolatedEnvironment(), "gate-audit")
        try await session.addToScope(url: "http://127.0.0.1:1/in")
        let gate = APIGate(session: session, source: .ai, policy: .inScope)
        try await breakAuditLog(session)
        await #expect(throws: (any Error).self) {
            _ = try await gate.call("send_request", arguments: raw, caller: "ai:test")
        }
        // It was sent (port 1 refuses), and history attributes it to the AI.
        await session.store.writer.flush()
        let rows = try await session.store.summaries(offset: 0, limit: 10)
        #expect(rows.map(\.source) == [.ai])
        try await session.close()
    }

    @Test("AUT-023: a refused call whose audit write fails fails too, and nothing is sent")
    func test_AUT023_auditFailureFailsRefusal() async throws {
        let session = try await open(isolatedEnvironment(), "gate-refused")
        let gate = APIGate(session: session, source: .automation, policy: .inScope)
        try await breakAuditLog(session)
        await #expect(throws: (any Error).self) {
            _ = try await gate.call("send_request", arguments: raw, caller: "mcp:test")
        }
        #expect(try await session.store.count() == 0)
        try await session.close()
    }

    @Test("TGT-023: a host allowed for manual sends (\"don't ask again\") is still out of scope for agents")
    func test_TGT023_manualAllowanceDoesNotWidenAgents() async throws {
        let session = try await open(isolatedEnvironment(), "gate-manual")
        await session.scopeGuard.allowWithoutAsking(host: "127.0.0.1")
        let gate = APIGate(session: session, source: .ai, policy: .inScope)
        let result = try await gate.call("send_request", arguments: raw, caller: "ai:m")
        #expect(errorCode(result) == "out_of_scope" && !result.sent)
        #expect(try await session.store.count() == 0)
        try await session.close()
    }

    @Test("AUT-023: ScopeGuard runs before the approval policy; every outcome is audited with its caller")
    func test_AUT023_order() async throws {
        let session = try await open(isolatedEnvironment(), "gate-order")
        let asked = LockedCounter()
        let gate = APIGate(session: session, source: .ai, policy: .ask) { _ in
            asked.increment()
            return false
        }
        // Out of scope (empty scope): refused without asking the human.
        let outside = try await gate.call("send_request", arguments: raw, caller: "ai:m")
        #expect(outside.isError && !outside.sent && errorCode(outside) == "out_of_scope")
        #expect(asked.value == 0)
        // In scope: the human is asked and says no.
        try await session.addToScope(url: "http://127.0.0.1:1/in")
        let declined = try await gate.call("send_request", arguments: raw, caller: "ai:m")
        #expect(errorCode(declined) == "not_approved" && asked.value == 1)
        // Reads and argument errors are audited too.
        _ = try await gate.call("get_scope", arguments: Data(), caller: "ai:m")
        let bad = try await gate.call(
            "list_exchanges", arguments: Data(#"{"limit":1000}"#.utf8), caller: "ai:m")
        #expect(errorCode(bad) == "invalid_arguments")
        await #expect(throws: APIGateError.unknownTool("rm_rf")) {
            _ = try await gate.call("rm_rf", arguments: Data(), caller: "ai:m")
        }
        let log = try await session.store.auditLog()
        #expect(log.map(\.outcome) == ["refused", "refused", "read", "error"])
        #expect(log.allSatisfy { $0.actor == "ai:m" })
        try await session.close()
    }
}

/// A thread-safe counter for approver callbacks.
final class LockedCounter: Sendable {
    private let lock = NSLock()
    // Guarded by `lock`; a Mutex would need macOS 15.
    nonisolated(unsafe) private var count = 0
    var value: Int { lock.withLock { count } }
    func increment() { lock.withLock { count += 1 } }
}
