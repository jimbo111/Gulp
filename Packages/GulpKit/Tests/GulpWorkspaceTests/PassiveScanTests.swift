import Foundation
import GulpCore
import GulpStore
import Testing

@testable import GulpWorkspace

// F08 §4: live passive scanning of recorded traffic, as issues (SCN-001…003).

@Suite("Live passive scanning (F08 §4)", .serialized)
struct PassiveScanTests {
    /// A page with no security headers and a bare cookie.
    func record(
        _ session: ProjectSession, _ path: String, source: ToolSource = .proxy, host: String = "lab",
        state: ExchangeState = .complete
    ) async -> ExchangeID {
        let body = "<p>page</p>"
        let response =
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nSet-Cookie: sid=1\r\n"
            + "Content-Length: \(body.utf8.count)\r\n\r\n\(body)"
        return await session.store.writer.record(
            Exchange(
                source: source, target: HTTPTarget(scheme: .http, host: host),
                request: RawRequest(Bytes("GET \(path) HTTP/1.1\r\nHost: \(host)\r\n\r\n")),
                response: RawResponse(Bytes(response)), state: state))
    }

    func types(_ session: ProjectSession) async throws -> [String] {
        try await session.store.issues().map(\.typeID).sorted()
    }

    @Test("F08 §4: proxy traffic is scanned live; duplicates merge; the cursor survives reopening")
    func test_SCN_livePassive() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "passive")
        let events = await session.events.subscribe()
        _ = await record(session, "/a")
        await session.passiveScan.drain()
        let first = try await types(session)
        #expect(first.contains("passive.csp.missing") && first.contains("passive.cookie.no-httponly"))
        // The issueFound events were published.
        var found = 0
        for await delivery in events {
            if case .issueFound = delivery.event { found += 1 }
            if found == first.count { break }
        }
        #expect(found == first.count)
        // The same page again: no new issues, one more evidence row on the page-level ones.
        _ = await record(session, "/a")
        await session.passiveScan.drain()
        #expect(try await types(session) == first)
        let csp = try #require(try await session.store.issues().first { $0.typeID == "passive.csp.missing" })
        #expect(try await session.store.issue(csp.id)?.evidenceCount == 2)
        #expect(await session.passiveScan.scanned == 2)
        try await session.close()

        // Reopened: nothing is scanned twice; new traffic still is.
        let reopened = try await open(environment, "passive")
        await reopened.passiveScan.drain()
        #expect(await reopened.passiveScan.scanned == 0)
        _ = await record(reopened, "/b")
        await reopened.passiveScan.drain()
        #expect(await reopened.passiveScan.scanned == 1)
        #expect(
            try await reopened.store.issues().filter { $0.typeID == "passive.csp.missing" }.map(\.path)
                .sorted() == ["/a", "/b"])
        try await reopened.close()
    }

    @Test("F08 §4: only in-scope proxy traffic by default; other tools and all traffic by setting")
    func test_SCN_scopeAndTools() async throws {
        let session = try await open(isolatedEnvironment(), "scope")
        try await session.setScope([ScopeRule(host: "lab")])
        _ = await record(session, "/out", host: "elsewhere")
        _ = await record(session, "/rep", source: .repeater)
        _ = await record(session, "/in")
        await session.passiveScan.drain()
        #expect(Set(try await session.store.issues().map(\.path)) == ["/", "/in"])  // cookies are host-wide
        var config = await session.passiveScanConfig()
        config.extraTools = ["repeater"]
        config.allTraffic = true
        config.disabledChecks = ["passive.cookie.no-httponly", "passive.cookie.no-samesite"]
        try await session.setPassiveScanConfig(config)
        try await session.passiveScan.rescanAll()
        await session.passiveScan.drain()
        #expect(Set(try await session.store.issues().map(\.path)) == ["/", "/in", "/out", "/rep"])
        #expect(
            Set(try await session.store.issues().map(\.host)) == ["http://lab:80", "http://elsewhere:80"])
        try await session.close()
    }

    @Test("F08 §4: a streaming row is scanned when it completes; a disabled scanner records nothing")
    func test_SCN_streamingAndDisabled() async throws {
        let session = try await open(isolatedEnvironment(), "stream")
        let id = await record(session, "/sse", state: .pending)
        await session.passiveScan.drain()
        #expect(try await session.store.issues().isEmpty)
        var completed = try #require(try await session.store.exchange(id: id))
        completed.state = .complete
        await session.store.writer.update(completed)
        await session.store.writer.flush()
        await session.passiveScan.exchangeUpdated(id)
        await session.passiveScan.drain()
        #expect(try await types(session).contains("passive.csp.missing"))

        var config = PassiveScanConfig()
        config.enabled = false
        try await session.setPassiveScanConfig(config)
        let before = try await session.store.issues().count
        _ = await record(session, "/later", host: "other")
        await session.passiveScan.drain()
        #expect(try await session.store.issues().count == before)
        try await session.close()
    }

    @Test(
        "SCN-007 / NB-005: JSON and SARIF exports; a Notebook item promoted to an issue; manifest verification"
    )
    func test_SCN007_exportPromoteVerify() async throws {
        let session = try await open(isolatedEnvironment(), "export")
        let id = await record(session, "/a")
        await session.passiveScan.drain()
        let count = try await session.store.issues().count
        let json =
            try JSONSerialization.jsonObject(with: try await session.exportIssues(.json)) as? [String: Any]
        let entries = json?["issues"] as? [[String: Any]]
        #expect(entries?.count == count && (entries?.first?["evidence"] as? [Any])?.isEmpty == false)
        let sarif =
            try JSONSerialization.jsonObject(with: try await session.exportIssues(.sarif)) as? [String: Any]
        let run = (sarif?["runs"] as? [[String: Any]])?.first
        #expect(sarif?["version"] as? String == "2.1.0" && (run?["results"] as? [Any])?.count == count)
        let rules =
            ((run?["tool"] as? [String: Any])?["driver"] as? [String: Any])?["rules"] as? [[String: Any]]
        #expect(
            rules?.allSatisfy {
                let properties = $0["properties"] as? [String: Any]
                return properties?["security-severity"] is String
                    && properties?["tags"] as? [String] == ["security"]
            } == true)

        let item = try #require(
            try await session.addToNotebook(id, title: "IDOR on /a", note: "Other users' data"))
        let promoted = try #require(try await session.promoteNotebookItem(item.id, severity: .high))
        let issue = try #require(try await session.store.issue(promoted))
        #expect(issue.typeID == "manual.finding" && issue.name == "IDOR on /a" && issue.severity == .high)
        #expect(issue.detail == "Other users' data" && issue.path == "/a")
        #expect(try await session.store.notebookIssue(item.id) == promoted)

        let manifest = [
            IssueExpectation(
                scheme: "http", path: "/a",
                expect: try await session.store.issues().filter { $0.typeID != "manual.finding" }.map(
                    \.typeID)
                    + ["manual.finding"])
        ]
        let pass = try await session.verifyIssues(manifest, bases: ["http": "http://lab"])
        #expect(pass.passed && pass.routes == 1)
        let fail = try await session.verifyIssues(
            [IssueExpectation(scheme: "http", path: "/a", expect: ["passive.cors.wildcard"])],
            bases: ["http": "http://lab"])
        #expect(fail.missing == ["http://lab:80/a passive.cors.wildcard"] && !fail.unexpected.isEmpty)
        try await session.close()
    }
}
