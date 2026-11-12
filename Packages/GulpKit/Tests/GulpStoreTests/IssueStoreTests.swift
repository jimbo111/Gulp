import Foundation
import GulpCore
import Testing

@testable import GulpStore

// F08 SCN-001…SCN-004 (issues, evidence, dedup, triage) and F14 NB-005 (Notebook ↔ issue).

private func finding(
    _ type: String = "passive.cookie.no-httponly", path: String = "/login", host: String = "http://lab:80",
    point: String? = "sid", confidence: IssueConfidence = .firm, severity: IssueSeverity = .low,
    exchange: ExchangeID? = nil
) -> IssueFinding {
    IssueFinding(
        typeID: type, name: "Cookie without HttpOnly", severity: severity, confidence: confidence, host: host,
        path: path, insertionPoint: point, detail: "`\(point ?? "")` lacks HttpOnly",
        background: "Scripts can read it.", remediation: "Set HttpOnly.",
        evidence: IssueEvidence(
            exchangeID: exchange, responseMarkers: [MarkerRange(10, 20)], note: "Set-Cookie"))
}

@Suite("Issues (SCN-001…SCN-004, NB-005)", .serialized)
struct IssueStoreTests {
    func exchange(_ store: ProjectStore, _ path: String = "/login") async -> ExchangeID {
        let id = await store.writer.record(
            Exchange(
                source: .proxy, target: HTTPTarget(scheme: .http, host: "lab"),
                request: RawRequest(Bytes("GET \(path) HTTP/1.1\r\nHost: lab\r\n\r\n")),
                response: RawResponse(
                    Bytes("HTTP/1.1 200 OK\r\nSet-Cookie: sid=1\r\nContent-Length: 0\r\n\r\n")),
                state: .complete))
        await store.writer.flush()
        return id
    }

    @Test("SCN-003: the same finding merges; evidence is added once per exchange and capped")
    func test_SCN003_dedup() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        let first = await exchange(store)
        let created = try await store.record(finding(confidence: .tentative, exchange: first))
        #expect(created.isNew && created.addedEvidence)
        let again = try await store.record(finding(confidence: .certain, exchange: first))
        #expect(!again.isNew && !again.addedEvidence && again.id == created.id)
        // Numeric path segments normalize to one issue (`/orders/{id}`).
        let a = try await store.record(finding(path: "/orders/123", exchange: first))
        let b = try await store.record(finding(path: "/orders/456?x=1", exchange: first))
        #expect(a.id == b.id && a.isNew && !b.isNew)
        for _ in 0..<12 { try await store.record(finding(exchange: await exchange(store))) }
        let issue = try #require(try await store.issue(created.id))
        #expect(issue.evidenceCount == ProjectStore.maxEvidencePerIssue)
        #expect(issue.confidence == .certain && issue.checkConfidence == .certain)
        #expect(issue.evidence.first?.responseMarkers == [MarkerRange(10, 20)])
        #expect(try await store.issues().count == 2)
        #expect(Issue.normalizedPath("/a/9f8e7d6c5b4a39281706/b/") == "/a/{id}/b")
        try await store.close()
    }

    @Test("SCN-037: an active finding keeps its base request as evidence, once, past the cap")
    func test_SCN037_baseRequestEvidence() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        let base = await exchange(store, "/item?id=1")
        var active = finding(
            "active.sqli.error", path: "/item", point: "url param id", exchange: await exchange(store))
        active.baseExchangeID = base
        let created = try await store.record(active)
        for _ in 0..<12 {
            var again = active
            again.evidence.exchangeID = await exchange(store)
            try await store.record(again)
        }
        let issue = try #require(try await store.issue(created.id))
        let bases = issue.evidence.filter { $0.note == IssueEvidence.baseRequestNote }
        #expect(bases.map(\.exchangeID) == [base], "one base row, never evicted by the cap")
        #expect(issue.evidence.count == ProjectStore.maxEvidencePerIssue + 1)
        try await store.close()
    }

    @Test("SCN-004: triage survives re-findings; fixed issues reopen; overrides drive filters")
    func test_SCN004_triage() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        let fixed = try await store.record(finding(point: "a"))
        let falsePositive = try await store.record(finding(point: "b"))
        let overridden = try await store.record(finding(point: "c", severity: .low))
        try await store.setIssueStatus(.fixed, for: [fixed.id])
        try await store.setIssueStatus(.falsePositive, for: [falsePositive.id])
        try await store.overrideIssue(overridden.id, severity: .high, confidence: nil)
        try await store.setIssueNotes(overridden.id, "Confirmed by hand")
        for point in ["a", "b", "c"] { try await store.record(finding(point: point)) }
        #expect(try await store.issue(fixed.id)?.status == .open)  // a regression
        #expect(try await store.issue(falsePositive.id)?.status == .falsePositive)
        let kept = try #require(try await store.issue(overridden.id))
        #expect(kept.severity == .high && kept.checkSeverity == .low && kept.notes == "Confirmed by hand")
        var high = IssueFilter()
        high.severities = [.high]
        #expect(try await store.issues(high).map(\.id) == [overridden.id])
        var open = IssueFilter()
        open.statuses = [.open]
        #expect(Set(try await store.issues(open).map(\.id)) == [fixed.id, overridden.id])
        try await store.overrideIssue(overridden.id, severity: nil, confidence: nil)
        #expect(try await store.issue(overridden.id)?.severity == .low)
        try await store.close()
    }

    @Test("SCN-005: filters by host and path; most severe first")
    func test_SCN005_listing() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        try await store.record(finding("t.info", path: "/a", severity: .info))
        try await store.record(finding("t.high", path: "/b", severity: .high))
        try await store.record(
            finding("t.med", path: "/safe/c", host: "https://other:443", severity: .medium))
        #expect(try await store.issues().map(\.typeID) == ["t.high", "t.med", "t.info"])
        var filter = IssueFilter()
        filter.host = "other"
        #expect(try await store.issues(filter).map(\.typeID) == ["t.med"])
        filter = IssueFilter()
        filter.pathPrefix = "/safe/"
        #expect(try await store.issues(filter).map(\.path) == ["/safe/c"])
        try await store.close()
    }

    @Test("Evidence doesn't block deleting or replacing its exchange")
    func test_evidenceAndExchangeLifecycle() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        let id = await exchange(store)
        let issue = try await store.record(finding(exchange: id))
        // A streaming response completing replaces the row (same id): still fine with evidence.
        var updated = try #require(try await store.exchange(id: id))
        updated.annotation.comment = "completed"
        await store.writer.update(updated)
        await store.writer.flush()
        #expect(try await store.exchange(id: id)?.annotation.comment == "completed")
        try await store.delete([id])
        #expect(try await store.exchange(id: id) == nil)
        let kept = try #require(try await store.issue(issue.id))
        #expect(kept.evidenceCount == 1 && kept.evidence.first?.exchangeID == nil)
        try await store.close()
    }

    @Test("NB-005: a Notebook item links to an issue (both sides)")
    func test_NB005_link() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        let id = await exchange(store)
        let item = try #require(try await store.addNotebookItem(exchange: id))
        let issue = try await store.record(finding(exchange: nil))
        try await store.linkNotebookItem(item.id, to: issue.id)
        #expect(try await store.notebookIssue(item.id) == issue.id)
        let linked = try #require(try await store.issue(issue.id))
        #expect(linked.evidence.contains { $0.note == "notebook:\(item.id)" && $0.exchangeID == id })
        try await store.linkNotebookItem(item.id, to: nil)
        #expect(try await store.notebookIssue(item.id) == nil)
        #expect(try await store.issue(issue.id)?.evidenceCount == 1)
        try await store.close()
    }
}
