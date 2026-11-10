import Foundation
import GulpCore
import GulpQuery
import GulpStore
import Testing

@testable import GulpWorkspace

@Suite("Notebook (NB-001…004, NB-006) and the coverage index (JRN-001)")
struct NotebookTests {
    func record(
        _ session: ProjectSession, _ method: String, _ path: String, _ source: ToolSource,
        host: String = "lab",
        body: String = "hello"
    ) async -> ExchangeID {
        let id = await session.store.writer.record(
            Exchange(
                source: source, target: HTTPTarget(scheme: .http, host: host),
                request: RawRequest(Bytes("\(method) \(path) HTTP/1.1\r\nHost: \(host)\r\n\r\n")),
                response: RawResponse(
                    Bytes("HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)")),
                state: .complete))
        await session.store.writer.flush()
        return id
    }

    @Test("NB-001 / F14 acceptance 1: the snapshot is exact and survives edits and deletion of the exchange")
    func test_NB001_snapshot() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "notebook")
        let id = await record(session, "GET", "/admin?x=1", .proxy, body: "secret page")
        let original = try #require(try await session.store.exchange(id: id))
        let item = try #require(try await session.addToNotebook(id, note: "**IDOR?**", tags: ["authz"]))
        #expect(item.title == "GET lab/admin" && item.location == "lab/admin?x=1")
        #expect(item.request == original.request.bytes.rawBytes)
        #expect(item.response == original.response?.wireBytes.rawBytes)
        #expect(item.exchangeID == id && item.status == .todo && item.kind == .exchange && !item.truncated)
        try await session.store.setComment("edited later", for: [id])
        try await session.store.delete([id])
        let after = try #require(try await session.store.notebookItem(item.id))
        #expect(after.exchangeID == nil)  // the back-reference is cleared…
        #expect(after.request == item.request && after.response == item.response)  // …the snapshot is not
        try await session.close()
    }

    @Test("NB-002/003 / F14 acceptance 2: notes, status, tags, highlight, order; they survive reopening")
    func test_NB002_editAndPersist() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "persist")
        let first = try #require(try await session.addToNotebook(await record(session, "GET", "/a", .proxy)))
        let note = try await session.addNote(title: "Rate limits", note: "None on /login", tags: ["ops"])
        #expect(note.kind == .note && note.target == nil && note.location == nil)
        try await session.store.updateNotebookItem(
            first.id,
            NotebookEdit(status: .confirmed, note: "XSS in a", tags: ["xss", "p1"], highlight: .red))
        try await session.store.reorderNotebook([note.id])
        try await session.close()

        let reopened = try await open(environment, "persist")
        let items = try await reopened.notebook()
        #expect(items.map(\.id) == [note.id, first.id])
        let saved = try #require(items.last)
        #expect(saved.status == .confirmed && saved.tags == ["xss", "p1"] && saved.highlight == .red)
        #expect(saved.note == "XSS in a" && saved.updatedAt >= saved.createdAt)
        try await reopened.store.updateNotebookItem(saved.id, NotebookEdit(highlight: .some(nil)))
        #expect(try await reopened.store.notebookItem(saved.id)?.highlight == nil)
        try await reopened.store.deleteNotebookItems([note.id])
        #expect(try await reopened.notebook().map(\.id) == [saved.id])
        try await reopened.close()
    }

    @Test("NB-004: the search-box filter and grouping by status or host")
    func test_NB004_filterGroup() async throws {
        let session = try await open(isolatedEnvironment(), "filter")
        let a = try #require(try await session.addToNotebook(await record(session, "GET", "/login", .proxy)))
        let b = try #require(
            try await session.addToNotebook(await record(session, "GET", "/x", .proxy, host: "api.lab")))
        let n = try await session.addNote(title: "General", note: "login throttling", tags: ["Ops"])
        try await session.store.updateNotebookItem(a.id, NotebookEdit(status: .confirmed, tags: ["xss"]))
        #expect(try await session.notebook(NotebookFilter("login")).map(\.id) == [a.id, n.id])
        #expect(try await session.notebook(NotebookFilter("status:confirmed")).map(\.id) == [a.id])
        #expect(try await session.notebook(NotebookFilter("status:notanissue")).isEmpty)
        #expect(try await session.notebook(NotebookFilter("tag:ops is:note")).map(\.id) == [n.id])
        #expect(try await session.notebook(NotebookFilter("host:api")).map(\.id) == [b.id])
        let byStatus = try await session.notebookGroups(.status)
        #expect(
            byStatus.map(\.name) == ["To do", "Confirmed"] && byStatus[0].items.map(\.id) == [b.id, n.id])
        #expect(try await session.notebookGroups(.host).map(\.name) == ["lab", "api.lab", "Notes"])
        try await session.close()
    }

    @Test("NB-006: an item's stored request goes back to Repeater, Comparer and Fuzzer")
    func test_NB006_sendBack() async throws {
        let session = try await open(isolatedEnvironment(), "sendback")
        let id = await record(session, "POST", "/order", .proxy, body: "placed")
        let item = try #require(try await session.addToNotebook(id, title: "Order flow"))
        try await session.store.delete([id])  // the stored snapshot is what gets sent
        #expect(try await session.sendNotebookItem(item.id, to: .repeater))
        let tab = try #require(await session.repeater.allTabs.last)
        #expect(tab.title == "Order flow" && tab.draft == item.request && tab.target.host == "lab")
        #expect(try await session.sendNotebookItem(item.id, to: .comparer))
        #expect(await session.inbox.comparerItems.last?.bytes == item.response)
        #expect(try await session.sendNotebookItem(item.id, to: .fuzzer))
        #expect(await session.inbox.fuzzerInput?.request == item.request)
        let note = try await session.addNote(title: "n")
        #expect(try await !session.sendNotebookItem(note.id, to: .repeater))
        try await session.close()
    }

    @Test("HIS-021: GulpQL `notes` finds exchanges with Notebook notes")
    func test_HIS021_notes() async throws {
        let session = try await open(isolatedEnvironment(), "notes")
        let a = await record(session, "GET", "/a", .proxy)
        _ = await record(session, "GET", "/b", .proxy)
        try await session.addToNotebook(a, note: "token leaks here")
        #expect(try await session.query("notes") == [a])
        #expect(try await session.query(#"notes contains "LEAKS""#) == [a])
        #expect(try await session.query(#"notes contains "leaks" or resp.body contains "nothing""#) == [a])
        try await session.close()
    }

    @Test("JRN-001: coverage per endpoint and tool; observed is not tested; scope changes rebuild")
    func test_JRN001_coverage() async throws {
        let session = try await open(isolatedEnvironment(), "coverage")
        try await session.setScope([ScopeRule(host: "lab")])
        _ = await record(session, "GET", "/browse?page=1", .proxy)
        _ = await record(session, "GET", "/browse?page=2", .proxy)
        _ = await record(session, "POST", "/api/order", .repeater)
        _ = await record(session, "GET", "/api/order", .proxy)
        _ = await record(session, "GET", "/other", .fuzzer, host: "elsewhere")
        var endpoints = try await session.coverage.endpoints()
        #expect(
            endpoints.map(\.id) == [
                "http://elsewhere:80/other", "http://lab:80/api/order", "http://lab:80/browse",
            ])
        let browse = try #require(endpoints.first { $0.path == "/browse" })
        #expect(
            !browse.tested && browse.inScope && browse.tools["proxy"]?.count == 2 && browse.lastTested == nil)
        let order = try #require(endpoints.first { $0.path == "/api/order" })
        #expect(
            order.tested && order.methods == ["GET", "POST"]
                && Set(order.tools.keys) == ["proxy", "repeater"])
        #expect(try await session.coverage.untested().map(\.path) == ["/browse"])
        #expect(try await session.coverage.untested(inScopeOnly: false).map(\.path) == ["/browse"])

        // Incremental: new traffic and Notebook items are picked up on the next read.
        let browseID = await record(session, "GET", "/browse", .proxy)
        try await session.addToNotebook(browseID)
        endpoints = try await session.coverage.endpoints()
        let noted = try #require(endpoints.first { $0.path == "/browse" })
        #expect(noted.tools["proxy"]?.count == 3 && noted.notebookItems == 1 && noted.tested)
        #expect(try await session.coverage.untested().isEmpty)

        // Scope changes rebuild the in-scope flags.
        try await session.setScope([ScopeRule(host: "elsewhere")])
        endpoints = try await session.coverage.endpoints()
        #expect(endpoints.filter(\.inScope).map(\.host) == ["elsewhere"])
        #expect(CoverageCategory.of("extension:x") == .manual && CoverageCategory.of("bogus") == .observed)
        try await session.close()
    }
}
