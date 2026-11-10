import GulpCore
import GulpHTTP
import NIOConcurrencyHelpers
import Testing

@testable import GulpRepeater

// F06 REP-001…REP-007, REP-016: Repeater tabs, history, drafts, streaming and cancel — against a
// scripted engine and in-memory storage (the real engine and store have their own tests).

/// An engine that answers every request with `200` echoing the request line, after `delay`.
final class ScriptedEngine: HTTPEngine {
    let delay: Duration
    private let sent = NIOLockedValueBox<[(RawRequest, SendOptions)]>([])

    init(delay: Duration = .zero) {
        self.delay = delay
    }

    var requests: [(RawRequest, SendOptions)] { sent.withLockedValue { $0 } }

    func send(_ request: RawRequest, to target: HTTPTarget, options: SendOptions) async -> ExchangeResult {
        let id = sent.withLockedValue {
            $0.append((request, options))
            return ExchangeID($0.count)
        }
        options.onResponseBytes?(Array("HTTP/1.1 200 OK\r\n".utf8))
        do {
            try await Task.sleep(for: delay)
        } catch {
            let partial = RawResponse(Bytes("HTTP/1.1 200 OK\r\n"))
            let exchange = Exchange(
                id: id, source: options.recordAs, target: target, request: request, response: partial,
                state: .failed(.cancelled))
            return ExchangeResult(exchange: exchange, error: .cancelled)
        }
        let line = request.bytes.string().split(separator: "\r\n").first ?? ""
        let response = RawResponse(
            Bytes("HTTP/1.1 200 OK\r\nContent-Length: \(line.utf8.count)\r\n\r\n\(line)"))
        let exchange = Exchange(
            id: id, source: options.recordAs, target: target, request: request, response: response,
            state: .complete)
        return ExchangeResult(exchange: exchange)
    }

    func send(
        _ request: H2RequestSpec, to target: HTTPTarget, options: SendOptions
    ) async -> ExchangeResult {
        ExchangeResult(exchange: Exchange(source: .repeater, target: target, request: RawRequest(Bytes())))
    }

    func sendGroup(
        _ items: [GroupItem], mode: GroupSendMode, options: SendOptions
    ) async -> [ExchangeResult] {
        var results: [ExchangeResult] = []
        for item in items { results.append(await send(item.request, to: item.target, options: options)) }
        groupModes.withLockedValue { $0.append(mode) }
        return results
    }

    let groupModes = NIOLockedValueBox<[GroupSendMode]>([])

    func openWebSocket(
        _ upgrade: RawRequest, to target: HTTPTarget, options: SendOptions
    ) async throws -> WebSocketSession {
        throw GulpError(message: "not here")
    }
}

/// Tabs and history in memory.
actor MemoryRepeaterStore: RepeaterPersistence {
    var tabs: [Int64: RepeaterTab] = [:]
    var histories: [Int64: [ExchangeID]] = [:]
    var saves = 0
    private var nextID: Int64 = 1

    func loadTabs() -> [RepeaterTab] { tabs.values.sorted { $0.ordinal < $1.ordinal } }

    func saveTab(_ tab: RepeaterTab) -> Int64 {
        saves += 1
        var stored = tab
        if stored.id == 0 {
            stored.id = nextID
            nextID += 1
        }
        tabs[stored.id] = stored
        return stored.id
    }

    func deleteTab(_ id: Int64) {
        tabs[id] = nil
        histories[id] = nil
    }

    func history(of tab: Int64) -> [ExchangeID] { histories[tab] ?? [] }

    func appendHistory(tab: Int64, exchange: ExchangeID) { histories[tab, default: []].append(exchange) }

    func exchange(_ id: ExchangeID) -> Exchange? { nil }

    var groups: [Int64: RepeaterGroup] = [:]

    func loadGroups() -> [RepeaterGroup] { groups.values.sorted { $0.id < $1.id } }

    func saveGroup(_ group: RepeaterGroup) -> Int64 {
        var stored = group
        if stored.id == 0 {
            stored.id = nextID
            nextID += 1
        }
        groups[stored.id] = stored
        return stored.id
    }

    func deleteGroup(_ id: Int64) { groups[id] = nil }
}

@Suite("GulpRepeater — tabs and sends (REP-001…REP-007, REP-016)")
struct GulpRepeaterTests {
    let target = HTTPTarget(scheme: .http, host: "vulnlab.test", port: 8088)
    let request = RawRequest(Bytes("GET /echo?q=1 HTTP/1.1\r\nHost: vulnlab.test:8088\r\n\r\n"))

    @Test("REP-001/002/004: a tab sends its exact draft; every send lands in the tab's history")
    func test_REP001_sendAndHistory() async throws {
        let engine = ScriptedEngine()
        let store = MemoryRepeaterStore()
        let repeater = RepeaterService(engine: engine, persistence: store)
        let tab = await repeater.openTab(request: request, target: target)
        #expect(tab.id > 0 && tab.title == "1")
        let first = try #require(await repeater.send(tab.id))
        #expect(first.exchange.response?.bytes.string().hasSuffix("GET /echo?q=1 HTTP/1.1") == true)
        #expect(engine.requests.first?.0 == request)  // exact bytes
        #expect(engine.requests.first?.1.recordAs == .repeater)
        #expect(engine.requests.first?.1.updateContentLength == true)  // REP-003 default on
        let edited = Array("GET /echo?q=2 HTTP/1.1\r\nHost: vulnlab.test:8088\r\n\r\n".utf8)
        await repeater.updateDraft(tab.id, bytes: edited)
        let second = try #require(await repeater.send(tab.id))
        #expect(second.exchange.response?.bytes.string().hasSuffix("q=2 HTTP/1.1") == true)
        #expect(await repeater.history(tab.id) == [1, 2])
        #expect(await store.histories[tab.id] == [1, 2])
    }

    @Test("REP-005: drafts are saved after a quiet period; rename, move, close and reopen; reload")
    func test_REP005_tabsPersist() async throws {
        let store = MemoryRepeaterStore()
        let repeater = RepeaterService(engine: ScriptedEngine(), persistence: store)
        let a = await repeater.openTab(request: request, target: target, title: "login")
        let b = await repeater.openTab(request: request, target: target)
        let savesBefore = await store.saves
        for i in 0..<5 { await repeater.updateDraft(a.id, bytes: Array("draft \(i)".utf8)) }
        #expect(await store.saves == savesBefore)  // debounced
        // Wait for the ≈500 ms debounce; poll rather than sleep a fixed time, so a loaded machine
        // (the whole suite runs in parallel) can't make the save land just after the check.
        let deadline = ContinuousClock.now + .seconds(5)
        while await store.saves == savesBefore, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(await store.saves == savesBefore + 1)
        #expect(await store.tabs[a.id]?.draft == Array("draft 4".utf8))
        await repeater.rename(b.id, to: "admin")
        await repeater.move(b.id, to: 0)
        #expect(await repeater.allTabs.map(\.title) == ["admin", "login"])
        await repeater.flush()
        let reloaded = RepeaterService(engine: ScriptedEngine(), persistence: store)
        try await reloaded.load()
        #expect(await reloaded.allTabs.map(\.title) == ["admin", "login"])
        await repeater.close(a.id)
        #expect(await store.tabs[a.id] == nil)
        let reopened = try #require(await repeater.reopenClosed())
        #expect(reopened.title == "login" && reopened.draft == Array("draft 4".utf8) && reopened.id != a.id)
        #expect(await repeater.reopenClosed() == nil)
    }

    @Test("REP-016: a streamed send shows bytes as they arrive; Stop cancels and keeps what arrived")
    func test_REP016_streamAndCancel() async throws {
        let engine = ScriptedEngine(delay: .seconds(30))
        let repeater = RepeaterService(engine: engine, persistence: MemoryRepeaterStore())
        let tab = await repeater.openTab(request: request, target: target)
        let seen = NIOLockedValueBox<[UInt8]>([])
        let sending = Task { await repeater.send(tab.id) { bytes in seen.withLockedValue { $0 += bytes } } }
        for _ in 0..<200 where seen.withLockedValue({ $0.isEmpty }) {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(String(decoding: seen.withLockedValue { $0 }, as: UTF8.self) == "HTTP/1.1 200 OK\r\n")
        #expect(await repeater.isSending(tab.id))
        await repeater.cancel(tab.id)
        let result = try #require(await sending.value)
        #expect(result.error == .cancelled)
        #expect(result.exchange.response?.bytes.string() == "HTTP/1.1 200 OK\r\n")
        #expect(await repeater.history(tab.id) == [1])  // the partial send is kept
        #expect(!(await repeater.isSending(tab.id)))
    }

    @Test("REP-003/006/007: options map onto the engine's send options")
    func test_REP003_options() {
        var options = RepeaterOptions()
        options.version = .http2
        options.redirects = .onSite
        options.maxRedirects = 3
        options.newConnection = true
        options.updateContentLength = false
        let send = options.sendOptions
        #expect(send.httpVersion == .http2)
        #expect(send.followRedirects == RedirectPolicy(mode: .onSite, maxHops: 3))
        #expect(send.connection == .new)
        #expect(!send.updateContentLength)
    }

    @Test("REP-010: a group sends its tabs together in its mode; each result lands in its tab")
    func test_REP010_groupSend() async throws {
        let engine = ScriptedEngine()
        let store = MemoryRepeaterStore()
        let repeater = RepeaterService(engine: engine, persistence: store)
        var tabs: [RepeaterTab] = []
        for index in 0..<3 {
            let request = RawRequest(Bytes("POST /redeem?n=\(index) HTTP/1.1\r\nHost: x\r\n\r\n"))
            tabs.append(await repeater.openTab(request: request, target: target))
        }
        let outsider = await repeater.openTab(request: request, target: target)
        let group = await repeater.createGroup(name: "race", tabs: tabs.map(\.id))
        #expect(group.id > 0 && group.mode == .singlePacket)
        #expect(await repeater.members(of: group.id).map(\.id) == tabs.map(\.id))
        let results = await repeater.sendGroup(group.id)
        #expect(results.map(\.tabID) == tabs.map(\.id))
        #expect(engine.groupModes.withLockedValue { $0 } == [.singlePacket])
        for (index, tab) in tabs.enumerated() {
            #expect(await repeater.history(tab.id).count == 1)
            #expect(results[index].exchange.response?.bytes.string().hasSuffix("n=\(index) HTTP/1.1") == true)
        }
        #expect(await repeater.history(outsider.id).isEmpty)
        // Groups persist; deleting one leaves its tabs ungrouped.
        await repeater.flush()
        let reloaded = RepeaterService(engine: engine, persistence: store)
        try await reloaded.load()
        #expect(await reloaded.allGroups.map(\.name) == ["race"])
        await repeater.deleteGroup(group.id)
        #expect(await repeater.members(of: group.id).isEmpty)
        #expect(await repeater.allGroups.isEmpty)
    }
}
