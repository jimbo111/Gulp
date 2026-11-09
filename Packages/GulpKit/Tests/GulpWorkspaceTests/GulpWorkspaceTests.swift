import Foundation
import GulpCore
import GulpHTTP
import GulpProxy
import GulpRepeater
import GulpStore
import GulpTLS
import Testing

@testable import GulpWorkspace

// F20 PRJ-001…PRJ-006 and the doc 04 §6 settings model. Each test gets its own support/caches dirs.

func isolatedEnvironment() -> WorkspaceEnvironment {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("gulp-ws-\(UUID().uuidString)")
    var environment = WorkspaceEnvironment(
        supportDirectory: root.appendingPathComponent("support"),
        cachesDirectory: root.appendingPathComponent("caches"))
    environment.caKeyType = .p256  // fast key generation in tests
    return environment
}

func projectURL(_ environment: WorkspaceEnvironment, _ name: String) -> URL {
    let fm = FileManager.default
    try? fm.createDirectory(at: environment.supportDirectory, withIntermediateDirectories: true)
    return environment.supportDirectory.appendingPathComponent("\(name).gulp")
}

func open(_ environment: WorkspaceEnvironment, _ name: String) async throws -> ProjectSession {
    try await ProjectSession.open(at: projectURL(environment, name), environment: environment)
}

func proxyOn(_ port: Int) -> ProxySettings {
    ProxySettings(listeners: [ProxyListenerConfig(port: port)])
}

func recordSample(_ session: ProjectSession, path: String = "/") async {
    let request = RawRequest(Bytes("GET \(path) HTTP/1.1\r\nHost: a\r\n\r\n"))
    let exchange = Exchange(source: .proxy, target: HTTPTarget(scheme: .http, host: "a"), request: request)
    _ = await session.store.writer.record(exchange)
}

@Suite("GulpWorkspace — projects (F20)", .serialized)
struct ProjectTests {
    @Test("PRJ-001: a temporary project starts instantly and is deleted on close unless kept")
    func test_PRJ001_temporary() async throws {
        let environment = isolatedEnvironment()
        let session = try await ProjectSession.openTemporary(environment: environment)
        let url = await session.url
        #expect(FileManager.default.fileExists(atPath: url.path))
        #expect(url.path.hasPrefix(environment.cachesDirectory.path))
        try await session.close()
        #expect(!FileManager.default.fileExists(atPath: url.path))

        let kept = try await ProjectSession.openTemporary(environment: environment)
        let keptURL = await kept.url
        try await kept.close(keepTemporary: true)
        #expect(FileManager.default.fileExists(atPath: keptURL.path))
    }

    @Test("PRJ-002/003: Save As moves a temporary project to a real file and keeps working there")
    func test_PRJ002_saveAs() async throws {
        let environment = isolatedEnvironment()
        let session = try await ProjectSession.openTemporary(environment: environment)
        let temporaryURL = await session.url
        for i in 0..<5 { await recordSample(session, path: "/\(i)") }
        let saved = projectURL(environment, "saved")
        try await session.saveAs(saved)
        let temporary = await session.isTemporary
        #expect(!temporary)
        #expect(!FileManager.default.fileExists(atPath: temporaryURL.path))
        await recordSample(session, path: "/after-save")
        try await session.close()

        let reopened = try await ProjectSession.open(at: saved, environment: environment)
        let count = try await reopened.store.count()
        #expect(count == 6)
        #expect(RecentProjects.list(in: environment).first?.path == saved.path)
        try await reopened.close()
    }

    @Test("PRJ-002: Save As onto the project's own file is refused and loses nothing")
    func test_PRJ002_saveAsSelf() async throws {
        let environment = isolatedEnvironment()
        let url = projectURL(environment, "self")
        let session = try await ProjectSession.open(at: url, environment: environment)
        await recordSample(session)
        await #expect(throws: GulpError.self) { try await session.saveAs(url) }
        await session.store.writer.flush()
        let count = try await session.store.count()
        #expect(count == 1)
        try await session.close()
    }

    @Test("TLS-001/002: sessions share the user's CA, created on first use and kept in the CA store")
    func test_TLS002_sessionCA() async throws {
        let environment = isolatedEnvironment()
        let first = try await ProjectSession.openTemporary(environment: environment)
        let second = try await ProjectSession.openTemporary(environment: environment)
        let a = try #require(first.minter?.authority.certificate)
        let b = try #require(second.minter?.authority.certificate)
        #expect(a == b)
        #expect(try environment.caStore.load()?.certificate == a)
        try await first.close()
        try await second.close()
    }

    @Test("PRJ-002: open creates a project; the recent list is most-recent-first")
    func test_PRJ002_recent() async throws {
        let environment = isolatedEnvironment()
        for name in ["a", "b", "a"] {
            let url = projectURL(environment, name)
            let session = try await ProjectSession.open(at: url, environment: environment)
            try await session.close()
        }
        let recent = RecentProjects.list(in: environment).map(\.lastPathComponent)
        #expect(recent == ["a.gulp", "b.gulp"])
    }

    @Test("PRJ-004: two projects open at once, each with its own store and proxy")
    func test_PRJ004_multipleSessions() async throws {
        let environment = isolatedEnvironment()
        let first = try await open(environment, "one")
        let second = try await open(environment, "two")
        let ephemeral = ProxySettings(listeners: [ProxyListenerConfig(port: 0)])
        try await first.settings.set(ephemeral, scope: .project)
        try await second.settings.set(ephemeral, scope: .project)
        let ports1 = await first.startProxyListeners().values.compactMap { try? $0.get() }
        let ports2 = await second.startProxyListeners().values.compactMap { try? $0.get() }
        #expect(ports1.count == 1 && ports2.count == 1 && ports1 != ports2)
        await recordSample(first)
        await first.store.writer.flush()
        let count1 = try await first.store.count()
        let count2 = try await second.store.count()
        #expect(count1 == 1 && count2 == 0)
        try await first.close()
        try await second.close()
    }

    @Test("PRJ-005: a new project can start with another project's settings")
    func test_PRJ005_settingsFrom() async throws {
        let environment = isolatedEnvironment()
        let templateURL = projectURL(environment, "template")
        let template = try await ProjectSession.open(at: templateURL, environment: environment)
        let custom = ProxySettings(listeners: [ProxyListenerConfig(port: 9_999)])
        try await template.settings.set(custom, scope: .project)
        try await template.close()
        let derived = try await ProjectSession.open(
            at: projectURL(environment, "derived"), environment: environment,
            settingsFrom: .project(templateURL))
        #expect(derived.settings.get(ProxySettings.self).listeners.map(\.port) == [9_999])
        try await derived.close()
    }

    @Test("PRJ-006: project name and notes are stored in the project")
    func test_PRJ006_info() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "info")
        try await session.setInfo(name: "ACME pentest", notes: "scope: *.acme.test")
        let name = try await session.store.meta("name")
        #expect(name == "ACME pentest")
        try await session.close()
    }

    @Test("Settings layering: project overrides user overrides default; user settings persist")
    func test_settingsLayering() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "s")
        #expect(session.settings.get(ProxySettings.self).listeners.map(\.port) == [8_080])
        try await session.settings.set(proxyOn(8_081), scope: .user)
        #expect(session.settings.get(ProxySettings.self).listeners.map(\.port) == [8_081])
        try await session.settings.set(proxyOn(8_082), scope: .project)
        #expect(session.settings.get(ProxySettings.self).listeners.map(\.port) == [8_082])
        try await session.close()

        let other = try await open(environment, "t")
        #expect(other.settings.get(ProxySettings.self).listeners.map(\.port) == [8_081])  // user value
        try await other.close()
    }

    @Test("The session's engine records into the project store (even failures)")
    func test_engineRecordsIntoStore() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "rec")
        var options = SendOptions(recordAs: .repeater)
        options.timeouts.total = .seconds(5)
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
        let result = await session.http.send(
            request, to: HTTPTarget(scheme: .http, host: "127.0.0.1", port: 1), options: options)
        #expect(result.exchange.id == 1)
        await session.store.writer.flush()
        let stored = try await session.store.exchange(id: 1)
        #expect(stored?.source == .repeater)
        #expect(stored?.state == .failed(.connectionRefused))
        try await session.close()
    }
}

@Suite("GulpWorkspace — paged History (HIS-002)")
struct HistoryPageCacheTests {
    func rows(_ ids: ClosedRange<Int>) -> [ExchangeSummary] {
        ids.map { id in
            ExchangeSummary(
                id: ExchangeID(id), source: .proxy, createdAt: Date(), scheme: .http, host: "h", port: 80,
                method: "GET", path: "/\(id)", query: nil, status: 200, responseLength: 1, mime: nil,
                title: nil, ext: nil, paramCount: 0, highlight: nil, comment: nil, state: "complete",
                error: nil, totalMs: nil)
        }
    }

    @Test("HIS-002: rows come from loaded pages only; misses ask for exactly one load per page")
    func test_HIS002_paging() {
        var cache = HistoryPageCache(pageSize: 10, maxPages: 2)
        cache.setTotalCount(35)
        let r1 = cache.row(12)
        #expect(r1 == nil)
        let b8 = cache.beginLoading(cache.page(for: 12))
        #expect(b8)
        let b9 = cache.beginLoading(1)
        #expect(!b9)  // already in flight
        cache.store(rows(11...20), page: 1)
        let r2 = cache.row(12)
        #expect(r2?.id == 13)
        let r3 = cache.row(99)
        #expect(r3 == nil)  // past the end
    }

    @Test("HIS-002: memory is bounded — the least recently used page is evicted")
    func test_HIS002_eviction() {
        var cache = HistoryPageCache(pageSize: 10, maxPages: 2)
        cache.setTotalCount(30)
        cache.store(rows(1...10), page: 0)
        cache.store(rows(11...20), page: 1)
        _ = cache.row(0)  // page 0 becomes most recent
        cache.store(rows(21...30), page: 2)
        #expect(cache.loadedPageCount == 2)
        let r4 = cache.row(15)
        #expect(r4 == nil)  // page 1 was evicted
        let r5 = cache.row(5)
        #expect(r5?.id == 6)
    }

    @Test("HIS-002: live append reloads the partial last page")
    func test_HIS002_liveAppend() {
        var cache = HistoryPageCache(pageSize: 10, maxPages: 5)
        cache.setTotalCount(15)
        cache.store(rows(1...10), page: 0)
        cache.store(rows(11...15), page: 1)
        cache.setTotalCount(18)
        let r6 = cache.row(3)
        #expect(r6?.id == 4)  // full page kept
        let r7 = cache.row(16)
        #expect(r7 == nil)  // partial page dropped for reload
        let reload = cache.beginLoading(1)
        #expect(reload)
    }
}

@Suite("GulpWorkspace — Repeater in the project (F06 REP-004, REP-005)", .serialized)
struct RepeaterProjectTests {
    @Test("REP-005: tabs, drafts, options and history are stored in the project and come back on reopen")
    func test_REP005_persistsInProject() async throws {
        let environment = isolatedEnvironment()
        let url = projectURL(environment, "repeater")
        let session = try await ProjectSession.open(at: url, environment: environment)
        // Port 1 refuses: the send fails fast, but is still recorded and kept in the tab's history.
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: 1)
        let request = RawRequest(Bytes("POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi"))
        var options = RepeaterOptions()
        options.redirects = .onSite
        let tab = await session.repeater.openTab(
            request: request, target: target, title: "login", options: options)
        let result = try #require(await session.repeater.send(tab.id))
        #expect(result.error != nil && result.exchange.id != 0)
        await session.repeater.updateDraft(tab.id, bytes: Array("GET /edited HTTP/1.1\r\n\r\n".utf8))
        try await session.close()  // flushes the pending draft

        let reopened = try await ProjectSession.open(at: url, environment: environment)
        let tabs = await reopened.repeater.allTabs
        #expect(tabs.map(\.title) == ["login"])
        #expect(tabs.first?.target == target)
        #expect(tabs.first?.options.redirects == .onSite)
        #expect(tabs.first?.draft == Array("GET /edited HTTP/1.1\r\n\r\n".utf8))
        let history = await reopened.repeater.history(tabs.first?.id ?? 0)
        #expect(history == [result.exchange.id])
        let sent = try await reopened.store.exchange(id: result.exchange.id)
        #expect(sent?.source == .repeater && sent?.request == request)
        try await reopened.close()
    }

    @Test("REP-001: Send to Repeater opens a tab with the exchange's exact bytes and target, and says so")
    func test_REP001_sendToRepeater() async throws {
        let environment = isolatedEnvironment()
        let session = try await ProjectSession.open(
            at: projectURL(environment, "send"), environment: environment)
        let request = RawRequest(
            Bytes("POST /api/login?next=/home HTTP/1.1\r\nHost: lab\r\nX-A: 1\r\n\r\nu=a"))
        let target = HTTPTarget(scheme: .https, host: "lab", port: 8443)
        var exchange = Exchange(source: .proxy, target: target, request: request)
        exchange.httpVersion = .http2
        let id = await session.store.writer.record(exchange)
        await session.store.writer.flush()
        let events = await session.events.subscribe()
        let tabs = await session.sendToRepeater([id])
        #expect(tabs.count == 1)
        #expect(tabs.first?.draft == request.bytes.rawBytes && tabs.first?.target == target)
        #expect(tabs.first?.title == "POST /api/login" && tabs.first?.options.version == .http2)
        var announced: Int64?
        for await delivery in events {
            if case .repeaterTabOpened(let tab) = delivery.event { announced = tab }
            if announced != nil { break }
        }
        #expect(announced == tabs.first?.id)
        try await session.close()
    }

    @Test("PRX-035: a recorded WebSocket message opens a WebSocket tab with its upgrade and the message")
    func test_PRX035_webSocketToRepeater() async throws {
        let environment = isolatedEnvironment()
        let session = try await ProjectSession.open(
            at: projectURL(environment, "ws"), environment: environment)
        let upgrade = RawRequest(Bytes("GET /chat HTTP/1.1\r\nHost: lab\r\nUpgrade: websocket\r\n\r\n"))
        let target = HTTPTarget(scheme: .https, host: "lab", port: 443)
        let exchangeID = await session.store.writer.record(
            Exchange(source: .proxy, target: target, request: upgrade))
        let connection = try await session.store.openWebSocket(
            upgradeExchangeID: exchangeID, url: "wss://lab/chat")
        let message = try await session.store.recordWebSocketMessage(
            connection: connection, direction: 0, opcode: 1, payload: Array("{\"op\":\"buy\"}".utf8),
            frames: [])
        let tab = try #require(
            await session.sendWebSocketToRepeater(connection: connection, message: message))
        #expect(tab.options.isWebSocket && tab.options.webSocketMessage == "{\"op\":\"buy\"}")
        #expect(tab.draft == upgrade.bytes.rawBytes && tab.target == target && tab.title == "WS /chat")
        #expect(await session.sendWebSocketToRepeater(connection: 999) == nil)
        try await session.close()
    }
}
