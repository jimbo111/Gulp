import Foundation
import GulpCore
import Testing

@testable import GulpStore

// GulpStore tests (doc 04 §4, F20 PRJ-003, F05 HIS-002/004/005/006). Each test uses its own
// temporary .gulp file.

func temporaryProject() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent("gulp-test-\(UUID().uuidString).gulp")
}

func sampleExchange(
    path: String = "/", status: Int = 200, body: String = "ok", mime: String = "text/plain",
    source: ToolSource = .proxy
) -> Exchange {
    let request = RawRequest(Bytes("GET \(path) HTTP/1.1\r\nHost: example.test\r\nCookie: a=1\r\n\r\n"))
    let head = "HTTP/1.1 \(status) X\r\nContent-Type: \(mime)\r\nContent-Length: \(body.utf8.count)\r\n\r\n"
    let response = RawResponse(Bytes(head + body))
    var timing = Timing(start: Date(timeIntervalSince1970: 1_700_000_000))
    timing.totalMs = 12.5
    let target = HTTPTarget(scheme: .http, host: "example.test", port: 8080)
    return Exchange(
        source: source, target: target, request: request, response: response, state: .complete,
        timing: timing, clientAddress: "127.0.0.1:5555", connectionID: 7,
        annotation: Annotation(comment: nil, highlight: nil, tags: ["t1", "t2"]))
}

@Suite("GulpStore — project database (doc 04 §4)", .serialized)
struct StoreTests {
    @Test("Schema v1 creates every table in doc 04 §4 and records project meta")
    func test_schemaV1() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        let expected = [
            "meta", "blobs", "exchanges", "exchange_tags", "ws_connections", "ws_messages", "fts_exchanges",
            "scope_rules", "issues", "issue_evidence", "tasks", "task_log", "repeater_tabs",
            "repeater_groups",
            "repeater_history", "fuzzer_attacks", "fuzzer_results", "oast_payloads", "oast_interactions",
            "notebook_items", "cookie_jar", "identities", "macros", "session_rules", "sequencer_runs",
            "settings", "extension_state",
        ]
        let tables = try await store.pool.read { db in
            try String.fetchAll(db, sql: "SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        for table in expected { #expect(tables.contains(table), "missing table \(table)") }
        let version = try await store.meta("schema_version")
        let uuid = try await store.meta("project_uuid")
        #expect(version == "3" && uuid != nil)
    }

    @Test("PRJ-003: an exchange round-trips byte-for-byte with its metadata")
    func test_roundTrip() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        let original = sampleExchange(path: "/a/b.json?x=1", mime: "application/json")
        let id = await store.writer.record(original)
        await store.writer.flush()
        let loaded = try #require(try await store.exchange(id: id))
        #expect(loaded.id == id)
        #expect(loaded.request.bytes == original.request.bytes)
        #expect(loaded.response?.bytes == original.response?.bytes)
        #expect(loaded.timing == original.timing)
        #expect(loaded.annotation.tags == ["t1", "t2"])
        #expect(loaded.clientAddress == "127.0.0.1:5555" && loaded.connectionID == 7)
        #expect(loaded.derived == original.derived)
        #expect(loaded.state == .complete)
    }

    @Test("HIS-007: update replaces a recorded exchange in place and announces exchangeUpdated")
    func test_HIS007_update() async throws {
        let bus = EventBus()
        let events = await bus.subscribe()
        let store = try ProjectStore.open(at: temporaryProject(), eventBus: bus)
        var exchange = sampleExchange(path: "/stream")
        exchange.state = .pending
        exchange.id = await store.writer.record(exchange)
        exchange.state = .complete
        exchange.response = RawResponse(Bytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
        await store.writer.update(exchange)
        await store.writer.flush()
        let count = try await store.count()
        #expect(count == 1)
        let loaded = try await store.exchange(id: exchange.id)
        #expect(loaded?.response?.bytes.string().hasSuffix("ok") == true)
        var sawUpdate = false
        for await delivery in events {
            if case .exchangeUpdated(let id) = delivery.event, id == exchange.id { sawUpdate = true }
            if sawUpdate { break }
        }
        #expect(sawUpdate)
        try await store.close()
    }

    @Test("PRX-031/032: WebSocket connections and messages are stored with frames and announced")
    func test_PRX031_webSocketRows() async throws {
        let bus = EventBus()
        let events = await bus.subscribe()
        let store = try ProjectStore.open(at: temporaryProject(), eventBus: bus)
        let upgrade = await store.writer.record(sampleExchange(path: "/chat"))  // not flushed yet
        let id = try await store.openWebSocket(upgradeExchangeID: upgrade, url: "ws://h/chat")
        let frames = [
            WSFrameInfo(fin: false, opcode: 1, rsv: 0, length: 3, masked: true),
            WSFrameInfo(fin: true, opcode: 0, rsv: 0, length: 2, masked: true),
        ]
        let message = try await store.recordWebSocketMessage(
            connection: id, direction: 0, opcode: 1, payload: Array("Hello".utf8), frames: frames)
        try await store.recordWebSocketMessage(
            connection: id, direction: 1, opcode: 2, payload: [0, 1, 2], frames: [])
        var connections = try await store.webSocketConnections()
        #expect(connections.count == 1)
        #expect(connections.first?.url == "ws://h/chat" && connections.first?.upgradeExchangeID == upgrade)
        #expect(connections.first?.messageCount == 2 && connections.first?.closedAt == nil)
        try await store.closeWebSocket(id, code: 1000)
        connections = try await store.webSocketConnections()
        #expect(connections.first?.closeCode == 1000 && connections.first?.closedAt != nil)
        let messages = try await store.webSocketMessages(connection: id)
        #expect(messages.map(\.direction) == [0, 1])
        #expect(messages.first?.payload == Array("Hello".utf8))
        #expect(messages.first?.frames == frames)
        #expect(messages.last?.payload == [0, 1, 2] && messages.last?.opcode == 2)
        var seen: [GulpEvent] = []
        for await delivery in events {
            guard let event = delivery.event else { continue }
            if case .exchangeRecorded = event { continue }
            seen.append(event)
            if seen.count == 4 { break }
        }
        #expect(seen.first == .wsConnectionChanged(id))
        #expect(seen.contains(.wsMessage(message)))
        #expect(seen.last == .wsConnectionChanged(id))
        try await store.close()
    }

    @Test("PRX-032: the message filter by direction, kind and text (UTF-8 or raw bytes)")
    func test_PRX032_messageFilter() {
        func message(_ direction: Int, _ opcode: Int, _ payload: [UInt8]) -> WebSocketMessageRecord {
            WebSocketMessageRecord(
                id: 1, direction: direction, opcode: opcode, createdAt: Date(), payload: payload, frames: [])
        }
        let text = message(0, 1, Array("Hello Wörld".utf8))
        let binary = message(1, 2, [0x00, 0xFF, 0x41])
        let ping = message(1, 9, [])
        #expect(WebSocketMessageFilter().matches(text))
        #expect(!WebSocketMessageFilter(direction: .toClient).matches(text))
        #expect(WebSocketMessageFilter(kind: .control).matches(ping))
        #expect(!WebSocketMessageFilter(kind: .data).matches(ping))
        #expect(WebSocketMessageFilter(text: "wörld").matches(text))
        #expect(WebSocketMessageFilter(text: "a").matches(binary))  // 0x41 'A', case-insensitive
        #expect(!WebSocketMessageFilter(text: "zzz").matches(text))
    }

    @Test("TGT-022: rows get in_scope on insert; changing scope recomputes every row and says so")
    func test_TGT022_inScope() async throws {
        let bus = EventBus()
        let store = try ProjectStore.open(at: temporaryProject(), eventBus: bus)
        let events = await bus.subscribe()
        try await store.setScope([ScopeRule(host: "a.test")])
        func record(_ host: String, _ path: String) async {
            let request = RawRequest(Bytes("GET \(path) HTTP/1.1\r\nHost: \(host)\r\n\r\n"))
            _ = await store.writer.record(
                Exchange(
                    source: .proxy, target: HTTPTarget(scheme: .http, host: host, port: 80), request: request)
            )
        }
        for index in 0..<3_000 { await record(index % 2 == 0 ? "a.test" : "b.test", "/p\(index)?q=1") }
        await store.writer.flush()
        var page = HistoryFilter()
        page.inScopeOnly = true
        #expect(try await store.count(filter: page) == 1_500)
        try await store.setScope([
            ScopeRule(host: "b.test"), ScopeRule(kind: .exclude, host: "b.test", path: "^/p1"),
        ])
        let inScope = try await store.count(filter: page)
        let excluded = (0..<3_000).filter { $0 % 2 == 1 && "/p\($0)".hasPrefix("/p1") }.count
        #expect(inScope == 1_500 - excluded)
        #expect(try await store.scopeRules().map(\.host) == ["b.test", "b.test"])
        var sawChange = false
        for await delivery in events {
            if delivery.event == .scopeChanged { sawChange = true }
            if sawChange { break }
        }
        #expect(sawChange)
        try await store.close()
    }

    @Test("Interim 1xx responses are stored as received and split again on load")
    func test_interimRoundTrip() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        let final = RawResponse(Bytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
        let interim = RawResponse(Bytes("HTTP/1.1 100 Continue\r\n\r\n"))
        var exchange = sampleExchange()
        exchange.response = RawResponse(final.bytes, interim: [interim])
        let id = await store.writer.record(exchange)
        await store.writer.flush()
        let loaded = try #require(try await store.exchange(id: id))
        #expect(loaded.response?.bytes == final.bytes)
        #expect(loaded.response?.interim.map(\.bytes) == [interim.bytes])
    }

    @Test("Failed exchanges keep their error token")
    func test_failedState() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        var exchange = sampleExchange()
        exchange.response = nil
        exchange.state = .failed(.connectionRefused)
        let id = await store.writer.record(exchange)
        await store.writer.flush()
        let loaded = try #require(try await store.exchange(id: id))
        #expect(loaded.state == .failed(.connectionRefused) && loaded.response == nil)
    }

    @Test("Identical bodies are stored once; large compressible bodies are zlib-compressed")
    func test_blobs() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        let big = String(repeating: "compressible ", count: 2_000)
        _ = await store.writer.record(sampleExchange(path: "/1", body: big))
        _ = await store.writer.record(sampleExchange(path: "/2", body: big))
        await store.writer.flush()
        let (blobs, compressed) = try await store.pool.read { db in
            (
                try Int.fetchOne(db, sql: "SELECT COUNT(*) FROM blobs") ?? 0,
                try Int.fetchOne(db, sql: "SELECT COUNT(*) FROM blobs WHERE compression = 1") ?? 0
            )
        }
        #expect(blobs == 3)  // two distinct requests, one shared response
        #expect(compressed == 1)
        let loaded = try #require(try await store.exchange(id: 2))
        #expect(loaded.response?.bytes.string().hasSuffix(big) == true)
    }

    @Test("PRJ-003: ids are assigned at once; 1,200 writes coalesce and all land")
    func test_coalescer() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        var ids: [ExchangeID] = []
        for i in 0..<1_200 { ids.append(await store.writer.record(sampleExchange(path: "/\(i)"))) }
        #expect(ids == Array(1...1_200))
        await store.writer.flush()
        let count = try await store.count()
        #expect(count == 1_200)
    }

    @Test("Writes publish exchangeRecorded only after they are durable")
    func test_events() async throws {
        let bus = EventBus()
        let events = await bus.subscribe()
        let store = try ProjectStore.open(at: temporaryProject(), eventBus: bus)
        let id = await store.writer.record(sampleExchange())
        var iterator = events.makeAsyncIterator()
        let delivery = await iterator.next()
        #expect(delivery?.event == .exchangeRecorded(id, source: .proxy))
        let row = try await store.exchange(id: id)
        #expect(row != nil)
    }

    @Test("HIS-002/006: paged summaries with filters and stable sorting")
    func test_pagingAndFilters() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        for i in 0..<30 {
            let status = i % 3 == 0 ? 404 : 200
            let path = i % 5 == 0 ? "/static/app\(i).css" : "/api/item\(i)?id=\(i)"
            _ = await store.writer.record(sampleExchange(path: path, status: status))
        }
        await store.writer.flush()
        let page = try await store.summaries(offset: 10, limit: 5)
        #expect(page.map(\.id) == [11, 12, 13, 14, 15])
        var notFound = HistoryFilter()
        notFound.statusClasses = [4]
        let count404 = try await store.count(filter: notFound)
        #expect(count404 == 10)
        var noAssets = HistoryFilter()
        noAssets.hideStaticAssets = true
        let countNoAssets = try await store.count(filter: noAssets)
        #expect(countNoAssets == 24)
        var withParams = HistoryFilter()
        withParams.onlyWithParams = true
        let countParams = try await store.count(filter: withParams)
        #expect(countParams == 24)
        let newestFirst = HistorySort(column: .id, ascending: false)
        let newest = try await store.summaries(sort: newestFirst, offset: 0, limit: 1)
        #expect(newest.first?.id == 30)
        #expect(newest.first?.url == "http://example.test:8080/api/item29?id=29")
    }

    @Test("HIS-004/005: highlight, comment and delete")
    func test_annotationsAndDelete() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        for i in 0..<5 { _ = await store.writer.record(sampleExchange(path: "/\(i)")) }
        try await store.setHighlight(.red, for: [1, 2])
        try await store.setComment("look here", for: [3])
        var annotated = HistoryFilter()
        annotated.onlyAnnotated = true
        let annotatedCount = try await store.count(filter: annotated)
        #expect(annotatedCount == 3)
        let first = try await store.summaries(offset: 0, limit: 1)
        #expect(first.first?.highlight == .red)
        try await store.delete([4, 5])
        let remaining = try await store.count()
        #expect(remaining == 3)
    }

    @Test("PRJ-002/003: reopening a project shows the same history and continues the numbering")
    func test_reopen() async throws {
        let url = temporaryProject()
        do {
            let store = try ProjectStore.open(at: url)
            for i in 0..<10 { _ = await store.writer.record(sampleExchange(path: "/\(i)")) }
            try await store.close()
        }
        let reopened = try ProjectStore.open(at: url)
        let count = try await reopened.count()
        #expect(count == 10)
        let next = await reopened.writer.record(sampleExchange())
        #expect(next == 11)
    }

    @Test("F20 §5: a project open in one session cannot be opened again until it is closed")
    func test_singleWriterLock() async throws {
        let url = temporaryProject()
        let store = try ProjectStore.open(at: url)
        #expect(throws: StoreError.alreadyOpen(url.lastPathComponent)) {
            _ = try ProjectStore.open(at: url)
        }
        #expect(throws: StoreError.self) { try ProjectStore.ensureNotOpen(url) }
        try await store.close()
        let again = try ProjectStore.open(at: url)
        try await again.close()
    }

    @Test("Project settings are stored as JSON per key (doc 04 §6)")
    func test_settings() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        try await store.setSettingsJSON("proxy.listeners", Data(#"[{"port":8080}]"#.utf8))
        let json = try await store.settingsJSON("proxy.listeners")
        #expect(json.map { String(decoding: $0, as: UTF8.self) } == #"[{"port":8080}]"#)
    }
}
