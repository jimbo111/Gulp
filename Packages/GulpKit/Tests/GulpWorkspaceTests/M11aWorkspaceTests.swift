import Foundation
import GulpCore
import GulpCrawler
import GulpHTTP
import GulpStore
import Testing

@testable import GulpWorkspace

// M11a in a project: strict crawl scope (CRL-001), OAST rows and payload linking (BCN-002), the
// panic stop over registered tasks (F20 GOV-001), and network settings (F03 §3.4).

@Suite("M11a workspace (CRL-001, BCN-002, GOV-001…003)")
struct M11aWorkspaceTests {
    @Test("CRL-001: with no scope the crawl fetches nothing; out-of-scope seeds are reported, not fetched")
    func test_CRL001_strictScope() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "crawl-scope")
        let run = await session.startCrawl(
            CrawlConfig(seeds: ["http://127.0.0.1:9/"], useRobotsAndSitemap: false))
        var report = CrawlReport()
        for await event in run.events { if case .finished(let done) = event { report = done } }
        #expect(report.pages.isEmpty && report.outOfScope == ["http://127.0.0.1:9/"])
        let running = await session.activeTasks.all
        #expect(running.isEmpty)  // unregistered when done
        try await session.close()
    }

    @Test("BCN-002: payloads link to the exchange that carried them; interactions match payloads by id")
    func test_BCN002_rows() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "oast-rows")
        let store = await session.store
        let id = "c58bduhe008dovpvhvugbfgyhuhk3mtty"
        try await store.addOASTPayload(
            id, host: "\(id).oast.test", context: OASTContext(tool: "fuzzer", insertionPoint: "position 1"))
        try await store.attachOASTPayloads([id], to: 42)
        let first = try await store.recordOASTInteraction(
            uniqueID: id.uppercased(), proto: "dns", remoteAddress: "10.0.0.1", at: Date(),
            raw: Array("q".utf8),
            summary: "A \(id)")
        #expect(first.payload?.exchangeID == 42 && first.payload?.context.insertionPoint == "position 1")
        let stray = try await store.recordOASTInteraction(
            uniqueID: "zzzzzzzzzzzzzzzzzzzzbfgyhuhk3mtty", proto: "http", remoteAddress: "", at: Date(),
            raw: [], summary: "")
        #expect(stray.payload == nil)
        #expect(try await store.oastInteractions(forExchange: 42).map(\.id) == [first.id])
        #expect(try await store.oastInteractions().map(\.id) == [stray.id, first.id])
        #expect(try await store.oastInteractionRaw(first.id) == Array("q".utf8))
        // Deleting the exchange doesn't fail on (or delete) the OAST rows.
        try await store.delete([42])
        #expect(try await store.oastPayloads().count == 1)
        try await session.close()
    }

    @Test("BCN-001: payload ids carrying the session's correlation id are found in request bytes")
    func test_BCN001_payloadIDs() {
        let prefix = Array("c58bduhe008dovpvhvug".utf8)
        let request = Array(
            "GET /f?u=http://c58bduhe008dovpvhvugbfgyhuhk3mtty.oast.test/&v=c58bduhe008dovpvhvugBAD&w=c58bduhe008dovpvhvugyyyyyyyyyyyyy HTTP/1.1\r\n\r\n"
                .utf8)
        #expect(
            OASTService.payloadIDs(in: request, prefix: prefix) == [
                "c58bduhe008dovpvhvugbfgyhuhk3mtty", "c58bduhe008dovpvhvugyyyyyyyyyyyyy",
            ])
        #expect(OASTService.payloadIDs(in: Array("nothing".utf8), prefix: prefix).isEmpty)
    }

    @Test("GOV-001: the panic stop pauses registered tasks and the limiter; resume all restarts them")
    func test_GOV001_panicStop() async throws {
        actor Log {
            var entries: [String] = []
            func add(_ entry: String) { entries.append(entry) }
        }
        let environment = isolatedEnvironment()
        let session = try await open(environment, "panic")
        let log = Log()
        await session.activeTasks.add(
            ActiveTask(
                id: UUID(), kind: "fuzzer", name: "a", pause: { await log.add("pause a") },
                resume: { await log.add("resume a") }))
        let report = await session.panicStop()
        #expect(report.tasks == ["fuzzer: a"] && report.cut == 0)
        let paused = await session.http.resources.isPaused
        let panicked = await session.isPanicked
        #expect(paused && panicked)
        // A task that starts during the panic is paused at once.
        await session.activeTasks.add(
            ActiveTask(
                id: UUID(), kind: "crawler", name: "b", pause: { await log.add("pause b") },
                resume: { await log.add("resume b") }))
        let resumed = await session.resumeAll()
        #expect(resumed.tasks == ["fuzzer: a", "crawler: b"])
        let entries = await log.entries
        #expect(entries == ["pause a", "pause b", "resume a", "resume b"])
        let stillPaused = await session.http.resources.isPaused
        #expect(!stillPaused)
        try await session.close()
    }

    @Test("F03 §3.4: network settings persist and are applied to the engine on open")
    func test_GOV002_settings() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "network")
        try await session.setNetworkSettings(
            NetworkSettings(
                rates: ThrottleLimits(globalPerSecond: 100),
                concurrency: ConcurrencyLimits(global: 10, perHost: 4, hosts: ["blocked.test": 0])))
        try await session.close()
        let reopened = try await open(environment, "network")
        let rates = await reopened.http.throttle.current
        #expect(rates.globalPerSecond == 100)
        let limits = await reopened.http.resources.current
        #expect(limits.global == 10 && limits.perHost == 4 && limits.cap(for: "blocked.test") == 0)
        #expect(!reopened.settings.get(OASTSettings.self).enabled)  // BCN-004: OAST off by default
        try await reopened.close()
    }
}
