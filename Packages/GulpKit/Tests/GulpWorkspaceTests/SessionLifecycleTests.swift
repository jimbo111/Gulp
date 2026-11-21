import Foundation
import GulpCore
import GulpFuzzer
import GulpHTTP
import GulpProxy
import GulpStore
import Testing

@testable import GulpWorkspace

// Project lifecycle (F20 PRJ-002, GOV-001): work in flight during Save As and close goes to the file
// the session uses now, and close() stops active tools before the engine and the store shut down.

@Suite("Project lifecycle: Save As and close with work in flight (PRJ-002, GOV-001)", .serialized)
struct SessionLifecycleTests {
    @Test("PRJ-002: a response that completes during Save As's copy lands in the new file")
    func test_PRJ002_updateDuringSaveAsCopy() async throws {
        let environment = isolatedEnvironment()
        let old = try ProjectStore.open(at: projectURL(environment, "old"))
        let recorder = ProjectRecorder(store: old, events: EventBus())
        var exchange = Exchange(
            source: .proxy, target: HTTPTarget(scheme: .http, host: "a"),
            request: RawRequest(Bytes("GET / HTTP/1.1\r\nHost: a\r\n\r\n")))
        exchange.id = await recorder.record(exchange)
        await recorder.pause()
        let copy = projectURL(environment, "copy")
        try await old.backup(to: copy)  // Save As copies the file…
        exchange.response = RawResponse(Bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        exchange.state = .complete
        await recorder.update(exchange)  // …while the response completes.
        let new = try ProjectStore.open(at: copy)
        await recorder.resume(with: new)
        await new.writer.flush()
        #expect(try await new.exchange(id: exchange.id)?.response != nil)
        try await old.close()
        try await new.close()
    }

    /// Three requests to a closed port (each fails fast with connection refused).
    static func refusedAttack() -> FuzzAttackConfig {
        var settings = FuzzSettings()
        settings.timeoutSeconds = 5
        return FuzzAttackConfig(
            name: "ports", target: HTTPTarget(scheme: .http, host: "127.0.0.1", port: 1),
            request: Array("GET /§x§ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n".utf8), attackType: .sniper,
            sets: [PayloadSet(.list(["a", "b", "c"]))], matches: [], settings: settings)
    }

    @Test("PRJ-002: an attack running across Save As writes its results to the new file")
    func test_PRJ002_attackAcrossSaveAs() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "attack")
        await session.panicStop()  // the attack's sends wait at the limiter until resumed
        let run = try await session.startAttack(Self.refusedAttack(), allowOutOfScope: true)
        try await session.saveAs(projectURL(environment, "attack-saved"))
        await session.resumeAll()
        for await _ in run.events {}
        #expect(try await session.attackResults(run.id).count == 3)
        try await session.close()
    }

    @Test("GOV-001: close() cancels running active tools and waits for them before shutting down")
    func test_GOV001_closeCancelsActiveTasks() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "close-running")
        await session.panicStop()  // the attack can't finish on its own
        let run = try await session.startAttack(Self.refusedAttack(), allowOutOfScope: true)
        try await session.close()
        try #require(await session.activeTasks.all.isEmpty, "close() returned with a tool still running")
        var summary: FuzzSummary?
        for await event in run.events { if case .finished(let done) = event { summary = done } }
        #expect(summary?.stopReason == "cancelled")
    }

    @Test("PRX-001: a headless run's listener starts without replacing the project's proxy settings")
    func test_PRX001_runtimeListenerKeepsSettings() async throws {
        let session = try await open(isolatedEnvironment(), "listener")
        var stored = ProxySettings(
            listeners: [ProxyListenerConfig(port: 18_080)], passThroughHosts: ["*.example"])
        stored.useScope = true
        try await session.settings.set(stored, scope: .project)
        let result = await session.startProxyListener(ProxyListenerConfig(bindAddress: "127.0.0.1", port: 0))
        #expect(try result.get() > 0)
        #expect(session.settings.get(ProxySettings.self) == stored)
        try await session.close()
    }
}
