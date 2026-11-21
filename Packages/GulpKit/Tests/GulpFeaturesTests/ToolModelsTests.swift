#if canImport(AppKit)
import Foundation
import GulpCore
import GulpRepeater
import GulpWorkspace
import Testing

@testable import GulpFeatures

@MainActor
@Suite("Tool models")
struct ToolModelsTests {
    /// docs/05 §8: each tool has one model per open project, so switching tools keeps a running
    /// scan, crawl or attack under its Pause/Stop controls and never starts a second one beside it.
    @Test func test_UI_oneModelPerToolPerSession() async throws {
        let session = try await openIsolatedSession()
        let models = ToolModels(session: session)
        #expect(models.activeScan === models.activeScan)
        #expect(models.crawler === models.crawler)
        #expect(models.fuzzer === models.fuzzer)
        #expect(models.repeater === models.repeater)
        #expect(models.decoder === models.decoder)
        #expect(models.siteMap === models.siteMap)
        models.stop()
        try await session.close()
    }

    /// AGENTS.md §4 / doc 01 §5.4: a model's session subscription ends when the window closes;
    /// "Send to Repeater" no longer reaches a stopped model.
    @Test func test_UI_stopEndsSessionSubscriptions() async throws {
        let session = try await openIsolatedSession()
        let models = ToolModels(session: session)
        let repeater = models.repeater
        let target = HTTPTarget(scheme: .https, host: "example.com", port: 443)
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        let first = await session.repeater.openTab(request: request, target: target)
        await session.events.publish(.repeaterTabOpened(first.id))
        #expect(await eventually { repeater.tabs.count == 1 })

        models.stop()
        try await Task.sleep(for: .milliseconds(50))
        let second = await session.repeater.openTab(request: request, target: target)
        await session.events.publish(.repeaterTabOpened(second.id))
        try await Task.sleep(for: .milliseconds(200))
        #expect(repeater.tabs.count == 1)
        try await session.close()
    }

    /// F10 §3: Beacon polls only while its view is shown; cancelling the view's task ends the loop.
    @Test func test_OAST_beaconPollEndsWithItsTask() async throws {
        let session = try await openIsolatedSession()
        let beacon = ToolModels(session: session).beacon
        let poll = Task { await beacon.poll() }
        #expect(await eventually { beacon.health != nil })
        poll.cancel()
        await poll.value
        try await session.close()
    }
}
#endif
