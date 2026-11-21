#if canImport(AppKit)
import Foundation
import GulpCore
import GulpRepeater
import GulpWorkspace
import Testing

@testable import GulpFeatures

@MainActor
@Suite("Repeater model")
struct RepeaterModelTests {
    /// REP-001: an edit survives switching to another tab and back (the local copy is updated, not
    /// only the service's), so Send transmits what the editor shows.
    @Test func test_REP001_draftEditSurvivesTabSwitch() async throws {
        let session = try await openIsolatedSession()
        let target = HTTPTarget(scheme: .https, host: "example.com", port: 443)
        let first = await session.repeater.openTab(
            request: RawRequest(Bytes("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")), target: target)
        let second = await session.repeater.openTab(
            request: RawRequest(Bytes("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")), target: target)
        let model = RepeaterModel(session: session)
        await model.reload(select: first.id)

        let edited = Array("GET /edited HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)
        model.draft = edited
        model.selectedID = second.id
        model.selectedID = first.id

        #expect(model.draft == edited)
        #expect(model.selected?.draft == edited)
        model.stop()
        try await session.close()
    }

    /// REP-016: streamed bytes reach the view at most every 100 ms, and the live view keeps at most
    /// `RepeaterModel.liveLimit` bytes however long the stream runs.
    @Test func test_REP016_liveResponseIsCoalescedAndBounded() async throws {
        let session = try await openIsolatedSession()
        let model = RepeaterModel(session: session)
        let id: Int64 = 1
        model.beginLive(for: id)
        let chunk = [UInt8](repeating: 0x41, count: 64 * 1_024)
        for _ in 0..<40 { model.received(chunk, for: id) }
        // Nothing is published until the 100 ms tick.
        #expect(model.live.isEmpty)
        #expect(await eventually { !model.live.isEmpty })
        #expect(model.live.count == RepeaterModel.liveLimit)
        #expect(model.liveTotal == 40 * chunk.count)
        model.endLive()
        model.stop()
        try await session.close()
    }
}
#endif
