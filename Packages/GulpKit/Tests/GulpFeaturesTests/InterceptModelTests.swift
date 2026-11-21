#if canImport(AppKit)
import GulpCore
import GulpWorkspace
import Testing

@testable import GulpFeatures

@MainActor
@Suite("Intercept model")
struct InterceptModelTests {
    /// PRX-011: an item the queue drops because its client went away leaves the list at once.
    @Test func test_PRX011_droppedItemLeavesTheList() async throws {
        let session = try await openIsolatedSession()
        await session.intercept.setIntercepting(requests: true)
        let model = InterceptModel(session: session)
        let queue = session.intercept
        let client = Task {
            await queue.holdRequest(
                RawRequest(Bytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")),
                target: HTTPTarget(scheme: .http, host: "example.com", port: 80))
        }
        #expect(await eventually { model.items.count == 1 })
        client.cancel()  // the client disconnected
        _ = await client.value
        #expect(await eventually { model.items.isEmpty })
        #expect(model.selectedID == nil)
        model.stop()
        try await session.close()
    }
}
#endif
