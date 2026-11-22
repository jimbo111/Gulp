#if canImport(AppKit)
import Foundation
import GulpCore
import GulpStore
import GulpWorkspace
import Testing

@testable import GulpFeatures

@MainActor
@Suite("Open projects (PRJ-003, PRJ-004)", .serialized)
struct OpenProjectsTests {
    /// PRJ-003: closing the last window starts its project's close, and AppKit then asks to quit
    /// (`applicationShouldTerminateAfterLastWindowClosed`). The quit must wait for that close, or
    /// the exchanges the write coalescer still holds (up to ~50 ms of traffic) are lost.
    @Test func test_PRJ003_quitWaitsForAProjectStillClosing() async throws {
        let projects = OpenProjects()
        let session = try await openIsolatedSession()
        let url = await session.url
        projects.add(session, models: ToolModels(session: session))
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
        for _ in 0..<20 {
            let exchange = Exchange(
                source: .proxy, target: HTTPTarget(scheme: .http, host: "a"), request: request)
            _ = await session.store.writer.record(exchange)  // queued, not yet written
        }
        let windowClose = Task { await projects.close(session) }  // the window's onDisappear
        await Task.yield()  // it has started closing

        // `applicationShouldTerminate` answers `.terminateNow` when nothing is open.
        #expect(projects.hasOpenProjects, "a project still closing must hold the quit")
        await projects.closeAll()  // what `.terminateLater` waits for; the process may exit after it

        let reopened = try ProjectStore.open(at: url)
        #expect(try await reopened.count() == 20)
        try await reopened.close()
        await windowClose.value
    }

    /// NB-002: a note typed just before the window closes (or ⌘Q) is saved, though the Notebook
    /// waits 400 ms after the last keystroke before writing.
    @Test func test_NB002_closeSavesANoteStillBeingTyped() async throws {
        let projects = OpenProjects()
        let session = try await openIsolatedSession()
        let url = await session.url
        let models = ToolModels(session: session)
        projects.add(session, models: models)
        let item = try await session.addNote(title: "Login")
        models.notebook.edit(item.id, NotebookEdit(note: "the reset token is reusable"))
        await projects.close(session)

        let reopened = try ProjectStore.open(at: url)
        let saved = try await reopened.notebookItems().first { $0.id == item.id }
        #expect(saved?.note == "the reset token is reusable")
        try await reopened.close()
    }
}
#endif
