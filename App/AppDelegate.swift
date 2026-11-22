import AppKit
import GulpFeatures
import GulpWorkspace
import Observation
import os

/// Application delegate: quitting closes every open project first, `.gulp` files opened from
/// Finder, Open With or the Dock go to a project window, and launched browsers close with the app.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// ⌘Q: close every project (debounced Repeater drafts, the store's write coalescer and the
    /// passive scan queue are flushed) before the process exits.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard OpenProjects.shared.hasOpenProjects else { return .terminateNow }
        Task {
            await OpenProjects.shared.closeAll()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    /// BRW-004: closing Gulp closes the browsers it launched.
    func applicationWillTerminate(_ notification: Notification) {
        ProjectSession.terminateLaunchedBrowsers()
    }

    /// `.gulp` documents from Finder, Open With and the Dock (PRJ-002): a project window opens each.
    func application(_ application: NSApplication, open urls: [URL]) {
        OpenProjects.shared.requestOpen(urls.filter { $0.pathExtension == "gulp" })
    }
}

/// The projects open in this process, and `.gulp` files waiting for a window.
@MainActor
@Observable
final class OpenProjects {
    static let shared = OpenProjects()

    /// Files to open; the frontmost project window takes them (it can call `openWindow`).
    private(set) var pendingFiles: [URL] = []

    @ObservationIgnored private var open: [ObjectIdentifier: (session: ProjectSession, models: ToolModels)] =
        [:]
    @ObservationIgnored private let log = Logger(subsystem: "io.github.jimbo111.gulp", category: "projects")

    var hasOpenProjects: Bool { !open.isEmpty }

    /// Track a project a window opened.
    func add(_ session: ProjectSession, models: ToolModels) {
        open[ObjectIdentifier(session)] = (session, models)
    }

    /// Stop the project's tool models and close its session (its window is closing, or the app is
    /// quitting). Temporary projects are kept, recoverable in Caches, until a save/discard prompt
    /// lands.
    func close(_ session: ProjectSession) async {
        guard let entry = open.removeValue(forKey: ObjectIdentifier(session)) else { return }
        entry.models.stop()
        let path = await entry.session.url.path
        do {
            try await entry.session.close(keepTemporary: true)
        } catch {
            log.error("Closing \(path, privacy: .public) failed: \(error)")
        }
    }

    /// Close every open project.
    func closeAll() async {
        for (session, _) in Array(open.values) { await close(session) }
    }

    /// Queue `.gulp` files for a project window to open.
    func requestOpen(_ urls: [URL]) {
        pendingFiles += urls
    }

    /// Take the queued files (one window opens them, once).
    func takePendingFiles() -> [URL] {
        defer { pendingFiles = [] }
        return pendingFiles
    }
}
