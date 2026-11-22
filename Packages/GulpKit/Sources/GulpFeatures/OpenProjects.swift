// GulpFeatures — the projects open in this process (PRJ-004), for the app delegate and the project
// windows: closing a window closes its project, and quitting closes every project first.

#if canImport(AppKit)
import Foundation
import GulpWorkspace
import Observation
import os

/// The projects open in this process, and `.gulp` files waiting for a window.
@MainActor
@Observable
public final class OpenProjects {
    /// The app's one instance.
    public static let shared = OpenProjects()

    /// Files to open; the frontmost project window takes them (it can call `openWindow`).
    public private(set) var pendingFiles: [URL] = []

    /// A project stays here until its close has finished, so a quit never exits while one is still
    /// writing (PRJ-003). `closing` is the close in flight, which every caller waits for.
    @ObservationIgnored private var open:
        [ObjectIdentifier: (session: ProjectSession, models: ToolModels, closing: Task<Void, Never>?)] = [:]
    @ObservationIgnored private let log = Logger(subsystem: "com.gulp.app", category: "projects")

    init() {}

    /// Whether any project is open or still closing.
    public var hasOpenProjects: Bool { !open.isEmpty }

    /// Track a project a window opened.
    public func add(_ session: ProjectSession, models: ToolModels) {
        open[ObjectIdentifier(session)] = (session, models, nil)
    }

    /// Stop the project's tool models and close its session (its window is closing, or the app is
    /// quitting); returns once it is closed. Temporary projects are kept, recoverable in Caches,
    /// until a save/discard prompt lands.
    public func close(_ session: ProjectSession) async {
        let key = ObjectIdentifier(session)
        guard var entry = open[key] else { return }
        let closing = entry.closing ?? startClosing(entry.session, models: entry.models)
        entry.closing = closing
        open[key] = entry
        await closing.value
        open[key] = nil
    }

    private func startClosing(_ session: ProjectSession, models: ToolModels) -> Task<Void, Never> {
        models.stop()
        let log = self.log
        return Task {
            await models.flushPendingWrites()  // e.g. a Notebook note still in its typing pause
            let path = await session.url.path
            do {
                try await session.close(keepTemporary: true)
            } catch {
                log.error("Closing \(path, privacy: .public) failed: \(error)")
            }
        }
    }

    /// Close every open project, and wait for closes already in progress.
    public func closeAll() async {
        for entry in Array(open.values) { await close(entry.session) }
    }

    /// Queue `.gulp` files for a project window to open.
    public func requestOpen(_ urls: [URL]) {
        pendingFiles += urls
    }

    /// Take the queued files (one window opens them, once).
    public func takePendingFiles() -> [URL] {
        defer { pendingFiles = [] }
        return pendingFiles
    }
}
#endif
