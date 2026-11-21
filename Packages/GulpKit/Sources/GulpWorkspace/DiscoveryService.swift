// GulpWorkspace — "Discover content" in a project (F07 ETL-003) and the user's wordlists (FUZ-011).
// Discovery probes unrecorded; each found path's exchange is recorded (tagged `discovered`), so it
// shows in History and the site map. Probes are scope-checked unless explicitly overridden.

import Foundation
import GulpCore
import GulpFuzzer
import GulpStore

extension WorkspaceEnvironment {
    /// The user's wordlists folder (bundled lists are copied here on first use).
    public var wordlistsDirectory: URL { supportDirectory.appendingPathComponent("Wordlists") }

    /// Copy the bundled wordlists into `wordlistsDirectory` (existing files are kept).
    @discardableResult
    public func installWordlists() throws -> [String] {
        try BundledWordlists.install(into: wordlistsDirectory)
    }
}

extension ProjectSession {
    /// Start content discovery (ETL-003). Found paths stream out and are recorded in the project.
    public func discoverContent(_ config: DiscoveryConfig, allowOutOfScope: Bool = false) async throws
        -> (discovery: ContentDiscovery, events: AsyncStream<DiscoveryEvent>)
    {
        var config = config
        if let target = HTTPTarget(url: config.baseURL) {
            let observed = (try? await store.observedExtensions(host: target.host, port: target.port)) ?? []
            var seen: Set<String> = []
            config.extensions = (observed + config.extensions).filter { seen.insert($0).inserted }
        }
        let scopeGuard = self.scopeGuard
        var check: (@Sendable (HTTPTarget, String) async -> Bool)?
        if !allowOutOfScope {
            check = { @Sendable target, path in await scopeGuard.permits(target, path: path) }
        }
        let discovery = try ContentDiscovery(config: config, engine: http, inScope: check)
        let source = await discovery.start()
        let writer = store.writer
        let (events, continuation) = AsyncStream.makeStream(
            of: DiscoveryEvent.self, bufferingPolicy: .unbounded)
        // GOV-001: discovery has no pause of its own; its sends wait at the shared limiter.
        let tasks = activeTasks
        let taskID = UUID()
        await tasks.add(
            ActiveTask(
                id: taskID, kind: "discovery", name: config.baseURL, pause: {}, resume: {},
                cancel: { await discovery.cancel() }))
        Task {
            for await event in source {
                if case .found(var found) = event {
                    var exchange = found.exchange
                    exchange.id = 0
                    exchange.annotation.tags.append("discovered")
                    found.exchange.id = await writer.record(exchange)
                    continuation.yield(.found(found))
                } else {
                    await writer.flush()
                    continuation.yield(event)
                }
            }
            await tasks.remove(taskID)
            continuation.finish()
        }
        continuation.onTermination = { _ in Task { await discovery.cancel() } }
        return (discovery, events)
    }
}
