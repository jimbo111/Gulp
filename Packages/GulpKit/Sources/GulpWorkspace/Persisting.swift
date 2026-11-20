// GulpWorkspace — store writes never fail silently. A dropped `store.record(finding)` loses an issue
// the user will never know existed, so a failed write is surfaced in the Event Log (doc 01 §8) instead.
// Scripts/rules-check.sh bans `try? await …store.<write>(…)` in this module; use `persisting` instead.

import GulpCore

/// Run the store write `write`; on failure publish a warning to the Event Log and return nil.
@discardableResult
func persisting<T: Sendable>(
    _ what: String, events: EventBus, isolation: isolated (any Actor)? = #isolation,
    _ write: () async throws -> T
) async -> T? {
    do {
        return try await write()
    } catch {
        await events.publish(
            .log(LogEntry(level: .warning, message: "Couldn't save \(what): \(error)", module: "gulp.store")))
        return nil
    }
}
