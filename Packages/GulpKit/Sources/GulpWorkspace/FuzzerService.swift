// GulpWorkspace — Fuzzer attacks in a project (F07 FUZ-004, FUZ-026, FUZ-030): start an attack on
// the session's engine with ScopeGuard checking every request (an explicit override sends out of
// scope), save it, stream its results to the caller while writing them to `fuzzer_results` in
// batches, and reload or export saved attacks.

import Foundation
import GulpCore
import GulpFuzzer
import GulpStore

/// A started attack.
public struct FuzzRun: Sendable {
    /// The saved attack's id.
    public let id: Int64
    /// Pause/resume/cancel.
    public let attack: FuzzAttack
    /// Results as they arrive, then `.finished`.
    public let events: AsyncStream<FuzzEvent>
}

/// The findings and error stored with a result row.
struct StoredFindings: Codable {
    var findings: ResponseFindings
    var error: String?
    var timeMs: Double
}

extension ProjectSession {
    /// Start an attack (FUZ-004). Every request is scope-checked unless `allowOutOfScope` (the explicit
    /// per-action override, CLAUDE.md §4); out-of-scope requests come back as rows with error
    /// `out_of_scope` and are not sent.
    public func startAttack(_ config: FuzzAttackConfig, allowOutOfScope: Bool = false) async throws -> FuzzRun
    {
        let scopeGuard = self.scopeGuard
        var check: (@Sendable (HTTPTarget, String) async -> Bool)?
        if !allowOutOfScope {
            check = { @Sendable target, path in await scopeGuard.permits(target, path: path) }
        }
        let attack = try FuzzAttack(config: config, engine: http, inScope: check)
        let store = self.store
        let eventBus = self.events
        let configJSON = String(decoding: try JSONEncoder().encode(config), as: UTF8.self)
        let id = try await store.createFuzzerAttack(
            name: config.name, configJSON: configJSON, baseRequest: config.request, state: "running")
        let source = await attack.start()
        let (events, continuation) = AsyncStream.makeStream(of: FuzzEvent.self, bufferingPolicy: .unbounded)
        let tasks = activeTasks
        let taskID = UUID()
        await tasks.add(
            ActiveTask(
                id: taskID, kind: "fuzzer", name: config.name, pause: { await attack.pause() },
                resume: { await attack.resume() }))
        Task {
            var pending: [FuzzerResultRow] = []
            var lastFlush = ContinuousClock.now
            for await event in source {
                switch event {
                case .result(let result):
                    pending.append(Self.row(result))
                    if pending.count >= 250 || ContinuousClock.now - lastFlush > .milliseconds(200) {
                        await persisting("fuzzer results", events: eventBus) {
                            try await store.appendFuzzerResults(id, pending)
                        }
                        pending = []
                        lastFlush = .now
                    }
                case .finished(let summary):
                    await persisting("fuzzer results", events: eventBus) {
                        try await store.appendFuzzerResults(id, pending)
                    }
                    pending = []
                    await persisting("the fuzzer attack state", events: eventBus) {
                        try await store.setFuzzerAttackState(id, summary.stopReason ?? "finished")
                    }
                }
                continuation.yield(event)
            }
            await tasks.remove(taskID)
            continuation.finish()
        }
        continuation.onTermination = { _ in Task { await attack.cancel() } }
        return FuzzRun(id: id, attack: attack, events: events)
    }

    static func row(_ result: FuzzResult) -> FuzzerResultRow {
        let encoder = JSONEncoder()
        let payloads =
            (try? encoder.encode(result.payloads)).map { String(decoding: $0, as: UTF8.self) } ?? "[]"
        let stored = StoredFindings(findings: result.findings, error: result.error, timeMs: result.timeMs)
        let grep = (try? encoder.encode(stored)).map { String(decoding: $0, as: UTF8.self) } ?? "{}"
        return FuzzerResultRow(
            seq: result.seq, payloadsJSON: payloads, exchangeID: result.exchangeID, status: result.status,
            length: result.length, timeMs: Int(result.timeMs.rounded()), grepJSON: grep)
    }

    /// Saved attacks, newest first, with their configurations.
    public func savedAttacks() async throws -> [(row: FuzzerAttackRow, config: FuzzAttackConfig?)] {
        try await store.fuzzerAttacks().map { row in
            (row, try? JSONDecoder().decode(FuzzAttackConfig.self, from: Data(row.configJSON.utf8)))
        }
    }

    /// A saved attack's results (FUZ-026 reopen), in request order.
    public func attackResults(_ id: Int64, offset: Int = 0, limit: Int = 100_000) async throws -> [FuzzResult]
    {
        let decoder = JSONDecoder()
        return try await store.fuzzerResults(id, offset: offset, limit: limit).map { row in
            let payloads = (try? decoder.decode([String?].self, from: Data(row.payloadsJSON.utf8))) ?? []
            let stored = try? decoder.decode(StoredFindings.self, from: Data(row.grepJSON.utf8))
            return FuzzResult(
                seq: row.seq, payloads: payloads, exchangeID: row.exchangeID, status: row.status,
                length: row.length,
                timeMs: stored?.timeMs ?? Double(row.timeMs), error: stored?.error,
                findings: stored?.findings ?? ResponseFindings(matches: [], extracts: [], reflection: .none))
        }
    }

    /// A saved attack's results as CSV (FUZ-026 export).
    public func exportAttackCSV(_ id: Int64) async throws -> String? {
        guard let config = try await savedAttacks().first(where: { $0.row.id == id })?.config else {
            return nil
        }
        return fuzzResultsCSV(try await attackResults(id), config: config)
    }

    /// Delete a saved attack and its results.
    public func deleteAttack(_ id: Int64) async throws {
        try await store.deleteFuzzerAttack(id)
    }
}
