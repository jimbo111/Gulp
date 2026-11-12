// GulpWorkspace — active scans in a project (F08 SCN-030…SCN-038, M11b). A scan sends through the
// session's engine as Scanner traffic (recorded; governed by the shared limiter, so the panic stop
// pauses it), checks every request against ScopeGuard (strict; an explicit override scans out of
// scope), records findings as issues (deduplicated by SCN-003's key), and uses the project's OAST
// session for blind checks, waiting the grace period before it finishes.

import Foundation
import GulpCore
import GulpHTTP
import GulpScanner
import GulpStore

/// A started active scan.
public struct ScanRun: Sendable {
    /// Pause/resume/cancel.
    public let scan: ActiveScan
    /// Events (findings are already recorded as issues when they arrive), then `.finished`.
    public let events: AsyncStream<ScanEvent>
}

/// Adapts the project's OAST session for scanner checks (SCN-033).
struct SessionOASTProvider: OASTProvider {
    let oast: OASTService
    let store: @Sendable () async -> ProjectStore

    func mint(note: String) async -> String? {
        try? await oast.mint(OASTContext(tool: "scanner", note: note)).host
    }

    func interactions(forHost host: String) async -> [String] {
        let id = String(host.split(separator: ".").first ?? "")
        return ((try? await store().oastInteractions(uniqueID: id)) ?? []).map(\.proto)
    }

    func settle(seconds: Double) async {
        await oast.drain(timeout: .seconds(seconds), quiet: .seconds(min(3, seconds)))
    }
}

extension ProjectSession {
    /// Start an active scan of `requests` (SCN-035).
    public func startActiveScan(
        _ requests: [(request: RawRequest, target: HTTPTarget)], config: ScanConfig,
        allowOutOfScope: Bool = false,
        name: String = "Active scan"
    ) async -> ScanRun {
        let engine = http
        let send: @Sendable (RawRequest, HTTPTarget) async -> Probe = { request, target in
            var options = SendOptions(recordAs: .scanner)
            options.timeouts.total = .seconds(30)
            options.updateContentLength = false
            let started = ContinuousClock.now
            let result = await engine.send(request, to: target, options: options)
            let elapsed = ContinuousClock.now - started
            return Probe(
                request: result.exchange.request, response: result.exchange.response,
                exchangeID: result.exchange.id,
                seconds: Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18,
                error: result.error?.code)
        }
        let scopeGuard = self.scopeGuard
        let inScope: @Sendable (HTTPTarget, String) async -> Bool
        if allowOutOfScope {
            inScope = { @Sendable _, _ in true }
        } else {
            inScope = { @Sendable target, path in await scopeGuard.permits(target, path: path) }
        }
        let registered = await oast.correlationID != nil
        let provider: (any OASTProvider)? =
            registered ? SessionOASTProvider(oast: oast, store: { [store] in store }) : nil
        let scan = ActiveScan(
            requests: requests, config: config, send: send, inScope: inScope, oast: provider)
        let source = await scan.start()
        let (events, continuation) = AsyncStream.makeStream(of: ScanEvent.self, bufferingPolicy: .unbounded)
        let tasks = activeTasks
        let taskID = UUID()
        await tasks.add(
            ActiveTask(
                id: taskID, kind: "scanner", name: name, pause: { await scan.pause() },
                resume: { await scan.resume() }))
        let store = self.store
        let eventBus = events_
        Task {
            for await event in source {
                if case .finding(let finding) = event {
                    // The evidence exchange may still sit in the write coalescer: commit it first
                    // (issue evidence references it).
                    await store.writer.flush()
                    do {
                        let result = try await store.record(finding)
                        await eventBus.publish(.issueFound(result.id))
                    } catch {
                        await eventBus.publish(
                            .log(
                                LogEntry(
                                    level: .error,
                                    message: "Scanner: couldn't record \(finding.typeID): \(error)",
                                    module: "gulp.scanner")))
                    }
                }
                if case .finished = event { await store.writer.flush() }
                continuation.yield(event)
            }
            await tasks.remove(taskID)
            continuation.finish()
        }
        continuation.onTermination = { _ in Task { await scan.cancel() } }
        return ScanRun(scan: scan, events: events)
    }

    /// Requests from recorded exchanges ("Actively scan" on History rows).
    public func scanRequests(exchanges ids: [ExchangeID]) async throws -> [(
        request: RawRequest, target: HTTPTarget
    )] {
        var requests: [(RawRequest, HTTPTarget)] = []
        for id in ids {
            if let exchange = try await store.exchange(id: id) {
                requests.append((exchange.request, exchange.target))
            }
        }
        return requests
    }

    nonisolated var events_: EventBus { events }
}
