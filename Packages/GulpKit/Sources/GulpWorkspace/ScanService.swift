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
    /// Sends a probe through the session engine as recorded, governed Scanner traffic.
    func scanSender() -> @Sendable (RawRequest, HTTPTarget) async -> Probe {
        let engine = http
        return { request, target in
            var options = SendOptions(recordAs: .scanner)
            options.timeouts.total = .seconds(30)
            options.updateContentLength = false
            let result = await engine.send(request, to: target, options: options)
            // Wire time only (SCN-032): limiter/throttle waits, backoff and connection setup are
            // not the server's response time, so time-based checks must not see them.
            let timing = result.exchange.timing
            return Probe(
                request: result.exchange.request, response: result.exchange.response,
                exchangeID: result.exchange.id,
                seconds: ((timing.ttfbMs ?? 0) + (timing.downloadMs ?? 0)) / 1_000,
                error: result.error?.code)
        }
    }

    /// ScopeGuard as the scanner's scope check (strict unless overridden for this scan).
    func scanScope(allowOutOfScope: Bool) -> @Sendable (HTTPTarget, String) async -> Bool {
        if allowOutOfScope { return { @Sendable _, _ in true } }
        let scopeGuard = self.scopeGuard
        return { @Sendable target, path in await scopeGuard.permits(target, path: path) }
    }

    /// The project's OAST session for blind checks, when one is registered.
    func scanOAST() async -> (any OASTProvider)? {
        guard await oast.correlationID != nil else { return nil }
        return SessionOASTProvider(oast: oast, store: { [store] in store })
    }

    /// Start an active scan of `requests` (SCN-035).
    public func startActiveScan(
        _ requests: [(request: RawRequest, target: HTTPTarget)], config: ScanConfig,
        allowOutOfScope: Bool = false,
        name: String = "Active scan"
    ) async -> ScanRun {
        let send = scanSender()
        let inScope = scanScope(allowOutOfScope: allowOutOfScope)
        let provider = await scanOAST()
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

    /// Re-test one active issue (SCN-037): re-run the check that reported it, at the same insertion
    /// point, starting from the stored base request (or the evidence request when there is none).
    /// Found again: the new evidence is recorded and the issue is (re)opened. Not found: the issue is
    /// marked fixed.
    public func retestIssue(_ id: IssueID, allowOutOfScope: Bool = false) async throws -> RetestResult {
        guard let issue = try await store.issue(id) else {
            return RetestResult(outcome: .inconclusive, detail: "no such issue")
        }
        guard let check = ActiveRetest.check(for: issue.typeID) else {
            return RetestResult(
                outcome: .inconclusive, detail: "\(issue.typeID) isn't reported by an active check")
        }
        let base =
            issue.evidence.first { $0.note == IssueEvidence.baseRequestNote && $0.exchangeID != nil }
            ?? issue.evidence.last { $0.exchangeID != nil }
        guard let exchangeID = base?.exchangeID, let exchange = try await store.exchange(id: exchangeID)
        else {
            return RetestResult(outcome: .inconclusive, detail: "the issue has no request to re-send")
        }
        var config = ScanConfig.preset(.thorough)
        config.oastGraceSeconds = 8
        config.disabledFamilies = []  // re-running this one check is the opt-in, whatever its family
        let label = issue.insertionPoint
        let scan = ActiveScan(
            requests: [(exchange.request, exchange.target)], config: config, checks: [check],
            send: scanSender(),
            inScope: scanScope(allowOutOfScope: allowOutOfScope), oast: await scanOAST(),
            points: label.map { wanted in
                { @Sendable point in point.label.lowercased() == wanted.lowercased() }
            })
        var found: [IssueFinding] = []
        var summary: ScanSummary?
        for await event in await scan.start() {
            switch event {
            case .finding(let finding) where finding.typeID == issue.typeID: found.append(finding)
            case .finished(let done): summary = done
            default: break
            }
        }
        await store.writer.flush()
        if summary?.outOfScope ?? 0 > 0 {
            return RetestResult(outcome: .inconclusive, detail: "the request is out of scope")
        }
        if found.isEmpty {
            try await store.setIssueStatus(.fixed, for: [id])
            return RetestResult(
                outcome: .fixed, detail: "the check no longer finds it (\(summary?.probes ?? 0) requests)")
        }
        for finding in found { _ = try await store.record(finding) }
        return RetestResult(outcome: .stillPresent, detail: "found again (\(summary?.probes ?? 0) requests)")
    }
}

/// The verdict of a re-test (SCN-037).
public struct RetestResult: Sendable, Hashable {
    /// The verdict.
    public enum Outcome: String, Sendable, Hashable {
        /// Found again; the issue is open.
        case stillPresent = "still present"
        /// Not found; the issue is marked fixed.
        case fixed
        /// Couldn't re-test (no request, out of scope, not an active issue).
        case inconclusive
    }

    /// The verdict.
    public var outcome: Outcome
    /// Why.
    public var detail: String
}
