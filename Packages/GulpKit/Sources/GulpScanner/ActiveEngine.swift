// GulpScanner — the active check engine (F08 SCN-030…SCN-038). A scan takes base requests, derives
// their insertion points, captures a baseline per point (plus a canary probe that tells a volatile
// page from a stable one), and runs every enabled check on every point. Checks send probes through
// the `AuditContext` (recorded as Scanner traffic, governed by the shared limiter), can measure time
// with repeated samples, and can register OAST payloads that are resolved after a grace period.

import Foundation
import GulpCore

/// One probe's outcome.
public struct Probe: Sendable {
    /// The request sent.
    public var request: RawRequest
    /// The response (nil on a network error).
    public var response: RawResponse?
    /// The recorded exchange (0 when not recorded).
    public var exchangeID: ExchangeID
    /// Seconds on the wire: from the end of the request write to the last response byte (HTTP-010's
    /// `ttfbMs + downloadMs`). Limiter and throttle waits, backoff and connection setup are excluded,
    /// so time-based checks measure the server; 0 when no response arrived.
    public var seconds: Double
    /// The network error, if any.
    public var error: String?

    /// A probe result.
    public init(
        request: RawRequest, response: RawResponse?, exchangeID: ExchangeID, seconds: Double,
        error: String? = nil
    ) {
        self.request = request
        self.response = response
        self.exchangeID = exchangeID
        self.seconds = seconds
        self.error = error
    }

    /// The response as text (decoded body, headers included), capped.
    public var text: String {
        guard let response else { return "" }
        let head = response.bytes[0..<min(response.parsed.headerBlockEnd, response.bytes.count)].rawBytes
        let body = ((try? response.decodedBody(limit: 4_000_000)) ?? nil)?.rawBytes ?? []
        return String(decoding: head + body, as: UTF8.self)
    }

    /// The body only, decoded.
    public var body: String {
        guard let response else { return "" }
        return String(
            decoding: ((try? response.decodedBody(limit: 4_000_000)) ?? nil)?.rawBytes ?? [], as: UTF8.self)
    }

    /// The status code.
    public var status: Int? { response?.parsed.statusCode }

    /// A header's value.
    public func header(_ name: String) -> String? { response?.headerValue(name)?.string() }
}

/// The baseline of an insertion point (SCN-031).
public struct Baseline: Sendable {
    /// The unmodified request's response.
    public var original: Probe
    /// A canary probe (a random alphanumeric value in the point).
    public var canary: Probe
    /// The canary value.
    public var canaryValue: String
    /// The page changes between identical-shape requests (length differs beyond the canary itself).
    public var volatile: Bool
}

/// Mints and resolves OAST payloads for checks (SCN-033); the workspace adapts its OAST service.
public protocol OASTProvider: Sendable {
    /// A new payload host (`<id>.<domain>`), or nil when OAST is off.
    func mint(note: String) async -> String?
    /// Protocols of the interactions that payload `host` caused so far.
    func interactions(forHost host: String) async -> [String]
    /// Poll for up to `seconds` (the grace period).
    func settle(seconds: Double) async
}

/// A check's handle on the scan (SCN-030).
public struct AuditContext: Sendable {
    /// The base request.
    public let base: RawRequest
    /// Where it goes.
    public let target: HTTPTarget
    /// Send a request (scope-checked, recorded, governed).
    public let send: @Sendable (RawRequest) async -> Probe
    /// OAST, when configured.
    public let oast: (any OASTProvider)?
    /// Register an OAST payload whose interaction proves `finding` (resolved after the grace period).
    public let expectOAST: @Sendable (_ host: String, _ finding: IssueFinding) async -> Void
    /// Payloads that could change data are allowed (SCN-038's "unsafe" gate).
    public let unsafe: Bool
    /// Timing samples per measurement (SCN-032).
    public let timingSamples: Int

    /// A random token (lowercase alphanumerics) for canaries.
    public func token(_ length: Int = 10) -> String {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz0123456789")
        return "g" + String((1..<length).map { _ in alphabet.randomElement()! })
    }

    /// A finding at this request's location.
    public func finding(
        _ definition: String, point: InsertionPoint?, variant: String = "", detail: String, evidence: Probe,
        marker: String? = nil, requestMarker: String? = nil, confidence: IssueConfidence? = nil
    ) -> IssueFinding {
        let def = IssueDefinitions.require(definition)
        let path = DerivedFields(target: target, request: base, response: nil).path ?? "/"
        var responseMarkers: [MarkerRange] = []
        if let marker, let wire = evidence.response?.wireBytes.rawBytes,
            let range = Self.find(Array(marker.utf8), in: wire)
        {
            responseMarkers.append(MarkerRange(range.lowerBound, range.upperBound))
        }
        var requestMarkers: [MarkerRange] = []
        if let requestMarker,
            let range = Self.find(Array(requestMarker.utf8), in: evidence.request.bytes.rawBytes)
        {
            requestMarkers.append(MarkerRange(range.lowerBound, range.upperBound))
        }
        return IssueFinding(
            typeID: def.id, name: def.name, severity: def.severity, confidence: confidence ?? def.confidence,
            host: Issue.origin(target), path: path, insertionPoint: point?.label, variant: variant,
            detail: detail,
            background: def.background, remediation: def.remediation, references: def.references,
            evidence: IssueEvidence(
                exchangeID: evidence.exchangeID == 0 ? nil : evidence.exchangeID,
                requestMarkers: requestMarkers,
                responseMarkers: responseMarkers))
    }

    static func find(_ needle: [UInt8], in haystack: [UInt8]) -> Range<Int>? {
        guard !needle.isEmpty, haystack.count >= needle.count else { return nil }
        for index in 0...(haystack.count - needle.count) where haystack[index] == needle[0] {
            if Array(haystack[index..<(index + needle.count)]) == needle {
                return index..<(index + needle.count)
            }
        }
        return nil
    }

    /// Median seconds of `samples` sends of `request` (SCN-032).
    public func time(_ request: RawRequest, samples: Int? = nil) async -> (seconds: Double, probe: Probe) {
        var times: [Double] = []
        var last: Probe?
        for _ in 0..<max(1, samples ?? timingSamples) {
            let probe = await send(request)
            times.append(probe.seconds)
            last = probe
        }
        times.sort()
        return (times[times.count / 2], last!)
    }
}

/// Check speed/precision tier.
public enum CheckIntensity: Int, Sendable, Codable, Hashable, Comparable {
    case light = 1, balanced = 2, thorough = 3

    /// Lighter tiers order first.
    public static func < (a: CheckIntensity, b: CheckIntensity) -> Bool { a.rawValue < b.rawValue }
}

/// An active check (SCN-030).
public protocol ActiveCheck: Sendable {
    /// Stable id (`active.sqli`).
    var id: String { get }
    /// Family name for configs.
    var family: String { get }
    /// The tier that enables it.
    var intensity: CheckIntensity { get }
    /// Insertion point kinds it tests (empty: request-level, run once per request).
    var kinds: Set<InsertionPointKind> { get }
    /// Probe `point` and return findings (OAST findings go through `context.expectOAST`).
    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding]
}

/// A scan configuration (SCN-034).
public struct ScanConfig: Sendable, Codable, Hashable {
    /// The presets.
    public enum Preset: String, Sendable, Codable, Hashable, CaseIterable {
        case passiveOnly = "passive-only", light, balanced, thorough, custom
    }

    /// The preset this config came from.
    public var preset: Preset
    /// Highest check tier run.
    public var intensity: CheckIntensity
    /// Check families to skip (by family name).
    public var disabledFamilies: Set<String>
    /// Insertion points.
    public var insertion: InsertionPolicy
    /// Parallel insertion points.
    public var concurrency: Int
    /// Timing samples per measurement.
    public var timingSamples: Int
    /// Seconds to wait for OAST interactions after the last probe (SCN-033).
    public var oastGraceSeconds: Double
    /// Max requests per insertion point (SCN-038).
    public var maxRequestsPerPoint: Int
    /// Allow payloads that could change data (SCN-038).
    public var unsafe: Bool
    /// Max requests for the whole scan; 0 is unlimited (SCN-038's global budget).
    public var maxRequests: Int
    /// Report one issue per type and path, listing every insertion point it was found at, instead
    /// of one per insertion point (SCN-036).
    public var consolidate: Bool

    /// A config.
    public init(
        preset: Preset = .balanced, intensity: CheckIntensity = .balanced, disabledFamilies: Set<String> = [],
        insertion: InsertionPolicy = InsertionPolicy(), concurrency: Int = 8, timingSamples: Int = 1,
        oastGraceSeconds: Double = 8, maxRequestsPerPoint: Int = 120, unsafe: Bool = false,
        maxRequests: Int = 0,
        consolidate: Bool = false
    ) {
        self.preset = preset
        self.intensity = intensity
        self.disabledFamilies = disabledFamilies
        self.insertion = insertion
        self.concurrency = concurrency
        self.timingSamples = timingSamples
        self.oastGraceSeconds = oastGraceSeconds
        self.maxRequestsPerPoint = maxRequestsPerPoint
        self.unsafe = unsafe
        self.maxRequests = maxRequests
        self.consolidate = consolidate
    }

    enum CodingKeys: String, CodingKey {
        case preset, intensity, disabledFamilies, insertion, concurrency, timingSamples, oastGraceSeconds
        case maxRequestsPerPoint, unsafe, maxRequests, consolidate
    }

    /// Decodes a config; missing keys take the preset's (or balanced) defaults, so saved configs
    /// keep loading as fields are added.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let base = ScanConfig.preset(try c.decodeIfPresent(Preset.self, forKey: .preset) ?? .custom)
        self.init(
            preset: base.preset,
            intensity: try c.decodeIfPresent(CheckIntensity.self, forKey: .intensity) ?? base.intensity,
            disabledFamilies: try c.decodeIfPresent(Set<String>.self, forKey: .disabledFamilies)
                ?? base.disabledFamilies,
            insertion: try c.decodeIfPresent(InsertionPolicy.self, forKey: .insertion) ?? base.insertion,
            concurrency: try c.decodeIfPresent(Int.self, forKey: .concurrency) ?? base.concurrency,
            timingSamples: try c.decodeIfPresent(Int.self, forKey: .timingSamples) ?? base.timingSamples,
            oastGraceSeconds: try c.decodeIfPresent(Double.self, forKey: .oastGraceSeconds)
                ?? base.oastGraceSeconds,
            maxRequestsPerPoint: try c.decodeIfPresent(Int.self, forKey: .maxRequestsPerPoint)
                ?? base.maxRequestsPerPoint,
            unsafe: try c.decodeIfPresent(Bool.self, forKey: .unsafe) ?? base.unsafe,
            maxRequests: try c.decodeIfPresent(Int.self, forKey: .maxRequests) ?? base.maxRequests,
            consolidate: try c.decodeIfPresent(Bool.self, forKey: .consolidate) ?? base.consolidate)
    }

    /// A preset's config (SCN-034).
    public static func preset(_ preset: Preset) -> ScanConfig {
        switch preset {
        case .passiveOnly:
            ScanConfig(preset: preset, intensity: .light, disabledFamilies: Set(ActiveChecks.families))
        case .light:
            ScanConfig(
                preset: preset, intensity: .light,
                insertion: InsertionPolicy(kinds: [
                    .urlParam, .bodyParam, .jsonValue, .protobufField, .custom,
                ]),
                timingSamples: 1)
        case .balanced: ScanConfig(preset: preset)
        case .thorough:
            ScanConfig(preset: preset, intensity: .thorough, timingSamples: 2, oastGraceSeconds: 15)
        case .custom: ScanConfig(preset: preset)
        }
    }
}

/// Live scan events (SCN-035).
public enum ScanEvent: Sendable {
    /// A finding (already deduplicated within the scan).
    case finding(IssueFinding)
    /// Progress: requests done/total, points done/total, probes sent.
    case progress(requestsDone: Int, requests: Int, pointsDone: Int, points: Int, probes: Int)
    /// A log line.
    case log(String)
    /// The scan ended.
    case finished(ScanSummary)
}

/// The end of a scan.
public struct ScanSummary: Sendable, Hashable {
    /// Findings reported.
    public var findings: Int
    /// Probes sent.
    public var probes: Int
    /// Requests skipped as out of scope.
    public var outOfScope: Int
    /// Seconds.
    public var seconds: Double
    /// Findings per check id.
    public var perCheck: [String: Int]
    /// `done`, `cancelled` or `budget` (the scan-wide request budget was spent).
    public var stopReason: String
}

/// A scan task (SCN-035).
public actor ActiveScan {
    /// What is scanned.
    public let requests: [(request: RawRequest, target: HTTPTarget)]
    /// The configuration.
    public let config: ScanConfig
    let checks: [any ActiveCheck]
    let sender: @Sendable (RawRequest, HTTPTarget) async -> Probe
    let inScope: @Sendable (HTTPTarget, String) async -> Bool
    let oast: (any OASTProvider)?
    let pointFilter: (@Sendable (InsertionPoint) -> Bool)?
    private var paused = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var cancelled = false
    private var probes = 0
    private var seen: Set<String> = []
    private var perCheck: [String: Int] = [:]
    private var pendingOAST: [(host: String, finding: IssueFinding)] = []
    private var consolidated: [String: (finding: IssueFinding, points: [String])] = [:]
    private var consolidatedOrder: [String] = []
    private var globalUsed = 0
    private var exhausted = false
    private var task: Task<Void, Never>?

    /// A scan of `requests` with `checks` (default: every built-in check enabled by `config`). With
    /// `points`, only the insertion points it accepts are tested and request-level checks don't run.
    public init(
        requests: [(request: RawRequest, target: HTTPTarget)], config: ScanConfig,
        checks: [any ActiveCheck]? = nil,
        send: @escaping @Sendable (RawRequest, HTTPTarget) async -> Probe,
        inScope: @escaping @Sendable (HTTPTarget, String) async -> Bool, oast: (any OASTProvider)? = nil,
        points pointFilter: (@Sendable (InsertionPoint) -> Bool)? = nil
    ) {
        self.pointFilter = pointFilter
        self.requests = requests
        self.config = config
        self.checks = (checks ?? ActiveChecks.all).filter {
            $0.intensity <= config.intensity && !config.disabledFamilies.contains($0.family)
        }
        self.sender = send
        self.inScope = inScope
        self.oast = oast
    }

    /// Start; events stream until the scan ends.
    public func start() -> AsyncStream<ScanEvent> {
        let (stream, continuation) = AsyncStream.makeStream(of: ScanEvent.self, bufferingPolicy: .unbounded)
        let started = ContinuousClock.now
        task = Task { await self.run(continuation, started: started) }
        continuation.onTermination = { [weak self] _ in Task { await self?.cancel() } }
        return stream
    }

    /// Pause before the next probe batch.
    public func pause() { paused = true }

    /// Resume.
    public func resume() {
        paused = false
        let woken = waiters
        waiters = []
        for waiter in woken { waiter.resume() }
    }

    /// Stop.
    public func cancel() {
        cancelled = true
        resume()
        task?.cancel()
    }

    /// Whether the scan is paused.
    public var isPaused: Bool { paused }

    func gate() async {
        while paused, !cancelled { await withCheckedContinuation { waiters.append($0) } }
    }

    func count() { probes += 1 }

    /// Keep the first finding per dedup key. With `consolidate` (SCN-036), findings of one type on
    /// one path are held back and merged: they are emitted at the end of the scan, one per type and
    /// path, listing every insertion point.
    func accept(_ finding: IssueFinding, check: String) -> Bool {
        guard seen.insert(finding.dedupKey).inserted else { return false }
        if config.consolidate {
            let key = [
                finding.typeID, finding.host.lowercased(), Issue.normalizedPath(finding.path),
                finding.variant,
            ]
            .joined(separator: "|")
            if consolidated[key] != nil {
                consolidated[key]?.points.append(finding.insertionPoint ?? "request")
            } else {
                consolidated[key] = (finding, [finding.insertionPoint ?? "request"])
                consolidatedOrder.append(key)
                perCheck[check, default: 0] += 1
            }
            return false
        }
        perCheck[check, default: 0] += 1
        return true
    }

    /// The merged findings of a consolidating scan.
    func mergedFindings() -> [IssueFinding] {
        consolidatedOrder.compactMap { key in
            guard var (finding, points) = consolidated[key] else { return nil }
            if points.count > 1 {
                finding.detail +=
                    "\n\nAlso found at: " + points.dropFirst().map { "**\($0)**" }.joined(separator: ", ")
                    + "."
            }
            return finding
        }
    }

    /// Take one request from the scan-wide budget (SCN-038); false once it is spent.
    func takeGlobal() -> Bool {
        guard config.maxRequests == 0 || globalUsed < config.maxRequests else {
            exhausted = true
            return false
        }
        globalUsed += 1
        return true
    }

    func addPending(_ host: String, _ finding: IssueFinding) { pendingOAST.append((host, finding)) }

    func run(_ continuation: AsyncStream<ScanEvent>.Continuation, started: ContinuousClock.Instant) async {
        var outOfScope = 0
        var units: [(request: RawRequest, target: HTTPTarget, point: InsertionPoint?)] = []
        for (request, target) in requests {
            let derived = DerivedFields(target: target, request: request, response: nil)
            let path = (derived.path ?? "/") + (derived.query.map { "?" + $0 } ?? "")
            guard await inScope(target, path) else {
                outOfScope += 1
                continuation.yield(.log("out of scope, not scanned: \(target.host)\(path)"))
                continue
            }
            if pointFilter == nil { units.append((request, target, nil)) }  // request-level checks
            for point in InsertionPoints.derive(request, policy: config.insertion)
            where pointFilter?(point) ?? true {
                units.append((request, target, point))
            }
        }
        let total = units.count
        var done = 0
        let concurrency = max(1, config.concurrency)
        await withTaskGroup(of: Void.self) { group in
            var iterator = units.makeIterator()
            func add() -> Bool {
                guard let unit = iterator.next() else { return false }
                group.addTask { await self.audit(unit.request, unit.target, unit.point, continuation) }
                return true
            }
            for _ in 0..<concurrency where add() {}
            while await group.next() != nil {
                done += 1
                continuation.yield(
                    .progress(
                        requestsDone: 0, requests: requests.count, pointsDone: done, points: total,
                        probes: probes))
                if cancelled { group.cancelAll() } else if !exhausted { _ = add() }
            }
        }
        // SCN-033: wait for late interactions, then resolve the registered payloads.
        if let oast, !pendingOAST.isEmpty, !cancelled {
            continuation.yield(
                .log(
                    "waiting \(Int(config.oastGraceSeconds)) s for OAST interactions (\(pendingOAST.count) payloads)"
                ))
            await oast.settle(seconds: config.oastGraceSeconds)
            for (host, finding) in pendingOAST {
                let protocols = await oast.interactions(forHost: host)
                guard !protocols.isEmpty else { continue }
                var confirmed = finding
                confirmed.detail +=
                    "\n\nThe target made \(protocols.joined(separator: " and ")) interaction(s) with `\(host)`."
                if accept(confirmed, check: confirmed.typeID) { continuation.yield(.finding(confirmed)) }
            }
        }
        for finding in mergedFindings() { continuation.yield(.finding(finding)) }
        if exhausted {
            continuation.yield(.log("the scan's request budget (\(config.maxRequests)) is spent"))
        }
        let elapsed = ContinuousClock.now - started
        let summary = ScanSummary(
            findings: perCheck.values.reduce(0, +), probes: probes, outOfScope: outOfScope,
            seconds: Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18,
            perCheck: perCheck,
            stopReason: cancelled ? "cancelled" : exhausted ? "budget" : "done")
        continuation.yield(.finished(summary))
        continuation.finish()
    }

    nonisolated func audit(
        _ request: RawRequest, _ target: HTTPTarget, _ point: InsertionPoint?,
        _ continuation: AsyncStream<ScanEvent>.Continuation
    ) async {
        let budget = Budget(limit: config.maxRequestsPerPoint)
        let sender = self.sender
        let context = AuditContext(
            base: request, target: target,
            send: { probe in
                await self.gate()
                guard await self.takeGlobal(), await budget.take() else {
                    return Probe(request: probe, response: nil, exchangeID: 0, seconds: 0, error: "budget")
                }
                await self.count()
                return await sender(probe, target)
            }, oast: oast, expectOAST: { host, finding in await self.addPending(host, finding) },
            unsafe: config.unsafe,
            timingSamples: config.timingSamples)
        let applicable = checks.filter { check in
            point.map { check.kinds.contains($0.kind) } ?? check.kinds.isEmpty
        }
        guard !applicable.isEmpty else { return }  // no baseline traffic for a point nothing tests
        var baseline: Baseline?
        if let point {
            let original = await context.send(request)
            let again = await context.send(request)
            let canaryValue = context.token(8)
            let canary = await context.send(point.build(request, payload: canaryValue))
            // Volatile: two identical requests already differ (timestamps, tokens), so length or
            // content comparisons can't be trusted on this point (F08 §6).
            let volatile = original.body != again.body || original.status != again.status
            baseline = Baseline(
                original: original, canary: canary, canaryValue: canaryValue, volatile: volatile)
        }
        for check in applicable {
            if await isCancelled() { return }
            var findings = await check.run(point, baseline: baseline, context: context)
            if let base = baseline?.original.exchangeID, base != 0 {
                for index in findings.indices { findings[index].baseExchangeID = base }
            }
            for finding in findings where await accept(finding, check: check.id) {
                continuation.yield(.finding(finding))
            }
        }
    }

    func isCancelled() -> Bool { cancelled }
}

/// A per-insertion-point request budget (SCN-038).
actor Budget {
    var used = 0
    let limit: Int
    init(limit: Int) { self.limit = limit }
    func take() -> Bool {
        guard used < limit else { return false }
        used += 1
        return true
    }
}

/// Re-testing one issue (SCN-037): which check produces an issue type.
public enum ActiveRetest {
    /// The built-in check that reports `typeID` (`active.sqli.boolean` → the SQL injection check).
    public static func check(for typeID: String) -> (any ActiveCheck)? {
        ActiveChecks.all.filter { typeID == $0.id || typeID.hasPrefix($0.id + ".") }.max {
            $0.id.count < $1.id.count
        }
    }
}
