// GulpFuzzer — running an attack (F07 FUZ-004, FUZ-014, FUZ-030, FUZ-031): N lanes pull requests from
// the plan, honour a requests-per-second cap and an optional delay (fixed + random jitter), check
// scope before every send (ScopeGuard, CLAUDE.md §4), retry failures, stop on a grep match or after
// N errors, and can be paused, resumed and cancelled. Results stream out as they arrive. Requests go
// through the shared engine (so the global throttle and the recorder apply) as source `fuzzer`.

import Foundation
import GulpCore
import GulpHTTP

/// The HTTP version an attack sends with (FUZ-003, as in the Repeater).
public enum FuzzHTTPVersion: String, Sendable, Hashable, Codable, CaseIterable {
    /// Negotiate via ALPN (HTTP/1.1 for plaintext).
    case auto
    /// Always HTTP/1.1.
    case http1_1
    /// HTTP/2 via ALPN.
    case http2
    /// Cleartext HTTP/2 with prior knowledge (h2c).
    case http2PriorKnowledge

    /// The engine's preference.
    public var preference: HTTPVersionPreference {
        switch self {
        case .auto: .auto
        case .http1_1: .http1_1
        case .http2: .http2
        case .http2PriorKnowledge: .http2PriorKnowledge
        }
    }
}

/// Attack settings (FUZ-030, FUZ-031).
public struct FuzzSettings: Sendable, Hashable, Codable {
    /// HTTP version (FUZ-003).
    public var httpVersion = FuzzHTTPVersion.auto
    /// Parallel requests.
    public var concurrency = 10
    /// Cap on requests per second (nil: none).
    public var requestsPerSecond: Double?
    /// Delay before each request on a lane (ms) …
    public var delayMs = 0
    /// … plus a random 0…jitter ms.
    public var delayJitterMs = 0
    /// Retries after a network error.
    public var retries = 0
    /// Stop when any grep-match column matches.
    public var stopOnGrepMatch = false
    /// Stop after this many errors.
    public var stopAfterErrors: Int?
    /// Recompute Content-Length after splicing payloads (FUZ-003 / F07 §5).
    public var updateContentLength = true
    /// Follow on-site redirects.
    public var followRedirects = false
    /// Total timeout per request (s).
    public var timeoutSeconds = 30
    /// Evaluate Transform Tags in the base request (F12; payload tags are a processor).
    public var transformTags = false
    /// The position marker (default §).
    public var marker = "§"

    /// Defaults.
    public init() {}

    /// Missing keys take their defaults, so attacks saved by an older build still open (FUZ-026).
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let defaults = FuzzSettings()
        httpVersion =
            try c.decodeIfPresent(FuzzHTTPVersion.self, forKey: .httpVersion) ?? defaults.httpVersion
        concurrency = try c.decodeIfPresent(Int.self, forKey: .concurrency) ?? defaults.concurrency
        requestsPerSecond = try c.decodeIfPresent(Double.self, forKey: .requestsPerSecond)
        delayMs = try c.decodeIfPresent(Int.self, forKey: .delayMs) ?? defaults.delayMs
        delayJitterMs = try c.decodeIfPresent(Int.self, forKey: .delayJitterMs) ?? defaults.delayJitterMs
        retries = try c.decodeIfPresent(Int.self, forKey: .retries) ?? defaults.retries
        stopOnGrepMatch =
            try c.decodeIfPresent(Bool.self, forKey: .stopOnGrepMatch) ?? defaults.stopOnGrepMatch
        stopAfterErrors = try c.decodeIfPresent(Int.self, forKey: .stopAfterErrors)
        updateContentLength =
            try c.decodeIfPresent(Bool.self, forKey: .updateContentLength) ?? defaults.updateContentLength
        followRedirects =
            try c.decodeIfPresent(Bool.self, forKey: .followRedirects) ?? defaults.followRedirects
        timeoutSeconds = try c.decodeIfPresent(Int.self, forKey: .timeoutSeconds) ?? defaults.timeoutSeconds
        transformTags = try c.decodeIfPresent(Bool.self, forKey: .transformTags) ?? defaults.transformTags
        marker = try c.decodeIfPresent(String.self, forKey: .marker) ?? defaults.marker
    }
}

/// Everything an attack needs (saved with the project, FUZ-026).
public struct FuzzAttackConfig: Sendable, Hashable, Codable {
    /// Display name.
    public var name: String
    /// Where requests go.
    public var target: HTTPTarget
    /// The base request with position markers.
    public var request: [UInt8]
    /// Attack type.
    public var attackType: AttackType
    /// Payload sets.
    public var sets: [PayloadSet]
    /// Grep-match columns.
    public var matches: [GrepMatch]
    /// Grep-extract columns.
    public var extracts: [GrepExtract]
    /// Settings.
    public var settings: FuzzSettings
    /// Protobuf field paths to fuzz inside the request's first message (GRP-005) instead of
    /// markers; nil or empty for a marker attack.
    public var rpcFields: [[Int]]?

    /// A configuration.
    public init(
        name: String, target: HTTPTarget, request: [UInt8], attackType: AttackType, sets: [PayloadSet],
        matches: [GrepMatch] = [], extracts: [GrepExtract] = [], settings: FuzzSettings = FuzzSettings(),
        rpcFields: [[Int]]? = nil
    ) {
        self.rpcFields = rpcFields
        self.name = name
        self.target = target
        self.request = request
        self.attackType = attackType
        self.sets = sets
        self.matches = matches
        self.extracts = extracts
        self.settings = settings
    }

    /// The plan (throws on bad markers, sets or processors).
    public func plan() throws -> AttackPlan {
        let template =
            if let rpcFields, !rpcFields.isEmpty {
                FuzzTemplate(rpc: try RPCPositions(request: request, paths: rpcFields))
            } else {
                try FuzzTemplate(request, marker: settings.marker)
            }
        return try AttackPlan(template: template, type: attackType, sets: sets)
    }
}

/// One row of results (FUZ-020).
public struct FuzzResult: Sendable, Hashable, Codable {
    /// Request number (1-based).
    public var seq: Int
    /// The payload per position (nil: base value), as text.
    public var payloads: [String?]
    /// The recorded exchange (0 if none).
    public var exchangeID: Int64
    /// Response status.
    public var status: Int?
    /// Response length (bytes on the wire).
    public var length: Int
    /// Time in ms.
    public var timeMs: Double
    /// Network error code, or `out_of_scope`.
    public var error: String?
    /// Grep columns and reflection.
    public var findings: ResponseFindings

    /// A result row.
    public init(
        seq: Int, payloads: [String?], exchangeID: Int64, status: Int?, length: Int, timeMs: Double,
        error: String?,
        findings: ResponseFindings
    ) {
        self.seq = seq
        self.payloads = payloads
        self.exchangeID = exchangeID
        self.status = status
        self.length = length
        self.timeMs = timeMs
        self.error = error
        self.findings = findings
    }
}

/// What an attack reports.
public enum FuzzEvent: Sendable {
    /// A result row.
    case result(FuzzResult)
    /// The attack ended.
    case finished(FuzzSummary)
}

/// How an attack ended.
public struct FuzzSummary: Sendable, Hashable, Codable {
    /// Requests sent (including errors).
    public var sent: Int
    /// Rows with an error.
    public var errors: Int
    /// Planned requests (before skip rules).
    public var planned: Int
    /// Wall time (s).
    public var seconds: Double
    /// Why it stopped early, if it did (`cancelled`, `grep match`, `errors`).
    public var stopReason: String?
    /// Requests ScopeGuard refused (reported, never sent).
    public var refused = 0

    /// Requests per second.
    public var rate: Double { seconds > 0 ? Double(sent) / seconds : 0 }
}

/// A running attack.
public actor FuzzAttack {
    /// The configuration.
    public let config: FuzzAttackConfig
    let plan: AttackPlan
    let analyzer: ResponseAnalyzer
    let engine: any HTTPEngine
    let inScope: (@Sendable (HTTPTarget, String) async -> Bool)?
    private var iterator: AnySequence<AttackItem>.Iterator
    private var paused = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var stopReason: String?
    private var sent = 0
    private var errors = 0
    private var refused = 0
    private var nextSlot: ContinuousClock.Instant?
    private var lastExtracts: [String?] = []
    private var task: Task<Void, Never>?

    /// An attack sending through `engine`; `inScope` decides whether each request may go (nil: no
    /// check — only for callers that already checked).
    public init(
        config: FuzzAttackConfig, engine: any HTTPEngine,
        inScope: (@Sendable (HTTPTarget, String) async -> Bool)?
    ) throws {
        self.config = config
        plan = try config.plan()
        analyzer = try ResponseAnalyzer(matches: config.matches, extracts: config.extracts)
        self.engine = engine
        self.inScope = inScope
        iterator = plan.items().makeIterator()
    }

    /// Positions whose set is a recursive-grep source (FUZ-014).
    var recursivePositions: [(position: Int, extractIndex: Int, initial: String)] {
        (0..<plan.template.positionCount).compactMap { position in
            if case .recursiveGrep(let index, let initial, _) = plan.sets[plan.setIndex(for: position)].source
            {
                return (position, index, initial)
            }
            return nil
        }
    }

    /// Start; results stream until the attack finishes, is stopped or cancelled.
    public func start() -> AsyncStream<FuzzEvent> {
        let (stream, continuation) = AsyncStream.makeStream(of: FuzzEvent.self, bufferingPolicy: .unbounded)
        let lanes = recursivePositions.isEmpty ? max(1, config.settings.concurrency) : 1
        let started = ContinuousClock.now
        let planned = plan.count
        task = Task {
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<lanes {
                    group.addTask { await self.lane(continuation) }
                }
            }
            let elapsed = ContinuousClock.now - started
            let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
            let summary = await self.summary(planned: planned, seconds: seconds)
            continuation.yield(.finished(summary))
            continuation.finish()
        }
        continuation.onTermination = { [weak self] _ in Task { await self?.cancel() } }
        return stream
    }

    func summary(planned: Int, seconds: Double) -> FuzzSummary {
        FuzzSummary(
            sent: sent, errors: errors, planned: planned, seconds: seconds, stopReason: stopReason,
            refused: refused)
    }

    /// Pause after the in-flight requests.
    public func pause() { paused = true }

    /// Resume a paused attack.
    public func resume() {
        paused = false
        let woken = waiters
        waiters = []
        for waiter in woken { waiter.resume() }
    }

    /// Stop the attack (in-flight requests finish and are reported).
    public func cancel() {
        if stopReason == nil { stopReason = "cancelled" }
        resume()
        task?.cancel()
    }

    /// Requests sent so far.
    public var progress: (sent: Int, errors: Int) { (sent, errors) }

    /// The next item, or nil when done or stopped.
    func nextItem() async -> AttackItem? {
        while paused, stopReason == nil {
            await withCheckedContinuation { waiters.append($0) }
        }
        guard stopReason == nil else { return nil }
        return iterator.next()
    }

    /// When this lane may send (the rps cap).
    func reserveSlot() -> ContinuousClock.Instant? {
        guard let rps = config.settings.requestsPerSecond, rps > 0 else { return nil }
        let now = ContinuousClock.now
        let interval = Duration.nanoseconds(Int64(1_000_000_000 / rps))
        let slot = max(now, nextSlot ?? now)
        nextSlot = slot + interval
        return slot
    }

    func record(_ result: FuzzResult) {
        if result.error == "out_of_scope" {
            refused += 1
        } else {
            sent += 1
            if result.error != nil { errors += 1 }
        }
        lastExtracts = result.findings.extracts
        if config.settings.stopOnGrepMatch, result.findings.matches.contains(true), stopReason == nil {
            stopReason = "grep match"
        }
        if let limit = config.settings.stopAfterErrors, errors >= limit, stopReason == nil {
            stopReason = "errors"
        }
    }

    func recursiveValue(_ extractIndex: Int, initial: String) -> String {
        guard extractIndex < lastExtracts.count, let value = lastExtracts[extractIndex] else {
            return initial
        }
        return value
    }

    nonisolated func lane(_ continuation: AsyncStream<FuzzEvent>.Continuation) async {
        let settings = config.settings
        var options = SendOptions(recordAs: .fuzzer)
        options.httpVersion = settings.httpVersion.preference
        options.updateContentLength = settings.updateContentLength
        options.timeouts.total = .seconds(settings.timeoutSeconds)
        if settings.followRedirects { options.followRedirects = RedirectPolicy(mode: .onSite) }
        options.scope = inScope  // every redirect hop is scope-checked too, not just the first request
        if !settings.transformTags { options.applyHooks.remove(.transformTags) }
        let recursive = await recursivePositions
        while !Task.isCancelled, var item = await nextItem() {
            // FUZ-014: the previous response's extract becomes this payload.
            for entry in recursive {
                let raw = Array(await recursiveValue(entry.extractIndex, initial: entry.initial).utf8)
                item.payloads[entry.position] =
                    (try? plan.process(raw, set: plan.setIndex(for: entry.position))) ?? raw
            }
            if settings.delayMs > 0 || settings.delayJitterMs > 0 {
                let delay =
                    settings.delayMs
                    + (settings.delayJitterMs > 0 ? Int.random(in: 0...settings.delayJitterMs) : 0)
                try? await Task.sleep(for: .milliseconds(delay))
            }
            if let slot = await reserveSlot() {
                try? await Task.sleep(until: slot, clock: .continuous)
            }
            let result = await send(item, options: options, retries: settings.retries)
            await record(result)
            continuation.yield(.result(result))
        }
    }

    nonisolated func send(_ item: AttackItem, options: SendOptions, retries: Int) async -> FuzzResult {
        let bytes = plan.request(for: item)
        let request = RawRequest(Bytes(bytes))
        let payloadTexts = item.payloads.map { $0.map { String(decoding: $0, as: UTF8.self) } }
        let sentPayloads = item.payloads.compactMap { $0 }
        let derived = DerivedFields(target: config.target, request: request, response: nil)
        let path = (derived.path ?? "/") + (derived.query.map { "?" + $0 } ?? "")
        if let inScope, await !inScope(config.target, path) {
            return FuzzResult(
                seq: item.seq, payloads: payloadTexts, exchangeID: 0, status: nil, length: 0, timeMs: 0,
                error: "out_of_scope", findings: analyzer.analyze(nil, payloads: []))
        }
        var attempt = 0
        while true {
            let result = await engine.send(request, to: config.target, options: options)
            if result.error != nil, attempt < retries, !Task.isCancelled {
                attempt += 1
                continue
            }
            let response = result.exchange.response
            return FuzzResult(
                seq: item.seq, payloads: payloadTexts, exchangeID: result.exchange.id,
                status: response?.parsed.statusCode, length: response?.wireBytes.count ?? 0,
                timeMs: result.exchange.timing.totalMs ?? 0, error: result.error?.code,
                findings: analyzer.analyze(response, payloads: sentPayloads))
        }
    }
}

/// CSV of results (FUZ-026): #, payloads, status, length, ms, error, grep columns, extracts, reflection.
public func fuzzResultsCSV(_ results: [FuzzResult], config: FuzzAttackConfig) -> String {
    func quote(_ text: String) -> String {
        text.contains(where: { $0 == "," || $0 == "\"" || $0.isNewline })
            ? "\"" + text.replacingOccurrences(of: "\"", with: "\"\"") + "\"" : text
    }
    var header = ["#", "payloads", "status", "length", "ms", "error"]
    header += config.matches.map { "match: \($0.pattern)" }
    header += config.extracts.indices.map { "extract \($0 + 1)" }
    header.append("reflected")
    var lines = [header.map(quote).joined(separator: ",")]
    for result in results {
        var fields = [
            String(result.seq), result.payloads.map { $0 ?? "" }.joined(separator: " | "),
            result.status.map(String.init) ?? "", String(result.length),
            String(format: "%.0f", result.timeMs),
            result.error ?? "",
        ]
        fields += result.findings.matches.map { $0 ? "1" : "0" }
        fields += result.findings.extracts.map { $0 ?? "" }
        fields.append(result.findings.reflection.rawValue)
        lines.append(fields.map(quote).joined(separator: ","))
    }
    return lines.joined(separator: "\r\n") + "\r\n"
}

extension FuzzResult: Identifiable {
    /// The row's sequence number.
    public var id: Int { seq }
}
