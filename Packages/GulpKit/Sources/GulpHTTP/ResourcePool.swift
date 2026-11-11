// GulpHTTP — the shared limiter for active tools (F03 §3.4, moved from the F29 Governor): one pool
// per engine that every active tool's send draws from.
//
// - GOV-002: a global concurrency cap (with the HTTP-013 global rate in `Throttle`).
// - GOV-003: a per-host concurrency budget (with the HTTP-013 per-host rate); a per-host cap of 0
//   blocks that host for active tools.
// - GOV-007: adaptive backoff — a burst of 429/503/timeouts halves the host's rate for active tools,
//   and a run of good responses raises it again until the original rate is back.
// - F20 GOV-001: the panic stop pauses the pool. New sends wait; sends in flight are cut (their
//   cancel handlers run), and the engine re-sends them when the pool resumes.
//
// Proxy and Repeater traffic is not governed (it is the user's own); `SendOptions.isGoverned` says
// which sends draw from the pool.

import Foundation

/// Concurrency budgets and backoff for active tools (GOV-002, GOV-003, GOV-007).
public struct ConcurrencyLimits: Sendable, Codable, Hashable {
    /// Max requests in flight across all hosts (nil: unlimited).
    public var global: Int?
    /// Max requests in flight to each host without an override (nil: unlimited).
    public var perHost: Int?
    /// Per-host overrides (lowercased host names); 0 blocks the host for active tools.
    public var hosts: [String: Int]
    /// Adaptive backoff on bursts of 429/503/timeouts (GOV-007).
    public var adaptiveBackoff: Bool

    /// Limits; the defaults are conservative (GOV-003).
    public init(
        global: Int? = 128, perHost: Int? = 32, hosts: [String: Int] = [:], adaptiveBackoff: Bool = true
    ) {
        self.global = global
        self.perHost = perHost
        self.hosts = hosts
        self.adaptiveBackoff = adaptiveBackoff
    }

    /// The cap for `host` (lowercased), nil when unlimited.
    public func cap(for host: String) -> Int? { hosts[host] ?? perHost }
}

/// Why the pool refused a send.
public enum PoolRefusal: Error, Sendable, Equatable {
    /// The host's cap is 0 (GOV-003).
    case blocked(host: String)
    /// The waiting task was cancelled.
    case cancelled
}

/// A host's backoff state, for the "throttled" badge (GOV-007).
public struct HostBackoff: Sendable, Hashable {
    /// The host.
    public var host: String
    /// The current rate cap for active tools (requests per second).
    public var rate: Double
    /// The rate observed before the backoff began.
    public var originalRate: Double
}

/// The shared limiter. See the file comment.
public actor ResourcePool {
    /// A granted slot; give it back with `release`.
    public struct Permit: Sendable, Hashable {
        /// Identity.
        public let id: UInt64
        /// The host (lowercased).
        public let host: String
    }

    /// How a governed send ended, for backoff.
    public enum Outcome: Sendable, Equatable {
        /// A response with this status.
        case status(Int)
        /// A timeout (counts against the host).
        case timeout
        /// Anything else (doesn't count).
        case other
    }

    private let throttle: Throttle
    private var limits: ConcurrencyLimits
    private var paused = false
    private var nextID: UInt64 = 1
    private var inFlight = 0
    private var inFlightByHost: [String: Int] = [:]
    private var waiters: [UInt64: CheckedContinuation<Void, Never>] = [:]
    private var waiterOrder: [UInt64] = []
    private var cancelHandlers: [UInt64: @Sendable () -> Void] = [:]
    private var revoked: Set<UInt64> = []
    /// Sends released so far, counted once their rate slot came up (a monotonic counter; rates
    /// are measured from it).
    public private(set) var granted = 0
    private var peakGlobal = 0
    private var peakByHost: [String: Int] = [:]
    private var health: [String: HostHealth] = [:]

    struct HostHealth {
        var outcomes: [(at: ContinuousClock.Instant, bad: Bool)] = []
        var completions: [ContinuousClock.Instant] = []
        var rate: Double?
        var originalRate: Double = 0
        var lastChange: ContinuousClock.Instant?
    }

    /// A pool drawing rates from `throttle`.
    public init(throttle: Throttle, limits: ConcurrencyLimits = ConcurrencyLimits()) {
        self.throttle = throttle
        self.limits = limits
    }

    /// Change the budgets; waiting sends re-check them.
    public func set(_ limits: ConcurrencyLimits) async {
        self.limits = limits
        wakeAll()
        if !limits.adaptiveBackoff {
            let backedOff = health.keys.filter { health[$0]?.rate != nil }
            for host in backedOff { health[host]?.rate = nil }
            for host in backedOff { await throttle.setBackoff(host, rate: nil) }
        }
    }

    /// The current budgets.
    public var current: ConcurrencyLimits { limits }

    // MARK: acquire / release

    /// Wait for a slot to send to `host`: not paused, within the global and per-host concurrency
    /// caps, then the rate schedule (HTTP-013 plus any backoff). Throws when the host is blocked or
    /// the task is cancelled while waiting.
    public func acquire(host: String) async throws(PoolRefusal) -> Permit {
        let host = host.lowercased()
        while true {
            if limits.cap(for: host) == 0 { throw .blocked(host: host) }
            if Task.isCancelled { throw .cancelled }
            if !paused, hasRoom(host) {
                let id = nextID
                nextID += 1
                inFlight += 1
                inFlightByHost[host, default: 0] += 1
                peakGlobal = max(peakGlobal, inFlight)
                peakByHost[host] = max(peakByHost[host] ?? 0, inFlightByHost[host] ?? 0)
                let permit = Permit(id: id, host: host)
                // The rate schedule (and backoff) while holding the slot.
                let throttle = self.throttle
                await throttle.acquire(host: host, governed: true)
                if paused || Task.isCancelled {
                    // Paused (or cancelled) while waiting for the rate slot: give it back.
                    await release(permit, outcome: .other)
                    if Task.isCancelled { throw .cancelled }
                    continue
                }
                granted += 1  // released to send: counted after the rate slot, so rates measure sends
                return permit
            }
            await wait()
        }
    }

    private func hasRoom(_ host: String) -> Bool {
        if let global = limits.global, inFlight >= global { return false }
        if let cap = limits.cap(for: host), (inFlightByHost[host] ?? 0) >= cap { return false }
        return true
    }

    private func wait() async {
        let id = nextID
        nextID += 1
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume()
                } else {
                    waiters[id] = continuation
                    waiterOrder.append(id)
                }
            }
        } onCancel: {
            Task { await self.wake(id) }
        }
    }

    private func wake(_ id: UInt64) {
        waiters.removeValue(forKey: id)?.resume()
        waiterOrder.removeAll { $0 == id }
    }

    private func wakeAll() {
        let order = waiterOrder
        waiterOrder = []
        for id in order { waiters.removeValue(forKey: id)?.resume() }
    }

    /// Register how to cut `permit`'s send (the panic stop calls it). Runs at once if the pool was
    /// paused in between.
    public func attach(_ permit: Permit, cancel: @escaping @Sendable () -> Void) {
        if paused || revoked.contains(permit.id) {
            revoked.insert(permit.id)
            cancel()
        } else {
            cancelHandlers[permit.id] = cancel
        }
    }

    /// Give a slot back, with the send's outcome for backoff. Returns true when the send was cut by
    /// the panic stop (the caller re-sends after resume).
    @discardableResult
    public func release(_ permit: Permit, outcome: Outcome) async -> Bool {
        inFlight -= 1
        inFlightByHost[permit.host, default: 1] -= 1
        if inFlightByHost[permit.host] == 0 { inFlightByHost[permit.host] = nil }
        cancelHandlers[permit.id] = nil
        let wasRevoked = revoked.remove(permit.id) != nil
        let change = wasRevoked ? nil : observe(permit.host, outcome, now: .now)
        wakeAll()
        if let change { await throttle.setBackoff(permit.host, rate: change.rate) }
        return wasRevoked
    }

    // MARK: panic stop (F20 GOV-001)

    /// Pause: new sends wait, and every send in flight is cut. Returns how many were cut.
    @discardableResult
    public func pause() -> Int {
        paused = true
        let handlers = cancelHandlers
        cancelHandlers = [:]
        for (id, cancel) in handlers {
            revoked.insert(id)
            cancel()
        }
        return handlers.count
    }

    /// Resume: waiting and cut sends go again.
    public func resume() {
        paused = false
        wakeAll()
    }

    /// Whether the pool is paused.
    public var isPaused: Bool { paused }

    /// Requests in flight now (global, per host).
    public var inFlightCount: (global: Int, byHost: [String: Int]) { (inFlight, inFlightByHost) }

    /// The highest in-flight counts since the last reset (for measurements and the throughput
    /// panel).
    public var peaks: (global: Int, byHost: [String: Int]) { (peakGlobal, peakByHost) }

    /// Reset `peaks`.
    public func resetPeaks() {
        peakGlobal = inFlight
        peakByHost = inFlightByHost
    }

    // MARK: adaptive backoff (GOV-007)

    /// Bad outcomes (429/503/timeouts) among a host's last `window` that start a backoff step.
    static let burst = 5
    static let window = 20
    /// Consecutive good outcomes that allow a recovery step.
    static let recoveryRun = 10
    static let stepInterval = Duration.seconds(1)
    static let minimumRate = 1.0

    /// Hosts currently backed off.
    public var throttledHosts: [HostBackoff] {
        health.compactMap { host, state in
            state.rate.map { HostBackoff(host: host, rate: $0, originalRate: state.originalRate) }
        }.sorted { $0.host < $1.host }
    }

    /// Clear a host's backoff now (the manual override).
    public func clearBackoff(_ host: String) async {
        let host = host.lowercased()
        health[host]?.rate = nil
        health[host]?.outcomes = []
        await throttle.setBackoff(host, rate: nil)
    }

    /// A change to a host's backoff rate (nil rate: cleared).
    struct BackoffChange: Equatable {
        var rate: Double?
    }

    /// Record an outcome; returns the backoff change it causes, if any.
    func observe(_ host: String, _ outcome: Outcome, now: ContinuousClock.Instant) -> BackoffChange? {
        let bad: Bool
        switch outcome {
        case .status(let code): bad = code == 429 || code == 503
        case .timeout: bad = true
        case .other: return nil
        }
        var state = health[host] ?? HostHealth()
        state.completions.append(now)
        state.completions.removeAll { now - $0 > .seconds(1) }
        state.outcomes.append((now, bad))
        if state.outcomes.count > Self.window {
            state.outcomes.removeFirst(state.outcomes.count - Self.window)
        }
        defer { health[host] = state }
        guard limits.adaptiveBackoff else { return nil }
        let settled = state.lastChange.map { now - $0 >= Self.stepInterval } ?? true
        let recent = state.outcomes.filter { now - $0.at <= .seconds(10) }
        if recent.filter(\.bad).count >= Self.burst, settled {
            let observed = Double(max(1, state.completions.count))
            if state.rate == nil { state.originalRate = observed }
            let next = max(Self.minimumRate, (state.rate ?? observed) / 2)
            state.rate = next
            state.lastChange = now
            state.outcomes = []
            return BackoffChange(rate: next)
        } else if let rate = state.rate, settled, state.outcomes.count >= Self.recoveryRun,
            !state.outcomes.suffix(Self.recoveryRun).contains(where: \.bad)
        {
            let next = rate * 2
            state.lastChange = now
            state.outcomes = []
            if next >= state.originalRate {
                state.rate = nil
                return BackoffChange(rate: nil)
            }
            state.rate = next
            return BackoffChange(rate: next)
        }
        return nil
    }
}
