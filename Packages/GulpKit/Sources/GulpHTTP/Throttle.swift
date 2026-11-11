// GulpHTTP — the shared request throttle (F03 HTTP-013): a global and a per-host requests-per-second
// cap that every tool's sends pass through, so the user can protect fragile targets. Extended in
// M11a with concurrency budgets and adaptive backoff (F03 §3.4, GOV-002/003).
//
// Each limit is a schedule rather than a token count: a request is given the earliest time at or
// after now that both its host's and the global schedule allow, and that slot is reserved before
// it waits, so concurrent senders queue fairly and nobody exceeds the rate.

import Foundation

/// Requests-per-second caps (0 = unlimited).
public struct ThrottleLimits: Sendable, Codable, Hashable {
    /// Across all hosts.
    public var globalPerSecond: Double
    /// For each host without its own entry in `hosts`.
    public var perHostPerSecond: Double
    /// Per-host overrides (lowercased host names).
    public var hosts: [String: Double]

    /// Limits (none by default).
    public init(globalPerSecond: Double = 0, perHostPerSecond: Double = 0, hosts: [String: Double] = [:]) {
        self.globalPerSecond = globalPerSecond
        self.perHostPerSecond = perHostPerSecond
        self.hosts = hosts
    }

    /// No limits.
    public static let none = ThrottleLimits()
}

/// The engine's throttle; shared by every tool that sends through the engine.
public actor Throttle {
    private var limits: ThrottleLimits
    private var nextGlobal: ContinuousClock.Instant?
    private var nextByHost: [String: ContinuousClock.Instant] = [:]
    /// Adaptive backoff rates (GOV-007) set by the `ResourcePool`; they cap active tools only.
    private var backoff: [String: Double] = [:]
    private var nextBackoff: [String: ContinuousClock.Instant] = [:]

    /// A throttle with `limits`.
    public init(_ limits: ThrottleLimits = .none) {
        self.limits = limits
    }

    /// Change the limits; requests already waiting keep their reserved slots.
    public func set(_ limits: ThrottleLimits) {
        self.limits = limits
        if limits.globalPerSecond <= 0 { nextGlobal = nil }
        if limits.perHostPerSecond <= 0 && limits.hosts.isEmpty { nextByHost = [:] }
    }

    /// The current limits.
    public var current: ThrottleLimits { limits }

    /// Wait until a request to `host` may be sent (returns at once when nothing limits it).
    /// `governed` sends (active tools) are also held to the host's adaptive backoff rate.
    public func acquire(host: String, governed: Bool = false) async {
        let delay = reserve(host: host.lowercased(), now: .now, governed: governed)
        if delay > .zero { try? await Task.sleep(for: delay) }
    }

    /// Set (or clear, with nil) the adaptive backoff rate for `host` (GOV-007).
    public func setBackoff(_ host: String, rate: Double?) {
        let host = host.lowercased()
        if let rate, rate > 0 {
            backoff[host] = rate
        } else {
            backoff[host] = nil
            nextBackoff[host] = nil
        }
    }

    /// Hosts currently held to a backoff rate (requests per second).
    public var backoffRates: [String: Double] { backoff }

    /// Reserve the next slot for `host`; returns how long to wait for it.
    func reserve(host: String, now: ContinuousClock.Instant, governed: Bool = false) -> Duration {
        let hostRate = limits.hosts[host] ?? limits.perHostPerSecond
        let globalRate = limits.globalPerSecond
        let backoffRate = governed ? backoff[host] ?? 0 : 0
        guard hostRate > 0 || globalRate > 0 || backoffRate > 0 else { return .zero }
        var slot = now
        if globalRate > 0, let next = nextGlobal, next > slot { slot = next }
        if hostRate > 0, let next = nextByHost[host], next > slot { slot = next }
        if backoffRate > 0, let next = nextBackoff[host], next > slot { slot = next }
        if globalRate > 0 { nextGlobal = slot + .seconds(1 / globalRate) }
        if hostRate > 0 { nextByHost[host] = slot + .seconds(1 / hostRate) }
        if backoffRate > 0 { nextBackoff[host] = slot + .seconds(1 / backoffRate) }
        return slot - now
    }
}
