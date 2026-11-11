// GulpWorkspace — the shared limiter's settings (F03 §3.4: HTTP-013 rates, GOV-002/003 concurrency
// budgets, GOV-007 backoff) and the panic stop (F20 GOV-001). Active tools register while they run,
// so the panic stop can pause them all, report what it stopped and resume them together.

import Foundation
import GulpCore
import GulpHTTP

/// Network limits for the project (Settings → Network).
public struct NetworkSettings: SettingsGroup {
    /// Storage key.
    public static let key = "network"
    /// HTTP-013 off, GOV-002/003 conservative budgets, backoff on.
    public static let defaultValue = NetworkSettings()

    /// Requests-per-second caps (every tool; HTTP-013).
    public var rates: ThrottleLimits
    /// Concurrency budgets and backoff (active tools; GOV-002/003/007).
    public var concurrency: ConcurrencyLimits

    /// Settings.
    public init(rates: ThrottleLimits = .none, concurrency: ConcurrencyLimits = ConcurrencyLimits()) {
        self.rates = rates
        self.concurrency = concurrency
    }
}

/// A running active task the panic stop can pause (F20 GOV-001).
public struct ActiveTask: Sendable, Identifiable {
    /// Identity.
    public let id: UUID
    /// `fuzzer`, `crawler`, `discovery`…
    public let kind: String
    /// What the user called it.
    public let name: String
    let pause: @Sendable () async -> Void
    let resume: @Sendable () async -> Void
}

/// The project's running active tasks.
public actor ActiveTasks {
    private var tasks: [UUID: ActiveTask] = [:]
    private var order: [UUID] = []
    /// Whether the panic stop is engaged.
    public private(set) var panicked = false

    /// Register a task; it is paused at once if the panic stop is engaged.
    func add(_ task: ActiveTask) async {
        tasks[task.id] = task
        order.append(task.id)
        if panicked { await task.pause() }
    }

    func remove(_ id: UUID) {
        tasks[id] = nil
        order.removeAll { $0 == id }
    }

    /// The running tasks, oldest first.
    public var all: [ActiveTask] { order.compactMap { tasks[$0] } }

    func pauseAll() async -> [ActiveTask] {
        panicked = true
        let running = all
        for task in running { await task.pause() }
        return running
    }

    func resumeAll() async -> [ActiveTask] {
        panicked = false
        let running = all
        for task in running { await task.resume() }
        return running
    }
}

/// What the panic stop did.
public struct PanicReport: Sendable {
    /// Tasks paused (or resumed), as "kind: name".
    public var tasks: [String]
    /// Requests that were in flight and got cut.
    public var cut: Int
}

extension ProjectSession {
    /// Apply the stored network settings to the engine (on open and after changes).
    public func applyNetworkSettings() async {
        let stored = settings.get(NetworkSettings.self)
        await http.throttle.set(stored.rates)
        await http.resources.set(stored.concurrency)
    }

    /// Store and apply network settings.
    public func setNetworkSettings(_ value: NetworkSettings) async throws {
        try await settings.set(value, scope: .project)
        await applyNetworkSettings()
    }

    /// The panic stop (GOV-001): pause every active task and cut every governed request in flight.
    /// Proxy and Repeater traffic continue; queued store writes still flush.
    @discardableResult
    public func panicStop() async -> PanicReport {
        let cut = await http.resources.pause()
        let stopped = await activeTasks.pauseAll()
        await events.publish(
            .log(
                LogEntry(
                    level: .warning,
                    message: "Panic stop: paused \(stopped.count) task(s), cut \(cut) request(s)",
                    module: "gulp.governor")))
        return PanicReport(tasks: stopped.map { "\($0.kind): \($0.name)" }, cut: cut)
    }

    /// "Resume all" after a panic stop.
    @discardableResult
    public func resumeAll() async -> PanicReport {
        let resumed = await activeTasks.resumeAll()
        await http.resources.resume()
        return PanicReport(tasks: resumed.map { "\($0.kind): \($0.name)" }, cut: 0)
    }

    /// Whether the panic stop is engaged.
    public var isPanicked: Bool {
        get async { await activeTasks.panicked }
    }
}
