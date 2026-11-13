// GulpWorkspace — live passive scanning (F08 §4): a background consumer that runs the passive checks
// on newly recorded traffic and records the findings as issues (deduplicated by the store). It reads
// from the store in id order from a persisted cursor, so events only nudge it: if it falls behind,
// it simply reads more next time (backpressure for free), and nothing recorded while the project was
// closed is missed. Streaming rows still in progress are skipped and scanned when they complete.

import Foundation
import GulpCore
import GulpQuery
import GulpScanner
import GulpStore

/// Passive-scan settings (F08 §4), stored with the project.
public struct PassiveScanConfig: SettingsGroup, Hashable {
    /// Storage key.
    public static let key = "scanner.passive"
    /// On, proxy traffic, in scope.
    public static let defaultValue = PassiveScanConfig()

    /// Scan at all.
    public var enabled = true
    /// Also scan out-of-scope traffic (default: in scope only; an empty scope counts as everything).
    public var allTraffic = false
    /// Tools whose traffic is scanned besides the proxy (`repeater`, `fuzzer`…).
    public var extraTools: [String] = []
    /// Issue types not to report.
    public var disabledChecks: [String] = []
    /// Run the secret & JS-endpoint recon checks (F27; off by default).
    public var recon = false

    /// Defaults.
    public init() {}

    /// The tools scanned (the proxy always).
    public var tools: [String] { Array(Set(["proxy"] + extraTools)).sorted() }
}

/// The live passive scanner of one project.
public actor PassiveScanService {
    private let storeProvider: @Sendable () async -> ProjectStore
    private let configProvider: @Sendable () -> PassiveScanConfig
    private let scopeIsEmpty: @Sendable () async -> Bool
    private let events: EventBus
    /// The last exchange id examined (persisted in `meta`), or nil until loaded.
    private var cursor: ExchangeID?
    private var wanted = false
    private var updated: Set<ExchangeID> = []
    private var worker: Task<Void, Never>?
    /// Exchanges scanned since the project opened.
    public private(set) var scanned = 0
    /// New issues found since the project opened.
    public private(set) var newIssues = 0

    static let cursorKey = "passive_scan_last_id"

    init(
        store: @escaping @Sendable () async -> ProjectStore,
        config: @escaping @Sendable () -> PassiveScanConfig,
        scopeIsEmpty: @escaping @Sendable () async -> Bool, events: EventBus
    ) {
        storeProvider = store
        configProvider = config
        self.scopeIsEmpty = scopeIsEmpty
        self.events = events
    }

    /// Scan whatever was recorded since the last scan (coalesced; returns at once).
    public func nudge() {
        wanted = true
        startWorker()
    }

    /// Scan a completed (formerly streaming) exchange.
    public func exchangeUpdated(_ id: ExchangeID) {
        updated.insert(id)
        startWorker()
    }

    /// Scan everything recorded so far, then return (used on close and by the CLI).
    public func drain() async {
        wanted = true
        startWorker()
        while let running = worker { await running.value }
    }

    /// Forget the cursor so the whole history is scanned again ("Scan history").
    public func rescanAll() async throws {
        cursor = 0
        try await storeProvider().setMeta(Self.cursorKey, "0")
        nudge()
    }

    private func startWorker() {
        guard worker == nil else { return }
        worker = Task {
            await self.work()
            self.workerDone()
        }
    }

    private func workerDone() {
        worker = nil
        if wanted || !updated.isEmpty { startWorker() }
    }

    private func work() async {
        while wanted || !updated.isEmpty {
            let pendingUpdates = updated
            updated = []
            let catchUp = wanted
            wanted = false
            do {
                if catchUp { try await scanNew() }
                for id in pendingUpdates.sorted() { try await scan(ids: [id], respectingCursor: false) }
            } catch {
                await events.publish(
                    .log(LogEntry(level: .warning, message: "Passive scan: \(error)", module: "gulp.scanner"))
                )
            }
        }
    }

    /// The filter selecting what this configuration scans.
    func filter(after: ExchangeID, upTo newest: ExchangeID, _ config: PassiveScanConfig) async
        -> HistoryFilter
    {
        var filter = HistoryFilter()
        var expression: GulpQLExpression = .and(
            .compare(GulpQLField("id"), .greater, .number(Double(after))),
            .compare(GulpQLField("id"), .lessOrEqual, .number(Double(newest))))
        expression = .and(
            expression, .compare(GulpQLField("source"), .in, .list(config.tools.map { .string($0) })))
        if !config.allTraffic, await !scopeIsEmpty() {
            expression = .and(expression, .test(GulpQLField("in_scope")))
        }
        filter.query = expression
        return filter
    }

    private func scanNew() async throws {
        let config = configProvider()
        guard config.enabled else { return }
        let store = await storeProvider()
        if cursor == nil { cursor = Int64(try await store.meta(Self.cursorKey) ?? "") ?? 0 }
        let newest = try await store.newestExchangeID()
        var position = cursor ?? 0
        while position < newest {
            let batch = try await store.exchangeIDs(
                filter: await filter(after: position, upTo: newest, config), limit: 200)
            if batch.isEmpty {
                position = newest
            } else {
                try await scan(ids: batch, respectingCursor: true)
                position = batch.last ?? newest
            }
            cursor = position
            try await store.setMeta(Self.cursorKey, String(position))
        }
    }

    private func scan(ids: [ExchangeID], respectingCursor: Bool) async throws {
        let config = configProvider()
        guard config.enabled else { return }
        let store = await storeProvider()
        let scanner = PassiveScanner(settings: settings(config))
        for exchange in try await store.exchanges(ids: ids) {
            // A streaming response still arriving: scanned when its update lands.
            if case .pending = exchange.state, respectingCursor { continue }
            if !respectingCursor {
                // An update: only for the tools and scope this configuration scans.
                let selected = try await store.exchangeIDs(
                    filter: await filter(after: exchange.id - 1, upTo: exchange.id, config), limit: 1)
                guard selected == [exchange.id] else { continue }
            }
            scanned += 1
            for finding in scanner.scan(exchange) {
                let result = try await store.record(finding)
                if result.isNew {
                    newIssues += 1
                    await events.publish(.issueFound(result.id))
                }
            }
        }
    }

    func settings(_ config: PassiveScanConfig) -> PassiveScanSettings {
        var settings = PassiveScanSettings()
        settings.disabled = Set(config.disabledChecks)
        settings.recon = config.recon
        return settings
    }
}

extension ProjectSession {
    /// Start the live passive scanner (on open).
    func startPassiveScan() {
        let scanner = passiveScan
        let events = self.events
        let task = Task {
            let deliveries = await events.subscribe()
            await scanner.nudge()  // whatever arrived while the project was closed
            for await delivery in deliveries {
                if Task.isCancelled { break }
                switch delivery.event {
                case .exchangeRecorded, nil: await scanner.nudge()
                case .exchangeUpdated(let id): await scanner.exchangeUpdated(id)
                default: break
                }
            }
        }
        backgroundTasks.append(task)
    }

    /// The passive-scan settings.
    public func passiveScanConfig() -> PassiveScanConfig { settings.get(PassiveScanConfig.self) }

    /// Change the passive-scan settings (applies to traffic from now on; `rescanAll` for history).
    public func setPassiveScanConfig(_ value: PassiveScanConfig) async throws {
        try await settings.set(value, scope: .project)
        await passiveScan.nudge()
    }
}
