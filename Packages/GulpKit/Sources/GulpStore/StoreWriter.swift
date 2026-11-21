// GulpStore — the write coalescer (doc 04 §4 "Notes", PRJ-003). Exchanges get their id at once from
// an in-memory counter, so callers (the proxy) never wait on SQLite; rows are written in one
// transaction every 50 ms or 500 items, and `exchangeRecorded` is published after they are durable.

import GRDB
import GulpCore

/// Batches exchange inserts. A crash loses at most the last ~50 ms of traffic (or nothing in durable
/// mode, which flushes every write).
public actor StoreWriter {
    /// Flush at least this often while writes are pending.
    public static let flushInterval: Duration = .milliseconds(50)
    /// Flush as soon as this many writes are pending.
    public static let maxBatch = 500

    private let pool: DatabasePool
    private let eventBus: EventBus?
    private let durable: Bool
    private var nextID: ExchangeID
    /// Queued writes; `replace` marks an update of an exchange recorded earlier (HIS-007).
    private var pending: [(exchange: Exchange, replace: Bool)] = []
    private var timer: Task<Void, Never>?
    private var tail: Task<Void, Never>?
    /// Decides each row's `in_scope` as it is written (F04 TGT-022).
    private var scope = ScopeService()

    init(pool: DatabasePool, nextID: ExchangeID, eventBus: EventBus?, durable: Bool) {
        self.pool = pool
        self.nextID = nextID
        self.eventBus = eventBus
        self.durable = durable
    }

    /// Assign the exchange its id and queue it. Returns at once (after the write in durable mode).
    public func record(_ exchange: Exchange) async -> ExchangeID {
        var queued = exchange
        let id = nextID
        nextID += 1
        queued.id = id
        pending.append((queued, false))
        scheduleFlush()
        if durable { await tail?.value }
        return id
    }

    /// Take `count` consecutive ids for rows written outside the queue (the synthetic-data seeder),
    /// so later recordings can't collide with them.
    func reserveIDs(_ count: Int) async -> Range<ExchangeID> {
        await flush()
        let first = nextID
        nextID += ExchangeID(max(0, count))
        return first..<nextID
    }

    /// Rewrite an exchange recorded earlier (same id) in place — a streaming response that has
    /// finished (HIS-007). The highlight, comment and tags the user gave the row meanwhile are kept
    /// (`exchange.annotation` is ignored). Published as `exchangeUpdated`.
    public func update(_ exchange: Exchange) async {
        pending.append((exchange, true))
        scheduleFlush()
        if durable { await tail?.value }
    }

    private func scheduleFlush() {
        if durable || pending.count >= Self.maxBatch {
            startFlush()
        } else if timer == nil {
            timer = Task {
                try? await Task.sleep(for: Self.flushInterval)
                await self.timerFired()
            }
        }
    }

    /// Rows written from now on get `in_scope` from `scope` (existing rows: `ProjectStore.setScope`).
    public func setScope(_ scope: ScopeService) {
        self.scope = scope
    }

    /// Write everything queued so far and wait until it is on disk.
    public func flush() async {
        startFlush()
        await tail?.value
    }

    private func timerFired() {
        timer = nil
        startFlush()
    }

    /// Hand the pending batch to a write task that runs after any write already in progress.
    private func startFlush() {
        timer?.cancel()
        timer = nil
        guard !pending.isEmpty else { return }
        let batch = pending
        pending = []
        let previous = tail
        tail = Task {
            await previous?.value
            await self.write(batch)
        }
    }

    private func write(_ batch: [(exchange: Exchange, replace: Bool)]) async {
        let scope = self.scope
        do {
            try await pool.write { db in
                for (exchange, replace) in batch {
                    let inScope = scope.isInScope(exchange.target, path: ScopePath.of(exchange))
                    if replace {
                        try ExchangeRows.update(exchange, inScope: inScope, in: db)
                    } else {
                        try ExchangeRows.insert(exchange, inScope: inScope, in: db)
                    }
                }
            }
            if let eventBus {
                for (exchange, replace) in batch {
                    let event: GulpEvent =
                        replace
                        ? .exchangeUpdated(exchange.id)
                        : .exchangeRecorded(exchange.id, source: exchange.source)
                    await eventBus.publish(event)
                }
            }
        } catch {
            let message = "Could not save \(batch.count) exchange(s): \(error)"
            await eventBus?.publish(.log(LogEntry(level: .error, message: message, module: "gulp.store")))
        }
    }
}
