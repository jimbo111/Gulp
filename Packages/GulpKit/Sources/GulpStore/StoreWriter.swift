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
    private var pending: [Exchange] = []
    private var timer: Task<Void, Never>?
    private var tail: Task<Void, Never>?

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
        pending.append(queued)
        if durable {
            await flush()
        } else if pending.count >= Self.maxBatch {
            startFlush()
        } else if timer == nil {
            timer = Task {
                try? await Task.sleep(for: Self.flushInterval)
                await self.timerFired()
            }
        }
        return id
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

    private func write(_ batch: [Exchange]) async {
        do {
            try await pool.write { db in
                for exchange in batch { try ExchangeRows.insert(exchange, in: db) }
            }
            if let eventBus {
                for exchange in batch {
                    await eventBus.publish(.exchangeRecorded(exchange.id, source: exchange.source))
                }
            }
        } catch {
            let message = "Could not save \(batch.count) exchange(s): \(error)"
            await eventBus?.publish(.log(LogEntry(level: .error, message: message, module: "gulp.store")))
        }
    }
}
