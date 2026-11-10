// GulpStore — the ordered id lists of GulpQL queries with an in-memory residual, cached so a table
// can page through them (HIS-002 + HIS-024) without re-running the scan for every page. Any commit
// to the project invalidates them: a transaction observer on the pool's single writer connection
// bumps a counter that is part of the key.

import Foundation
import GRDB
import GulpCore

/// Counts committed write transactions.
// @unchecked Sendable: `value` is only touched under `lock`; GRDB calls the observer methods on the
// writer's serial queue, readers call `current` from any thread.
final class CommitCounter: TransactionObserver, @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    var current: Int { lock.withLock { value } }

    func observes(eventsOfKind eventKind: DatabaseEventKind) -> Bool { false }
    func databaseDidChange(with event: DatabaseEvent) {}
    func databaseDidCommit(_ db: Database) { lock.withLock { value += 1 } }
    func databaseDidRollback(_ db: Database) {}
}

/// A few recent residual-query results.
// @unchecked Sendable: `entries` is only touched under `lock`.
final class ResultCache: @unchecked Sendable {
    struct Key: Hashable {
        var filter: HistoryFilter
        var sort: HistorySort
        var version: Int
    }

    private let lock = NSLock()
    private var entries: [(Key, [ExchangeID])] = []

    func get(_ key: Key) -> [ExchangeID]? {
        lock.withLock { entries.first { $0.0 == key }?.1 }
    }

    func put(_ key: Key, _ ids: [ExchangeID]) {
        lock.withLock {
            entries.removeAll { $0.0 == key || $0.0.version != key.version }
            entries.append((key, ids))
            if entries.count > 4 { entries.removeFirst() }
        }
    }
}
