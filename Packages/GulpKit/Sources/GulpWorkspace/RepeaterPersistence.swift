// GulpWorkspace — Repeater tabs stored in the project (F06 REP-004/REP-005): `RepeaterPersistence`
// on top of GulpStore's repeater rows, following Save As like the recorder does.

import Foundation
import GulpCore
import GulpRepeater
import GulpStore

/// The project file a session currently writes to (Save As switches it).
actor CurrentStore {
    private(set) var store: ProjectStore

    init(_ store: ProjectStore) {
        self.store = store
    }

    func set(_ store: ProjectStore) {
        self.store = store
    }
}

/// Stores Repeater tabs in the session's current project file.
final class StoreRepeaterPersistence: RepeaterPersistence {
    private let current: CurrentStore

    init(_ current: CurrentStore) {
        self.current = current
    }

    private var store: ProjectStore {
        get async { await current.store }
    }

    func loadTabs() async throws -> [RepeaterTab] {
        let decoder = JSONDecoder()
        return try await store.repeaterTabs().compactMap { row in
            guard let target = try? decoder.decode(HTTPTarget.self, from: Data(row.targetJSON.utf8)) else {
                return nil
            }
            let options = (try? decoder.decode(RepeaterOptions.self, from: Data(row.optionsJSON.utf8)))
            return RepeaterTab(
                id: row.id, title: row.title, groupID: row.groupID, ordinal: row.ordinal, target: target,
                options: options ?? RepeaterOptions(), draft: row.draft)
        }
    }

    func saveTab(_ tab: RepeaterTab) async throws -> Int64 {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let row = RepeaterTabRow(
            id: tab.id, title: tab.title, groupID: tab.groupID, ordinal: tab.ordinal,
            targetJSON: String(decoding: try encoder.encode(tab.target), as: UTF8.self),
            optionsJSON: String(decoding: try encoder.encode(tab.options), as: UTF8.self), draft: tab.draft)
        return try await store.saveRepeaterTab(row)
    }

    func deleteTab(_ id: Int64) async throws {
        try await store.deleteRepeaterTab(id)
    }

    func history(of tab: Int64) async throws -> [ExchangeID] {
        try await store.repeaterHistory(tab: tab)
    }

    func appendHistory(tab: Int64, exchange: ExchangeID) async throws {
        try await store.appendRepeaterHistory(tab: tab, exchange: exchange)
    }

    func exchange(_ id: ExchangeID) async throws -> Exchange? {
        try await store.exchange(id: id)
    }
}
