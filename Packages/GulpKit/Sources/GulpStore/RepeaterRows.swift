// GulpStore — Repeater tabs and their send history (F06 REP-004/REP-005; doc 04 §4 `repeater_tabs`,
// `repeater_history`). Row-level only: the tab's target and options are JSON chosen by the caller
// (GulpWorkspace), so this module stays independent of GulpRepeater.

import Foundation
import GRDB
import GulpCore

/// A stored Repeater tab.
public struct RepeaterTabRow: Sendable, Hashable {
    /// Row id (0 = not stored yet).
    public var id: Int64
    /// Tab title.
    public var title: String
    /// Group id (REP-010).
    public var groupID: Int64?
    /// Tab-bar position.
    public var ordinal: Int
    /// The target, as JSON.
    public var targetJSON: String
    /// The send options, as JSON.
    public var optionsJSON: String
    /// The draft request bytes.
    public var draft: [UInt8]

    /// A row.
    public init(
        id: Int64, title: String, groupID: Int64?, ordinal: Int, targetJSON: String, optionsJSON: String,
        draft: [UInt8]
    ) {
        self.id = id
        self.title = title
        self.groupID = groupID
        self.ordinal = ordinal
        self.targetJSON = targetJSON
        self.optionsJSON = optionsJSON
        self.draft = draft
    }
}

extension ProjectStore {
    /// All Repeater tabs in tab-bar order.
    public func repeaterTabs() async throws -> [RepeaterTabRow] {
        try await pool.read { db in
            let rows = try Row.fetchAll(db, sql: "SELECT * FROM repeater_tabs ORDER BY ordinal, id")
            return try rows.map { row in
                let blob: Int64? = row["draft_blob"]
                return RepeaterTabRow(
                    id: row["id"], title: row["title"] ?? "", groupID: row["group_id"],
                    ordinal: row["ordinal"] ?? 0,
                    targetJSON: row["target_json"] ?? "{}", optionsJSON: row["options_json"] ?? "{}",
                    draft: try blob.flatMap { try BlobStore.load($0, from: db) } ?? [])
            }
        }
    }

    /// Insert (`id == 0`) or update a tab; returns its id.
    public func saveRepeaterTab(_ tab: RepeaterTabRow) async throws -> Int64 {
        try await pool.write { db in
            let blob = try BlobStore.store(tab.draft, in: db)
            let arguments: StatementArguments = [
                tab.title, tab.groupID, tab.ordinal, tab.targetJSON, tab.optionsJSON, blob,
            ]
            if tab.id != 0,
                try Int.fetchOne(
                    db, sql: "SELECT 1 FROM repeater_tabs WHERE id = ?", arguments: [tab.id]) != nil
            {
                try db.execute(
                    sql: """
                        UPDATE repeater_tabs SET title = ?, group_id = ?, ordinal = ?, target_json = ?, \
                        options_json = ?, draft_blob = ? WHERE id = ?
                        """,
                    arguments: arguments + [tab.id])
                return tab.id
            }
            try db.execute(
                sql: """
                    INSERT INTO repeater_tabs (title, group_id, ordinal, target_json, options_json, \
                    draft_blob) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                arguments: arguments)
            return db.lastInsertedRowID
        }
    }

    /// Delete a tab and its history rows (the exchanges stay in the project).
    public func deleteRepeaterTab(_ id: Int64) async throws {
        try await pool.write { db in
            try db.execute(sql: "DELETE FROM repeater_history WHERE tab_id = ?", arguments: [id])
            try db.execute(sql: "DELETE FROM repeater_tabs WHERE id = ?", arguments: [id])
        }
    }

    /// The exchanges sent from a tab, oldest first.
    public func repeaterHistory(tab: Int64) async throws -> [ExchangeID] {
        try await pool.read { db in
            try ExchangeID.fetchAll(
                db, sql: "SELECT exchange_id FROM repeater_history WHERE tab_id = ? ORDER BY ordinal, id",
                arguments: [tab])
        }
    }

    /// Append a send to a tab's history.
    public func appendRepeaterHistory(tab: Int64, exchange: ExchangeID) async throws {
        // The exchange id is handed out before its row is written (coalesced writes): flush first
        // so the foreign key finds it.
        await writer.flush()
        try await pool.write { db in
            let next =
                try Int.fetchOne(
                    db, sql: "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM repeater_history WHERE tab_id = ?",
                    arguments: [tab]) ?? 0
            try db.execute(
                sql: "INSERT INTO repeater_history (tab_id, exchange_id, ordinal) VALUES (?, ?, ?)",
                arguments: [tab, exchange, next])
        }
    }
}

extension ProjectStore {
    /// All Repeater groups (REP-010): id, name, color, send mode.
    public func repeaterGroups() async throws -> [(id: Int64, name: String, color: String, mode: String)] {
        try await pool.read { db in
            try Row.fetchAll(db, sql: "SELECT * FROM repeater_groups ORDER BY id").map { row in
                (row["id"], row["name"] ?? "", row["color"] ?? "", row["send_mode"] ?? "")
            }
        }
    }

    /// Insert (`id == 0`) or update a group; returns its id.
    public func saveRepeaterGroup(id: Int64, name: String, color: String, mode: String) async throws -> Int64
    {
        try await pool.write { db in
            if id != 0,
                try Int.fetchOne(db, sql: "SELECT 1 FROM repeater_groups WHERE id = ?", arguments: [id])
                    != nil
            {
                try db.execute(
                    sql: "UPDATE repeater_groups SET name = ?, color = ?, send_mode = ? WHERE id = ?",
                    arguments: [name, color, mode, id])
                return id
            }
            try db.execute(
                sql: "INSERT INTO repeater_groups (name, color, send_mode) VALUES (?, ?, ?)",
                arguments: [name, color, mode])
            return db.lastInsertedRowID
        }
    }

    /// Delete a group; tabs that pointed at it become ungrouped.
    public func deleteRepeaterGroup(_ id: Int64) async throws {
        try await pool.write { db in
            try db.execute(
                sql: "UPDATE repeater_tabs SET group_id = NULL WHERE group_id = ?", arguments: [id])
            try db.execute(sql: "DELETE FROM repeater_groups WHERE id = ?", arguments: [id])
        }
    }
}
