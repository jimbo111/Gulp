// GulpStore — what the site map stores (F04 TGT-007): per-node annotations and per-host notes,
// keyed by the node's URL key, plus the per-host exchange read used by "Analyze target" (TGT-008).

import Foundation
import GRDB
import GulpCore

/// A site-map node's annotation (TGT-007). A host node's `notes` are the per-host notes.
public struct SiteMapNote: Sendable, Hashable {
    /// The node's URL key (`SiteMapNode.id`).
    public var nodeKey: String
    /// A comment on the node.
    public var comment: String?
    /// A highlight color.
    public var highlight: Highlight?
    /// Free-form notes (used on host nodes).
    public var notes: String?

    /// A note.
    public init(nodeKey: String, comment: String? = nil, highlight: Highlight? = nil, notes: String? = nil) {
        self.nodeKey = nodeKey
        self.comment = comment
        self.highlight = highlight
        self.notes = notes
    }

    /// Nothing is set.
    public var isEmpty: Bool {
        (comment ?? "").isEmpty && highlight == nil && (notes ?? "").isEmpty
    }
}

extension ProjectStore {
    /// Every site-map annotation, by node key.
    public func siteMapNotes() async throws -> [String: SiteMapNote] {
        try await pool.read { db in
            let rows = try Row.fetchAll(
                db, sql: "SELECT node_key, comment, highlight, notes FROM site_map_notes")
            var result: [String: SiteMapNote] = [:]
            for row in rows {
                let key: String = row["node_key"]
                result[key] = SiteMapNote(
                    nodeKey: key, comment: row["comment"],
                    highlight: (row["highlight"] as String?).flatMap(Highlight.init(rawValue:)),
                    notes: row["notes"])
            }
            return result
        }
    }

    /// Store `note` (an empty note deletes the row).
    public func setSiteMapNote(_ note: SiteMapNote) async throws {
        try await pool.write { db in
            if note.isEmpty {
                try db.execute(
                    sql: "DELETE FROM site_map_notes WHERE node_key = ?", arguments: [note.nodeKey])
            } else {
                try db.execute(
                    sql: """
                        INSERT OR REPLACE INTO site_map_notes (node_key, comment, highlight, notes) \
                        VALUES (?, ?, ?, ?)
                        """,
                    arguments: [note.nodeKey, note.comment, note.highlight?.rawValue, note.notes])
            }
        }
    }

    /// Up to `limit` of the newest exchanges sent to `target`'s host, port and scheme (bytes included),
    /// oldest first.
    public func exchanges(to target: HTTPTarget, limit: Int = 5_000) async throws -> [Exchange] {
        await writer.flush()
        return try await pool.read { db in
            let ids = try ExchangeID.fetchAll(
                db,
                sql: """
                    SELECT id FROM exchanges WHERE host = ? COLLATE NOCASE AND port = ? AND scheme = ? \
                    ORDER BY id DESC LIMIT ?
                    """,
                arguments: [target.host, target.port, target.scheme.rawValue, limit])
            return try ids.reversed().compactMap { try ExchangeRows.load($0, from: db) }
        }
    }

    /// History rows for `ids` (the endpoints table of a selected site-map node, TGT-002), in id order;
    /// missing ids are skipped.
    public func summaries(ids: [ExchangeID]) async throws -> [ExchangeSummary] {
        try await pool.read { db in
            var rows: [ExchangeSummary] = []
            for start in stride(from: 0, to: ids.count, by: 500) {
                let chunk = Array(ids[start..<min(start + 500, ids.count)])
                let marks = Array(repeating: "?", count: chunk.count).joined(separator: ", ")
                rows += try Row.fetchAll(
                    db,
                    sql:
                        "SELECT \(ExchangeRows.summaryColumns) FROM exchanges WHERE id IN (\(marks)) ORDER BY id",
                    arguments: StatementArguments(chunk)
                ).map(ExchangeRows.summary)
            }
            return rows.sorted { $0.id < $1.id }
        }
    }
}
