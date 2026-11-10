// GulpStore — Notebook items (F14 NB-001…NB-004; doc 04 §4 `notebook_items`). An item saved from an
// exchange keeps a snapshot of the request/response in blobs (not just the exchange id), so later
// traffic, edits or deleting the exchange can't change or orphan it; the id stays as an optional
// back-reference (the foreign key nulls it when the exchange is deleted).

import Foundation
import GRDB
import GulpCore

/// A Notebook item's triage state (NB-001).
public enum NotebookStatus: String, Sendable, Hashable, Codable, CaseIterable {
    /// Not looked at yet.
    case todo
    /// Being looked at.
    case investigating
    /// A real finding.
    case confirmed
    /// Checked; not a problem.
    case notAnIssue = "not-an-issue"
    /// Reported to the client.
    case reported

    /// The label shown in the UI.
    public var title: String {
        switch self {
        case .todo: "To do"
        case .investigating: "Investigating"
        case .confirmed: "Confirmed"
        case .notAnIssue: "Not an issue"
        case .reported: "Reported"
        }
    }
}

/// One Notebook item: a saved exchange or a free-form note (NB-001, NB-003).
public struct NotebookItem: Sendable, Hashable, Identifiable {
    /// What an item holds.
    public enum Kind: String, Sendable, Hashable, Codable {
        /// A snapshot of a request/response.
        case exchange
        /// A free-form note.
        case note
    }

    /// Row id.
    public var id: Int64
    /// Exchange snapshot or note.
    public var kind: Kind
    /// The exchange it was saved from, while that exchange exists.
    public var exchangeID: ExchangeID?
    /// Where the saved request goes.
    public var target: HTTPTarget?
    /// The saved request bytes.
    public var request: [UInt8]?
    /// The saved response bytes (wire form).
    public var response: [UInt8]?
    /// The snapshot was cut at `NotebookItem.snapshotLimit` (F14 §5).
    public var truncated: Bool
    /// Title.
    public var title: String
    /// Triage status.
    public var status: NotebookStatus
    /// The note (markdown source).
    public var note: String
    /// Tags.
    public var tags: [String]
    /// Highlight color.
    public var highlight: Highlight?
    /// Created.
    public var createdAt: Date
    /// Last changed.
    public var updatedAt: Date
    /// Position in the list (NB-002 reorder).
    public var ordinal: Int

    /// Snapshots are capped at this many bytes per message (like the engine's response cap).
    public static let snapshotLimit = 50 * 1024 * 1024

    /// `host/path` of the saved request (for the list), or nil for notes.
    public var location: String? {
        guard let target, let request else { return nil }
        let derived = DerivedFields(target: target, request: RawRequest(Bytes(request)), response: nil)
        let query = derived.query.map { "?" + $0 } ?? ""
        return derived.host + (derived.path ?? "/") + query
    }
}

/// The editable fields of an item.
public struct NotebookEdit: Sendable, Hashable {
    /// New title.
    public var title: String?
    /// New status.
    public var status: NotebookStatus?
    /// New note.
    public var note: String?
    /// New tags.
    public var tags: [String]?
    /// New highlight (`.some(nil)` clears it).
    public var highlight: Highlight??

    /// No changes.
    public init(
        title: String? = nil, status: NotebookStatus? = nil, note: String? = nil, tags: [String]? = nil,
        highlight: Highlight?? = nil
    ) {
        self.title = title
        self.status = status
        self.note = note
        self.tags = tags
        self.highlight = highlight
    }
}

extension ProjectStore {
    /// Save an exchange to the Notebook as a snapshot (NB-001). Nil if the exchange doesn't exist.
    public func addNotebookItem(
        exchange id: ExchangeID, title: String? = nil, note: String = "", status: NotebookStatus = .todo,
        tags: [String] = []
    ) async throws -> NotebookItem? {
        await writer.flush()
        guard let exchange = try await self.exchange(id: id) else { return nil }
        let request = exchange.request.bytes.rawBytes
        let response = exchange.response?.wireBytes.rawBytes
        let derived = exchange.derived
        let defaultTitle = "\(derived.method ?? "?") \(derived.host)\(derived.path ?? "/")"
        return try await insertNotebookItem(
            kind: .exchange, exchangeID: id, target: exchange.target, request: request, response: response,
            title: title ?? defaultTitle, note: note, status: status, tags: tags)
    }

    /// A free-form note (NB-003).
    public func addNotebookNote(title: String, note: String = "", tags: [String] = []) async throws
        -> NotebookItem
    {
        try await insertNotebookItem(
            kind: .note, exchangeID: nil, target: nil, request: nil, response: nil, title: title, note: note,
            status: .todo, tags: tags)!
    }

    func insertNotebookItem(
        kind: NotebookItem.Kind, exchangeID: ExchangeID?, target: HTTPTarget?, request: [UInt8]?,
        response: [UInt8]?, title: String, note: String, status: NotebookStatus, tags: [String]
    ) async throws -> NotebookItem? {
        let limit = NotebookItem.snapshotLimit
        let truncated = (request?.count ?? 0) > limit || (response?.count ?? 0) > limit
        let now = Date().timeIntervalSince1970
        let targetJSON = try target.map { String(decoding: try JSONEncoder().encode($0), as: UTF8.self) }
        let tagJSON = String(decoding: try JSONEncoder().encode(tags), as: UTF8.self)
        let id = try await pool.write { db -> Int64 in
            let requestBlob = try request.map { try BlobStore.store(Array($0.prefix(limit)), in: db) }
            let responseBlob = try response.map { try BlobStore.store(Array($0.prefix(limit)), in: db) }
            let ordinal =
                try Int.fetchOne(db, sql: "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM notebook_items") ?? 0
            try db.execute(
                sql: """
                    INSERT INTO notebook_items (kind, exchange_id, request_blob, response_blob, target_json, \
                    title, status, body_md, tags, highlight, created_at, updated_at, ordinal, truncated) \
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)
                    """,
                arguments: [
                    kind.rawValue, exchangeID, requestBlob, responseBlob, targetJSON, title, status.rawValue,
                    note,
                    tagJSON, now, now, ordinal, truncated,
                ])
            return db.lastInsertedRowID
        }
        return try await notebookItem(id)
    }

    /// One item.
    public func notebookItem(_ id: Int64) async throws -> NotebookItem? {
        try await pool.read { db in
            try Row.fetchOne(db, sql: "SELECT * FROM notebook_items WHERE id = ?", arguments: [id])
                .map { try Self.notebookItem($0, db) }
        }
    }

    /// Every item, in list order (NB-002).
    public func notebookItems() async throws -> [NotebookItem] {
        try await pool.read { db in
            try Row.fetchAll(db, sql: "SELECT * FROM notebook_items ORDER BY ordinal, id").map {
                try Self.notebookItem($0, db)
            }
        }
    }

    /// Change an item's title, status, note, tags or highlight.
    public func updateNotebookItem(_ id: Int64, _ edit: NotebookEdit) async throws {
        var sets: [String] = []
        var arguments: [(any DatabaseValueConvertible)?] = []
        if let title = edit.title {
            sets.append("title = ?")
            arguments.append(title)
        }
        if let status = edit.status {
            sets.append("status = ?")
            arguments.append(status.rawValue)
        }
        if let note = edit.note {
            sets.append("body_md = ?")
            arguments.append(note)
        }
        if let tags = edit.tags {
            sets.append("tags = ?")
            arguments.append(String(decoding: try JSONEncoder().encode(tags), as: UTF8.self))
        }
        if let highlight = edit.highlight {
            sets.append("highlight = ?")
            arguments.append(highlight?.rawValue)
        }
        guard !sets.isEmpty else { return }
        sets.append("updated_at = ?")
        arguments.append(Date().timeIntervalSince1970)
        arguments.append(id)
        let sql = "UPDATE notebook_items SET \(sets.joined(separator: ", ")) WHERE id = ?"
        let values = arguments.map { $0?.databaseValue ?? .null }  // Sendable for the write closure
        try await pool.write { db in try db.execute(sql: sql, arguments: StatementArguments(values)) }
    }

    /// Delete items (NB-002). Their blobs are reclaimed by Compact.
    public func deleteNotebookItems(_ ids: [Int64]) async throws {
        try await pool.write { db in
            for id in ids { try db.execute(sql: "DELETE FROM notebook_items WHERE id = ?", arguments: [id]) }
        }
    }

    /// Put the items in this order (NB-002 drag reorder); items not listed keep their relative order
    /// after the listed ones.
    public func reorderNotebook(_ ids: [Int64]) async throws {
        try await pool.write { db in
            let all = try Int64.fetchAll(db, sql: "SELECT id FROM notebook_items ORDER BY ordinal, id")
            let listed = Set(ids)
            let order = ids.filter { all.contains($0) } + all.filter { !listed.contains($0) }
            for (ordinal, id) in order.enumerated() {
                try db.execute(
                    sql: "UPDATE notebook_items SET ordinal = ? WHERE id = ?", arguments: [ordinal, id])
            }
        }
    }

    static func notebookItem(_ row: Row, _ db: Database) throws -> NotebookItem {
        let targetJSON: String? = row["target_json"]
        let tagJSON: String? = row["tags"]
        let requestBlob: Int64? = row["request_blob"]
        let responseBlob: Int64? = row["response_blob"]
        let highlight: String? = row["highlight"]
        return NotebookItem(
            id: row["id"], kind: NotebookItem.Kind(rawValue: row["kind"] ?? "") ?? .note,
            exchangeID: row["exchange_id"],
            target: targetJSON.flatMap { try? JSONDecoder().decode(HTTPTarget.self, from: Data($0.utf8)) },
            request: try requestBlob.flatMap { try BlobStore.load($0, from: db) },
            response: try responseBlob.flatMap { try BlobStore.load($0, from: db) },
            truncated: (row["truncated"] as Int?) == 1, title: row["title"] ?? "",
            status: NotebookStatus(rawValue: row["status"] ?? "") ?? .todo, note: row["body_md"] ?? "",
            tags: tagJSON.flatMap { try? JSONDecoder().decode([String].self, from: Data($0.utf8)) } ?? [],
            highlight: highlight.flatMap(Highlight.init),
            createdAt: Date(timeIntervalSince1970: row["created_at"] ?? 0),
            updatedAt: Date(timeIntervalSince1970: row["updated_at"] ?? 0), ordinal: row["ordinal"] ?? 0)
    }
}
