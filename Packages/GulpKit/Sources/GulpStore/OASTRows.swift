// GulpStore — OAST payloads and interactions (F10 BCN-002; doc 04 §4 `oast_payloads`,
// `oast_interactions`). A payload row is written when a tool mints a token, with its context (tool,
// insertion point) and, once sent, the exchange that carried it; interactions polled from the server
// are matched to payloads by their unique id.

import Foundation
import GRDB
import GulpCore

/// Who used a payload, and where (BCN-001).
public struct OASTContext: Sendable, Hashable, Codable {
    /// The tool (`fuzzer`, `repeater`, `scanner`, `manual`…).
    public var tool: String
    /// The insertion point or position (e.g. `position 1`, `url param q`).
    public var insertionPoint: String?
    /// A note (the Transform Tag, the check…).
    public var note: String?

    /// A context.
    public init(tool: String, insertionPoint: String? = nil, note: String? = nil) {
        self.tool = tool
        self.insertionPoint = insertionPoint
        self.note = note
    }
}

/// A stored payload.
public struct StoredOASTPayload: Sendable, Hashable, Identifiable {
    /// Row id.
    public var id: Int64
    /// The 33-character unique id.
    public var correlationID: String
    /// The payload host.
    public var host: String?
    /// When it was minted.
    public var createdAt: Date
    /// Who used it.
    public var context: OASTContext
    /// The exchange that carried it, once known.
    public var exchangeID: ExchangeID?
}

/// A stored interaction, with its payload when one matched.
public struct StoredOASTInteraction: Sendable, Hashable, Identifiable {
    /// Row id.
    public var id: Int64
    /// The unique id the server reported.
    public var uniqueID: String
    /// `dns`, `http`, `https`, `smtp`…
    public var proto: String
    /// Who interacted.
    public var remoteAddress: String
    /// When.
    public var at: Date
    /// A one-line summary (the request line, or the DNS query).
    public var summary: String
    /// The matching payload of this project, if any.
    public var payload: StoredOASTPayload?
}

extension ProjectStore {
    /// Remember a minted payload (ignored if the id is already known).
    public func addOASTPayload(_ correlationID: String, host: String?, context: OASTContext) async throws {
        let json = String(decoding: try JSONEncoder().encode(context), as: UTF8.self)
        try await pool.write { db in
            try db.execute(
                sql: """
                    INSERT OR IGNORE INTO oast_payloads (correlation_id, host, created_at, context_json) \
                    VALUES (?, ?, ?, ?)
                    """,
                arguments: [correlationID.lowercased(), host, Date().timeIntervalSince1970, json])
        }
    }

    /// Tie payloads to the exchange that carried them.
    public func attachOASTPayloads(_ correlationIDs: [String], to exchange: ExchangeID) async throws {
        guard !correlationIDs.isEmpty else { return }
        // The exchange id is handed out before its row is written (coalesced): flush first, so a
        // payload never names an exchange that a crash could lose and a later one reuse.
        await writer.flush()
        try await pool.write { db in
            for id in correlationIDs {
                try db.execute(
                    sql: "UPDATE oast_payloads SET exchange_id = ? WHERE correlation_id = ?",
                    arguments: [exchange, id.lowercased()])
            }
        }
    }

    /// Store an interaction (raw text in a blob) and return it with its matching payload.
    @discardableResult
    public func recordOASTInteraction(
        uniqueID: String, proto: String, remoteAddress: String, at: Date, raw: [UInt8], summary: String
    ) async throws -> StoredOASTInteraction {
        let unique = uniqueID.lowercased()
        let id: Int64 = try await pool.write { db in
            let payload = try Int64.fetchOne(
                db, sql: "SELECT id FROM oast_payloads WHERE correlation_id = ?", arguments: [unique])
            let blob = raw.isEmpty ? nil : try BlobStore.store(raw, in: db)
            try db.execute(
                sql: """
                    INSERT INTO oast_interactions (payload_id, unique_id, protocol, remote_address, at, raw_blob, \
                    summary) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                arguments: [payload, unique, proto, remoteAddress, at.timeIntervalSince1970, blob, summary])
            return db.lastInsertedRowID
        }
        return try await oastInteractions(ids: [id]).first!
    }

    /// Interactions, newest first (`after`: only newer than this id).
    public func oastInteractions(after: Int64 = 0, limit: Int = 500) async throws -> [StoredOASTInteraction] {
        try await pool.read { db in
            try Self.interactionRows(db, where: "i.id > ? ORDER BY i.id DESC LIMIT ?", [after, limit])
        }
    }

    /// Interactions caused by payloads that `exchange` carried (the Fuzzer's OAST column, FUZ-025).
    public func oastInteractions(forExchange exchange: ExchangeID) async throws -> [StoredOASTInteraction] {
        try await pool.read { db in
            try Self.interactionRows(db, where: "p.exchange_id = ? ORDER BY i.id", [exchange])
        }
    }

    /// Interactions reported for one unique id (a scanner check's payload).
    public func oastInteractions(uniqueID: String) async throws -> [StoredOASTInteraction] {
        try await pool.read { db in
            try Self.interactionRows(db, where: "i.unique_id = ? ORDER BY i.id", [uniqueID.lowercased()])
        }
    }

    func oastInteractions(ids: [Int64]) async throws -> [StoredOASTInteraction] {
        try await pool.read { db in
            try Self.interactionRows(
                db, where: "i.id IN (\(ids.map { _ in "?" }.joined(separator: ",")))", StatementArguments(ids)
            )
        }
    }

    /// The raw request/query text of an interaction.
    public func oastInteractionRaw(_ id: Int64) async throws -> [UInt8]? {
        try await pool.read { db in
            guard
                let blob = try Int64.fetchOne(
                    db, sql: "SELECT raw_blob FROM oast_interactions WHERE id = ?", arguments: [id])
            else { return nil }
            return try BlobStore.load(blob, from: db)
        }
    }

    /// Payloads minted, newest first.
    public func oastPayloads(limit: Int = 500) async throws -> [StoredOASTPayload] {
        try await pool.read { db in
            try Row.fetchAll(
                db,
                sql:
                    "SELECT id, correlation_id, host, created_at, context_json, exchange_id FROM oast_payloads ORDER BY id DESC LIMIT ?",
                arguments: [limit]
            ).map(Self.payload)
        }
    }

    static func payload(_ row: Row) -> StoredOASTPayload {
        let context =
            (row["context_json"] as String?).flatMap {
                try? JSONDecoder().decode(OASTContext.self, from: Data($0.utf8))
            }
            ?? OASTContext(tool: "unknown")
        return StoredOASTPayload(
            id: row["id"], correlationID: row["correlation_id"], host: row["host"],
            createdAt: Date(timeIntervalSince1970: row["created_at"] ?? 0), context: context,
            exchangeID: row["exchange_id"])
    }

    static func interactionRows(_ db: Database, where clause: String, _ arguments: StatementArguments) throws
        -> [StoredOASTInteraction]
    {
        try Row.fetchAll(
            db,
            sql: """
                SELECT i.id AS iid, i.unique_id, i.protocol, i.remote_address, i.at, i.summary, \
                p.id, p.correlation_id, p.host, p.created_at, p.context_json, p.exchange_id \
                FROM oast_interactions i LEFT JOIN oast_payloads p ON p.id = i.payload_id WHERE \(clause)
                """,
            arguments: arguments
        ).map { row in
            let payloadID: Int64? = row["id"]
            return StoredOASTInteraction(
                id: row["iid"], uniqueID: row["unique_id"] ?? "", proto: row["protocol"] ?? "",
                remoteAddress: row["remote_address"] ?? "", at: Date(timeIntervalSince1970: row["at"] ?? 0),
                summary: row["summary"] ?? "", payload: payloadID == nil ? nil : payload(row))
        }
    }
}
