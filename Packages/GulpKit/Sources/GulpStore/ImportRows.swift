// GulpStore — what the import/export service (F20 PRJ-012) and the agent audit log (F21 AUT-023)
// need: a duplicate check that uses the content-addressed blobs, bulk reads for export, and the
// `audit_log` table.

import Crypto
import Foundation
import GRDB
import GulpCore

/// One audited agent action (AUT-023).
public struct AuditEntry: Sendable, Hashable, Codable {
    /// Row id.
    public var id: Int64
    /// When.
    public var at: Date
    /// Who: the client and channel, e.g. `mcp:claude-code`.
    public var actor: String
    /// What: the tool, e.g. `send_request`.
    public var action: String
    /// The target, if any (`https://host:443/path`).
    public var target: String?
    /// `allowed`, `refused`, `error`, `read`.
    public var outcome: String
    /// More detail (the refusal, the exchange id…).
    public var detail: String?
}

extension ProjectStore {
    /// Whether an exchange with exactly these bytes, to this target — and, when `startedAt` is
    /// given, started then (±1 ms, HAR's precision) — is already stored (import dedup, PRJ-012).
    /// Uses the blobs' SHA-256 index and the request-blob index.
    public func containsExchange(target: HTTPTarget, request: Bytes, response: Bytes?, startedAt: Date? = nil)
        async throws -> Bool
    {
        let requestDigest = Data(SHA256.hash(data: request.rawBytes))
        let responseDigest = response.map { Data(SHA256.hash(data: $0.rawBytes)) }
        return try await pool.read { db in
            guard
                let requestBlob = try Int64.fetchOne(
                    db, sql: "SELECT id FROM blobs WHERE sha256 = ?", arguments: [requestDigest])
            else { return false }
            var responseBlob: Int64?
            if let responseDigest {
                responseBlob = try Int64.fetchOne(
                    db, sql: "SELECT id FROM blobs WHERE sha256 = ?", arguments: [responseDigest])
                if responseBlob == nil { return false }
            }
            var sql = """
                SELECT 1 FROM exchanges WHERE request_blob = ? AND scheme = ? AND host = ? AND port = ? \
                AND response_blob IS ?
                """
            var arguments: [(any DatabaseValueConvertible)?] = [
                requestBlob, target.scheme.rawValue, target.host, target.port, responseBlob,
            ]
            if let startedAt {
                sql += " AND abs(created_at - ?) < 0.001"
                arguments.append(startedAt.timeIntervalSince1970)
            }
            return try Int.fetchOne(db, sql: sql + " LIMIT 1", arguments: StatementArguments(arguments))
                != nil
        }
    }

    /// Full exchanges for `ids` (missing ones skipped), in id order.
    public func exchanges(ids: [ExchangeID]) async throws -> [Exchange] {
        await writer.flush()
        return try await pool.read { db in
            try ids.sorted().compactMap { try ExchangeRows.load($0, from: db) }
        }
    }

    /// Ids of the exchanges matching `filter`, oldest first, at most `limit`.
    public func exchangeIDs(filter: HistoryFilter = HistoryFilter(), limit: Int = 1_000_000) async throws
        -> [ExchangeID]
    {
        await writer.flush()
        let (clause, arguments) = filter.sql()
        let sql = "SELECT id FROM exchanges WHERE \(clause) ORDER BY id LIMIT ?"
        return try await pool.read { db in
            try ExchangeID.fetchAll(
                db, sql: sql, arguments: StatementArguments(arguments + [max(0, limit).databaseValue]))
        }
    }

    /// Append to the audit log (AUT-023); returns the row id.
    @discardableResult
    public func appendAudit(actor: String, action: String, target: String?, outcome: String, detail: String?)
        async throws -> Int64
    {
        try await pool.write { db in
            try db.execute(
                sql:
                    "INSERT INTO audit_log (at, actor, action, target, outcome, detail) VALUES (?, ?, ?, ?, ?, ?)",
                arguments: [Date().timeIntervalSince1970, actor, action, target, outcome, detail])
            return db.lastInsertedRowID
        }
    }

    /// The newest `limit` audit entries, oldest first.
    public func auditLog(limit: Int = 200) async throws -> [AuditEntry] {
        try await pool.read { db in
            try Row.fetchAll(
                db, sql: "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", arguments: [limit]
            ).reversed().map { row in
                AuditEntry(
                    id: row["id"], at: Date(timeIntervalSince1970: row["at"]), actor: row["actor"],
                    action: row["action"], target: row["target"], outcome: row["outcome"],
                    detail: row["detail"])
            }
        }
    }
}

extension ProjectStore {
    // F07 ETL-003
    /// File extensions already seen on a host (to seed content discovery).
    public func observedExtensions(host: String, port: Int) async throws -> [String] {
        try await pool.read { db in
            try String.fetchAll(
                db,
                sql: """
                    SELECT extension FROM exchanges WHERE host = ? COLLATE NOCASE AND port = ? \
                    AND extension IS NOT NULL GROUP BY extension ORDER BY COUNT(*) DESC LIMIT 20
                    """,
                arguments: [host, port])
        }
    }
}
