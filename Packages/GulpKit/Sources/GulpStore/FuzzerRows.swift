// GulpStore — saved Fuzzer attacks and their results (F07 FUZ-026; doc 04 §4 `fuzzer_attacks`,
// `fuzzer_results`). GulpStore doesn't know the Fuzzer's types: the configuration and each row's
// payloads/findings are JSON written by GulpFuzzer.

import Foundation
import GRDB
import GulpCore

/// A saved attack.
public struct FuzzerAttackRow: Sendable, Hashable {
    /// Row id.
    public var id: Int64
    /// Name.
    public var name: String
    /// The configuration (JSON).
    public var configJSON: String
    /// `running`, `paused`, `finished`, `cancelled`…
    public var state: String
    /// When it was created.
    public var createdAt: Date
    /// Result rows stored.
    public var resultCount: Int
}

/// One stored result row.
public struct FuzzerResultRow: Sendable, Hashable {
    /// Request number.
    public var seq: Int
    /// The payloads (JSON array).
    public var payloadsJSON: String
    /// The recorded exchange (0: none).
    public var exchangeID: Int64
    /// Status.
    public var status: Int?
    /// Length.
    public var length: Int
    /// Time (ms).
    public var timeMs: Int
    /// Findings and error (JSON object).
    public var grepJSON: String

    /// A row.
    public init(
        seq: Int, payloadsJSON: String, exchangeID: Int64, status: Int?, length: Int, timeMs: Int,
        grepJSON: String
    ) {
        self.seq = seq
        self.payloadsJSON = payloadsJSON
        self.exchangeID = exchangeID
        self.status = status
        self.length = length
        self.timeMs = timeMs
        self.grepJSON = grepJSON
    }
}

extension ProjectStore {
    /// Save a new attack; returns its id.
    public func createFuzzerAttack(name: String, configJSON: String, baseRequest: [UInt8], state: String)
        async throws
        -> Int64
    {
        try await pool.write { db in
            let blob = try BlobStore.store(baseRequest, in: db)
            try db.execute(
                sql: """
                    INSERT INTO fuzzer_attacks (name, config_json, base_request_blob, state, created_at) \
                    VALUES (?, ?, ?, ?, ?)
                    """,
                arguments: [name, configJSON, blob, state, Date().timeIntervalSince1970])
            return db.lastInsertedRowID
        }
    }

    /// Set an attack's state.
    public func setFuzzerAttackState(_ id: Int64, _ state: String) async throws {
        try await pool.write { db in
            try db.execute(sql: "UPDATE fuzzer_attacks SET state = ? WHERE id = ?", arguments: [state, id])
        }
    }

    /// Append result rows (one transaction; rows already stored are replaced).
    public func appendFuzzerResults(_ id: Int64, _ rows: [FuzzerResultRow]) async throws {
        guard !rows.isEmpty else { return }
        // A row names an exchange whose id was handed out before its write (coalesced): flush first,
        // so a result is never stored ahead of its exchange (an id lost in a crash would be reused).
        await writer.flush()
        try await pool.write { db in
            for row in rows {
                try db.execute(
                    sql: """
                        INSERT OR REPLACE INTO fuzzer_results \
                        (attack_id, seq, payloads_json, exchange_id, status, length, time_ms, grep_json) \
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                    arguments: [
                        id, row.seq, row.payloadsJSON, row.exchangeID, row.status, row.length, row.timeMs,
                        row.grepJSON,
                    ])
            }
        }
    }

    /// Saved attacks, newest first.
    public func fuzzerAttacks() async throws -> [FuzzerAttackRow] {
        try await pool.read { db in
            try Row.fetchAll(
                db,
                sql: """
                    SELECT a.id, a.name, a.config_json, a.state, a.created_at, \
                    (SELECT COUNT(*) FROM fuzzer_results r WHERE r.attack_id = a.id) AS results \
                    FROM fuzzer_attacks a ORDER BY a.id DESC
                    """
            ).map { row in
                FuzzerAttackRow(
                    id: row["id"], name: row["name"] ?? "", configJSON: row["config_json"] ?? "{}",
                    state: row["state"] ?? "", createdAt: Date(timeIntervalSince1970: row["created_at"] ?? 0),
                    resultCount: row["results"] ?? 0)
            }
        }
    }

    /// One page of an attack's results, in request order.
    public func fuzzerResults(_ id: Int64, offset: Int = 0, limit: Int = 1_000) async throws
        -> [FuzzerResultRow]
    {
        try await pool.read { db in
            try Row.fetchAll(
                db,
                sql: """
                    SELECT seq, payloads_json, exchange_id, status, length, time_ms, grep_json FROM fuzzer_results \
                    WHERE attack_id = ? ORDER BY seq LIMIT ? OFFSET ?
                    """,
                arguments: [id, limit, offset]
            ).map { row in
                FuzzerResultRow(
                    seq: row["seq"], payloadsJSON: row["payloads_json"] ?? "[]",
                    exchangeID: row["exchange_id"] ?? 0,
                    status: row["status"], length: row["length"] ?? 0, timeMs: row["time_ms"] ?? 0,
                    grepJSON: row["grep_json"] ?? "{}")
            }
        }
    }

    /// Delete an attack and its results.
    public func deleteFuzzerAttack(_ id: Int64) async throws {
        try await pool.write { db in
            try db.execute(sql: "DELETE FROM fuzzer_results WHERE attack_id = ?", arguments: [id])
            try db.execute(sql: "DELETE FROM fuzzer_attacks WHERE id = ?", arguments: [id])
        }
    }
}
