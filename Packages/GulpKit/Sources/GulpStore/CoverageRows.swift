// GulpStore — the raw material of the coverage index (F04 JRN-001): exchanges grouped by endpoint
// (scheme, host, port, path without the query) and tool, from a given row id on, so the index can be
// built once and extended incrementally. Derived data: no table (F04 §4).

import Foundation
import GRDB
import GulpCore

/// Exchanges of one tool on one endpoint.
public struct CoverageRow: Sendable, Hashable {
    /// `http`/`https`.
    public var scheme: String
    /// Host.
    public var host: String
    /// Port.
    public var port: Int
    /// Path without the query.
    public var path: String
    /// Method.
    public var method: String
    /// The tool (`exchanges.source`).
    public var source: String
    /// How many exchanges.
    public var count: Int
    /// The newest one's start.
    public var last: Date
    /// The endpoint is in scope.
    public var inScope: Bool
}

/// A Notebook item's endpoint, for the coverage index.
public struct NotebookEndpoint: Sendable, Hashable {
    /// The saved request's target.
    public var target: HTTPTarget
    /// Its path without the query.
    public var path: String
}

extension ProjectStore {
    /// Exchanges with `id > after`, grouped by endpoint, method and tool; and the highest id seen.
    public func coverageRows(after: ExchangeID = 0) async throws -> (rows: [CoverageRow], lastID: ExchangeID)
    {
        await writer.flush()
        return try await pool.read { db in
            let lastID = try ExchangeID.fetchOne(db, sql: "SELECT COALESCE(MAX(id), 0) FROM exchanges") ?? 0
            let rows = try Row.fetchAll(
                db,
                sql: """
                    SELECT scheme, host, port, COALESCE(path, '/') AS p, COALESCE(method, '?') AS m, source, \
                    COUNT(*) AS n, MAX(created_at) AS last, MAX(in_scope) AS scoped FROM exchanges \
                    WHERE id > ? AND id <= ? GROUP BY scheme, host, port, p, m, source
                    """,
                arguments: [after, lastID]
            ).map { row in
                CoverageRow(
                    scheme: row["scheme"], host: row["host"], port: row["port"], path: row["p"],
                    method: row["m"],
                    source: row["source"], count: row["n"], last: Date(timeIntervalSince1970: row["last"]),
                    inScope: (row["scoped"] as Int?) == 1)
            }
            return (rows, lastID)
        }
    }

    /// The endpoints Notebook items were saved from.
    public func notebookEndpoints() async throws -> [NotebookEndpoint] {
        try await notebookItems().compactMap { item in
            guard let target = item.target, let request = item.request else { return nil }
            let derived = DerivedFields(target: target, request: RawRequest(Bytes(request)), response: nil)
            return NotebookEndpoint(target: target, path: derived.path ?? "/")
        }
    }
}
