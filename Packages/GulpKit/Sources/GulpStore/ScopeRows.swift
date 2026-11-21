// GulpStore — the project's scope (F04 TGT-020…TGT-022; doc 04 §4 `scope_rules`) and the `in_scope`
// column: rules are stored in order; changing them recomputes `in_scope` for every row in batches
// (only rows whose answer changes are written) and publishes `scopeChanged`.

import Foundation
import GRDB
import GulpCore

/// The path and query a scope rule sees for an exchange.
enum ScopePath {
    static func of(_ exchange: Exchange) -> String {
        let derived = exchange.derived
        return (derived.path ?? "/") + (derived.query.map { "?\($0)" } ?? "")
    }
}

extension ProjectStore {
    /// The scope rules, in order.
    public func scopeRules() async throws -> [ScopeRule] {
        try await pool.read { db in
            try Row.fetchAll(db, sql: "SELECT * FROM scope_rules ORDER BY ordinal, id").map { row in
                let uid: String? = row["uid"]
                return ScopeRule(
                    id: uid.flatMap(UUID.init(uuidString:)) ?? UUID(),
                    kind: ScopeRule.Kind(rawValue: row["kind"] ?? "") ?? .include,
                    enabled: (row["enabled"] as Int?) != 0,
                    scheme: ScopeRule.Scheme(rawValue: row["protocol"] ?? "") ?? .any,
                    host: row["host_regex"] ?? "", hostIsRegex: (row["host_is_regex"] as Int?) != 0,
                    port: row["port"] ?? "", path: row["path_regex"] ?? "")
            }
        }
    }

    /// Load the stored scope into the writer (call after opening).
    public func loadScope() async throws -> ScopeService {
        let service = ScopeService(rules: try await scopeRules())
        await writer.setScope(service)
        return service
    }

    /// Replace the scope (TGT-020/022): store the rules, apply them to new rows, recompute `in_scope`
    /// for existing rows in the background batches, then publish `scopeChanged`.
    @discardableResult
    public func setScope(_ rules: [ScopeRule]) async throws -> ScopeService {
        try await pool.write { db in
            try db.execute(sql: "DELETE FROM scope_rules")
            for (ordinal, rule) in rules.enumerated() {
                try db.execute(
                    sql: """
                        INSERT INTO scope_rules (uid, kind, enabled, protocol, host_regex, host_is_regex, port, \
                        path_regex, ordinal) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                    arguments: [
                        rule.id.uuidString, rule.kind.rawValue, rule.enabled, rule.scheme.rawValue, rule.host,
                        rule.hostIsRegex, rule.port, rule.path, ordinal,
                    ])
            }
        }
        let service = ScopeService(rules: rules)
        await writer.setScope(service)
        await writer.flush()  // rows queued under the old scope are on disk before the recompute
        try await recomputeInScope(service)
        await eventBus?.publish(.scopeChanged)
        return service
    }

    /// Recompute `in_scope` for every exchange, `batch` rows per transaction (TGT-022: 100k rows
    /// must not freeze anything — readers keep working between batches in WAL mode).
    func recomputeInScope(_ service: ScopeService, batch: Int = 2_000) async throws {
        var after: Int64 = 0
        while true {
            let start = after
            // GRDB's `Row` isn't Sendable: read the columns into plain values inside the closure.
            let rows = try await pool.read { db in
                try Row.fetchAll(
                    db,
                    sql: """
                        SELECT id, scheme, host, port, path, query, in_scope FROM exchanges WHERE id > ? \
                        ORDER BY id LIMIT ?
                        """,
                    arguments: [start, batch]
                ).map { row -> (id: Int64, target: HTTPTarget, path: String, inScope: Bool) in
                    let scheme: String = row["scheme"] ?? "http"
                    let target = HTTPTarget(
                        scheme: scheme == "https" ? .https : .http, host: row["host"] ?? "",
                        port: row["port"] ?? 0)
                    let query: String? = row["query"]
                    let path = (row["path"] ?? "/") + (query.map { "?\($0)" } ?? "")
                    return (row["id"], target, path, (row["in_scope"] as Int?) == 1)
                }
            }
            guard let last = rows.last else { return }
            after = last.id
            var changes: [(Int64, Bool)] = []
            for row in rows {
                let inScope = service.isInScope(row.target, path: row.path)
                if inScope != row.inScope { changes.append((row.id, inScope)) }
            }
            if !changes.isEmpty {
                let updates = changes
                try await pool.write { db in
                    for (id, inScope) in updates {
                        try db.execute(
                            sql: "UPDATE exchanges SET in_scope = ? WHERE id = ?", arguments: [inScope, id])
                    }
                }
            }
            await Task.yield()
        }
    }
}

extension ProjectStore {
    /// Site-map entries (F04 TGT-001) for exchanges with id > `after`, oldest first.
    public func siteMapEntries(after: ExchangeID = 0, limit: Int = 5_000) async throws -> [SiteMapEntry] {
        try await pool.read { db in
            try Row.fetchAll(
                db,
                sql:
                    "SELECT id, scheme, host, port, path, in_scope, status, mime, (response_blob IS NULL AND "
                    + "EXISTS (SELECT 1 FROM exchange_tags t WHERE t.exchange_id = exchanges.id AND t.tag = 'imported')) "
                    + "AS request_only FROM exchanges WHERE id > ? ORDER BY id LIMIT ?",
                arguments: [after, limit]
            ).map { row in
                let scheme: String = row["scheme"] ?? "http"
                return SiteMapEntry(
                    id: row["id"],
                    target: HTTPTarget(
                        scheme: scheme == "https" ? .https : .http, host: row["host"] ?? "",
                        port: row["port"] ?? 0),
                    path: row["path"] ?? "/", inScope: (row["in_scope"] as Int?) == 1, status: row["status"],
                    mime: row["mime"], visited: (row["request_only"] as Int?) != 1)
            }
        }
    }

    /// Ids of the newest exchanges whose responses may hold links (HTML, JSON, JavaScript, XML).
    public func textualResponseIDs(limit: Int = 2_000) async throws -> [ExchangeID] {
        try await pool.read { db in
            try ExchangeID.fetchAll(
                db,
                sql: """
                    SELECT id FROM exchanges WHERE mime LIKE '%html%' OR mime LIKE '%json%' \
                    OR mime LIKE '%javascript%' OR mime LIKE '%xml%' ORDER BY id DESC LIMIT ?
                    """,
                arguments: [limit])
        }
    }
}
