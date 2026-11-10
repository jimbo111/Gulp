// GulpStore — GulpQL over the project (F05 HIS-024): the expression's push-down part joins the
// History filter's WHERE clause; a residual (bodies, headers, cookies…) is evaluated in memory over
// the reduced candidate set, reading each candidate's bytes once. The `gulpql_regexp` SQL function
// makes regexes on columns (`req.host ~ "api"`) push down too.

import Foundation
import GRDB
import GulpCore
import GulpQuery

extension SQLBinding {
    /// The GRDB value.
    var databaseValue: DatabaseValue {
        switch self {
        case .text(let text): text.databaseValue
        case .int(let int): int.databaseValue
        case .double(let double): double.databaseValue
        case .blob(let bytes): Data(bytes).databaseValue
        case .null: .null
        }
    }
}

/// Compiled regexes for `gulpql_regexp`, shared by every connection.
// @unchecked Sendable: the dictionary is only touched under `lock`; NSRegularExpression is immutable
// and safe to use from several threads once compiled.
final class RegexCache: @unchecked Sendable {
    static let shared = RegexCache()
    private let lock = NSLock()
    private var compiled: [String: NSRegularExpression] = [:]

    func matches(_ pattern: String, _ text: String, caseless: Bool) -> Bool {
        let key = (caseless ? "i:" : "s:") + pattern
        let regex: NSRegularExpression? = lock.withLock {
            if let hit = compiled[key] { return hit }
            guard
                let made = try? NSRegularExpression(
                    pattern: pattern, options: caseless ? [.caseInsensitive] : [])
            else { return nil }
            if compiled.count > 256 { compiled.removeAll() }
            compiled[key] = made
            return made
        }
        guard let regex else { return false }
        // Columns are short; bound the work a pathological value can cause anyway.
        let checked = text.count > 65_536 ? String(text.prefix(65_536)) : text
        return regex.firstMatch(in: checked, range: NSRange(checked.startIndex..., in: checked)) != nil
    }
}

enum StoreFunctions {
    /// `gulpql_regexp(pattern, text, caseless)` → 0/1 (NULL text → 0).
    static let regexp = DatabaseFunction(GulpQL.regexFunctionName, argumentCount: 3, pure: true) { values in
        guard let pattern = String.fromDatabaseValue(values[0]),
            let text = String.fromDatabaseValue(values[1])
        else { return 0 }
        let caseless = (Int.fromDatabaseValue(values[2]) ?? 1) != 0
        return RegexCache.shared.matches(pattern, text, caseless: caseless) ? 1 : 0
    }
}

extension ProjectStore {
    /// Ids of the exchanges matching `filter` (its GulpQL query included), in `sort` order, at most
    /// `limit`. The query's residual is evaluated in memory; cancelling the task stops the scan.
    public func matchingIDs(
        filter: HistoryFilter, sort: HistorySort = .idAscending, limit: Int = 1_000_000,
        context: GulpQLContext = GulpQLContext()
    ) async throws -> [ExchangeID] {
        await writer.flush()
        let (clause, arguments) = filter.sql()
        let residual = filter.query?.sqlLowering().residual
        guard let residual else {
            let sql = "SELECT id FROM exchanges WHERE \(clause) ORDER BY \(sort.sql) LIMIT ?"
            return try await pool.read { db in
                try ExchangeID.fetchAll(
                    db, sql: sql, arguments: StatementArguments(arguments + [max(0, limit).databaseValue]))
            }
        }
        let predicate = try GulpQLPredicate(residual)
        let needsNotes = residual.fields.contains { $0.name == "notes" }
        let sql = "SELECT id, in_scope FROM exchanges WHERE \(clause) ORDER BY \(sort.sql)"
        return try await pool.read { db in
            var matched: [ExchangeID] = []
            let candidates = try Row.fetchCursor(db, sql: sql, arguments: StatementArguments(arguments))
            var seen = 0
            while matched.count < limit, let row = try candidates.next() {
                seen += 1
                if seen % 256 == 0, Task.isCancelled { throw CancellationError() }
                let id: ExchangeID = row["id"]
                guard let exchange = try ExchangeRows.load(id, from: db) else { continue }
                let inScope = (row["in_scope"] as Int?) == 1
                let notes = needsNotes ? try Self.notes(for: id, db) : []
                if predicate.evaluate(
                    exchange, context: Self.context(context, inScope: inScope, notes: notes))
                {
                    matched.append(id)
                }
            }
            return matched
        }
    }

    /// The number of exchanges matching `filter` (a residual makes this a scan).
    public func count(matching filter: HistoryFilter, context: GulpQLContext = GulpQLContext()) async throws
        -> Int
    {
        if filter.query?.sqlLowering().residual == nil { return try await count(filter: filter) }
        return try await matchingIDs(filter: filter, context: context).count
    }

    /// History rows for `ids` in the order given (a GulpQL result in its sort order; missing ids
    /// skipped).
    public func summaries(inOrder ids: [ExchangeID]) async throws -> [ExchangeSummary] {
        guard !ids.isEmpty else { return [] }
        await writer.flush()
        let rows = try await pool.read { db in
            var byID: [ExchangeID: ExchangeSummary] = [:]
            for start in stride(from: 0, to: ids.count, by: 500) {
                let chunk = Array(ids[start..<min(ids.count, start + 500)])
                let marks = Array(repeating: "?", count: chunk.count).joined(separator: ", ")
                let sql = "SELECT \(ExchangeRows.summaryColumns) FROM exchanges WHERE id IN (\(marks))"
                for row in try Row.fetchAll(db, sql: sql, arguments: StatementArguments(chunk)) {
                    let summary = ExchangeRows.summary(row)
                    byID[summary.id] = summary
                }
            }
            return byID
        }
        return ids.compactMap { rows[$0] }
    }

    /// SQLite's plan for the push-down part of `filter` (HIS-024's index check).
    public func queryPlan(filter: HistoryFilter, sort: HistorySort = .idAscending) async throws -> String {
        let (clause, arguments) = filter.sql()
        let sql = "EXPLAIN QUERY PLAN SELECT id FROM exchanges WHERE \(clause) ORDER BY \(sort.sql)"
        return try await pool.read { db in
            try Row.fetchAll(db, sql: sql, arguments: StatementArguments(arguments))
                .map { $0["detail"] as String? ?? "" }.joined(separator: "\n")
        }
    }

    /// Refresh the query planner's statistics (a sampled ANALYZE, cheap on big projects), so it
    /// knows e.g. that `status >= 500` is selective and uses `ix_ex_status` (HIS-024). Runs on close.
    public func updateStatistics() async throws {
        await writer.flush()
        try await pool.writeWithoutTransaction { db in
            try db.execute(sql: "PRAGMA analysis_limit = 1000")
            try db.execute(sql: "ANALYZE")
        }
    }

    static func notes(for id: ExchangeID, _ db: Database) throws -> [String] {
        try String.fetchAll(
            db, sql: "SELECT body_md FROM notebook_items WHERE exchange_id = ? AND body_md IS NOT NULL",
            arguments: [id])
    }

    /// The caller's context plus what the row knows: the stored scope flag, notes, gzip/deflate.
    static func context(_ base: GulpQLContext, inScope: Bool, notes: [String]) -> GulpQLContext {
        var context = base
        context.inScope = { _ in inScope }
        context.notes = { _ in notes }
        if context.decodeBody == nil {
            context.decodeBody = { body, encoding in SearchDecoding.decode(body, encoding: encoding) }
        }
        return context
    }
}
