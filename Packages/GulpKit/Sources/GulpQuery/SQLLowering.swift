// GulpQuery — SQL push-down (F05 HIS-024). The parts of an expression that map to `exchanges`
// columns become a WHERE clause; the rest is a residual evaluated in memory over the reduced set.
// GulpQuery doesn't import GRDB: bindings are a neutral enum and GulpStore maps them.
//
// Semantics match the in-memory evaluator: every lowered comparison is written so it is never SQL
// NULL (`col IS NOT NULL AND …`), because SQL's three-valued logic would otherwise make
// `not (resp.status >= 500)` drop request-only rows that the evaluator keeps. Hosts and sources are
// stored lowercase, so equality on them binds a lowercased value and uses the binary indexes.

/// A value bound to a `?` placeholder.
public enum SQLBinding: Sendable, Hashable {
    /// TEXT.
    case text(String)
    /// INTEGER.
    case int(Int64)
    /// REAL.
    case double(Double)
    /// BLOB.
    case blob([UInt8])
    /// NULL.
    case null
}

/// The split of an expression into SQL and an in-memory remainder.
public struct GulpQLLowering: Sendable, Hashable {
    /// A WHERE clause (without `WHERE`) over `exchanges`, or nil when nothing pushes down.
    public var sql: String?
    /// The `?` values, in order.
    public var bindings: [SQLBinding]
    /// What must still be evaluated in memory (nil: the SQL is exact).
    public var residual: GulpQLExpression?
}

extension GulpQLExpression {
    /// Push down what maps to columns (HIS-024).
    public func sqlLowering() -> GulpQLLowering {
        switch self {
        case .and(let a, let b):
            let left = a.sqlLowering()
            let right = b.sqlLowering()
            var parts: [String] = []
            if let sql = left.sql { parts.append(sql) }
            if let sql = right.sql { parts.append(sql) }
            let residual: GulpQLExpression? =
                switch (left.residual, right.residual) {
                case (nil, nil): nil
                case (let x?, nil), (nil, let x?): x
                case (let x?, let y?): .and(x, y)
                }
            return GulpQLLowering(
                sql: parts.count > 1 ? "(" + parts.joined(separator: " AND ") + ")" : parts.first,
                bindings: left.bindings + right.bindings, residual: residual)
        case .or(let a, let b):
            let left = a.sqlLowering()
            let right = b.sqlLowering()
            guard let l = left.sql, let r = right.sql, left.residual == nil, right.residual == nil else {
                return GulpQLLowering(sql: nil, bindings: [], residual: self)
            }
            return GulpQLLowering(
                sql: "(\(l) OR \(r))", bindings: left.bindings + right.bindings, residual: nil)
        case .not(let a):
            let inner = a.sqlLowering()
            guard let sql = inner.sql, inner.residual == nil else {
                return GulpQLLowering(sql: nil, bindings: [], residual: self)
            }
            return GulpQLLowering(sql: "(NOT \(sql))", bindings: inner.bindings, residual: nil)
        case .constant(let flag):
            return GulpQLLowering(sql: flag ? "1" : "0", bindings: [], residual: nil)
        case .test(let field):
            guard let sql = Lowering.test(field) else {
                return GulpQLLowering(sql: nil, bindings: [], residual: self)
            }
            return GulpQLLowering(sql: sql.0, bindings: sql.1, residual: nil)
        case .compare(let field, let op, let value):
            guard let sql = Lowering.compare(field, op, value) else {
                return GulpQLLowering(sql: nil, bindings: [], residual: self)
            }
            return GulpQLLowering(sql: sql.0, bindings: sql.1, residual: nil)
        }
    }
}

enum Lowering {
    typealias Fragment = (String, [SQLBinding])

    static let numericColumns: Set<String> = ["port", "status", "response_length", "id"]
    /// Stored lowercase and indexed: equality binds a lowercased value (binary compare).
    static let lowercaseColumns: Set<String> = ["host", "source", "scheme"]

    /// A boolean field as a never-NULL SQL condition.
    static func boolean(_ field: GulpQLField) -> String? {
        guard field.arguments.isEmpty else { return nil }
        switch field.name {
        case "in_scope", "matches_scope": return "exchanges.in_scope = 1"
        case "has_response": return "exchanges.response_blob IS NOT NULL"
        case "edited":
            return
                "(exchanges.original_request_blob IS NOT NULL OR exchanges.original_response_blob IS NOT NULL)"
        case "resp.sets_cookie": return "COALESCE(exchanges.sets_cookies, 0) = 1"
        default: return nil
        }
    }

    static func test(_ field: GulpQLField) -> Fragment? {
        if field.name == "time_between", field.arguments.count == 2,
            let from = GulpQLTime.parse(field.arguments[0]), let to = GulpQLTime.parse(field.arguments[1])
        {
            return (
                "(exchanges.created_at BETWEEN ? AND ?)",
                [.double(from.timeIntervalSince1970), .double(to.timeIntervalSince1970)]
            )
        }
        if let condition = boolean(field) { return (condition, []) }
        if let list = listSource(field) { return ("EXISTS (\(list.select))", []) }
        guard field.arguments.isEmpty, let column = GulpQLFields.named(field.name)?.column else { return nil }
        let c = "exchanges." + column
        if numericColumns.contains(column) { return ("(\(c) IS NOT NULL AND \(c) != 0)", []) }
        return ("(\(c) IS NOT NULL AND \(c) != '')", [])
    }

    /// `tag` and `notes` live in other tables: an EXISTS over them.
    static func listSource(_ field: GulpQLField) -> (select: String, column: String)? {
        switch field.name {
        case "tag":
            return ("SELECT 1 FROM exchange_tags t WHERE t.exchange_id = exchanges.id", "t.tag")
        case "notes":
            return (
                "SELECT 1 FROM notebook_items n WHERE n.exchange_id = exchanges.id AND n.body_md IS NOT NULL",
                "n.body_md"
            )
        default: return nil
        }
    }

    static func compare(_ field: GulpQLField, _ op: GulpQLOperator, _ value: GulpQLValue) -> Fragment? {
        if let condition = boolean(field) {
            guard let wanted = value.asBool, op == .equal || op == .notEqual else { return nil }
            return (op == .equal) == wanted ? (condition, []) : ("(NOT \(condition))", [])
        }
        if let list = listSource(field) {
            let positive: GulpQLOperator = op == .notEqual ? .equal : op == .notMatches ? .matches : op
            guard let (condition, bindings) = scalar(list.column, text: true, lower: false, positive, value)
            else { return nil }
            let exists = "EXISTS (\(list.select) AND \(condition))"
            return positive == op ? (exists, bindings) : ("(NOT \(exists))", bindings)
        }
        guard field.arguments.isEmpty, let column = GulpQLFields.named(field.name)?.column else { return nil }
        let numeric = numericColumns.contains(column)
        guard
            let (condition, bindings) = scalar(
                "exchanges." + column, text: !numeric, lower: lowercaseColumns.contains(column), op, value)
        else { return nil }
        return ("(exchanges.\(column) IS NOT NULL AND \(condition))", bindings)
    }

    /// A condition on a non-NULL column value.
    static func scalar(_ c: String, text: Bool, lower: Bool, _ op: GulpQLOperator, _ value: GulpQLValue)
        -> Fragment?
    {
        // Regex operators (and a /regex/ literal with ==) use the registered function.
        if op.isRegex || (op == .equal && { if case .regex = value { true } else { false } }()) {
            guard text, let pattern = value.asText else { return nil }
            let caseless: Int64 = op == .matchesCaseSensitive ? 0 : 1
            let call = "\(GulpQL.regexFunctionName)(?, \(c), ?)"
            return (op == .notMatches ? "NOT \(call)" : call, [.text(pattern), .int(caseless)])
        }
        func bind(_ v: GulpQLValue) -> SQLBinding? {
            if text {
                guard let t = v.asText else { return nil }
                return .text(lower ? t.lowercased() : t)
            }
            guard let n = v.asNumber else { return nil }
            return n.rounded() == n && abs(n) < 9e15 ? .int(Int64(n)) : .double(n)
        }
        // Text equality is case-insensitive; indexed lowercase columns compare binary for the index.
        let collate = text && !lower ? " COLLATE NOCASE" : ""
        switch op {
        case .equal, .notEqual:
            guard let b = bind(value) else { return nil }
            return ("\(c) \(op == .equal ? "=" : "<>") ?\(collate)", [b])
        case .less, .lessOrEqual, .greater, .greaterOrEqual:
            // Text ordering (and number-like text) stays in memory, where it compares numerically.
            guard !text, let b = bind(value) else { return nil }
            // Written as a two-sided range (the open side closed at the Int64 limit): without STAT4,
            // SQLite guesses a one-sided range keeps 1/4 of the rows and prefers scanning in id order
            // over the index; a two-sided range is guessed at 1/64 and uses `ix_ex_status`.
            if op == .greater || op == .greaterOrEqual {
                return ("\(c) \(op.rawValue) ? AND \(c) <= ?", [b, .int(Int64.max)])
            }
            return ("\(c) >= ? AND \(c) \(op.rawValue) ?", [.int(Int64.min), b])
        case .contains, .startsWith, .endsWith:
            guard text, let t = value.asText else { return nil }
            let escaped = likeEscape(t)
            let pattern =
                switch op {
                case .contains: "%" + escaped + "%"
                case .startsWith: escaped + "%"
                default: "%" + escaped
                }
            return ("\(c) LIKE ? ESCAPE '\\'", [.text(pattern)])
        case .in:
            switch value {
            case .list(let values):
                let bound = values.compactMap(bind)
                guard bound.count == values.count, !bound.isEmpty else { return nil }
                let marks = Array(repeating: "?", count: bound.count).joined(separator: ", ")
                return ("\(c)\(collate) IN (\(marks))", bound)
            case .range(let low, let high):
                guard !text else { return nil }
                return ("\(c) BETWEEN ? AND ?", [.double(low), .double(high)])
            default: return nil
            }
        case .matches, .notMatches, .matchesCaseSensitive: return nil
        }
    }

    /// Escape `%`, `_` and `\` for `LIKE … ESCAPE '\'`.
    static func likeEscape(_ text: String) -> String {
        var out = ""
        for character in text {
            if character == "%" || character == "_" || character == "\\" { out.append("\\") }
            out.append(character)
        }
        return out
    }
}
