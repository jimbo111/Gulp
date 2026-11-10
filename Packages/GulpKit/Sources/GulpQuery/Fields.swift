// GulpQuery — the fields GulpQL knows (F05 HIS-021/HIS-022). One table drives validation, the
// evaluator, SQL lowering and autocomplete.

/// What a field yields.
public enum GulpQLFieldKind: String, Sendable, Hashable {
    /// Text.
    case text
    /// A number.
    case number
    /// True/false (usable bare: `in_scope`).
    case bool
    /// Several texts; a comparison holds if any element satisfies it.
    case list
}

/// A field's description, for validation and autocomplete (HIS-025).
public struct GulpQLFieldInfo: Sendable, Hashable {
    /// The name (`req.header`).
    public var name: String
    /// Accepted argument counts.
    public var arity: ClosedRange<Int>
    /// What it yields.
    public var kind: GulpQLFieldKind
    /// One-line help.
    public var help: String
    /// The `exchanges` column it lowers to, if any (HIS-024).
    var column: String?

    /// How it is written, e.g. `req.header("name")`.
    public var signature: String {
        switch arity.upperBound {
        case 0: name
        case 1 where arity.lowerBound == 0: name + "[(\"name\")]"
        case 1: name + "(\"name\")"
        default: name + "(\"from\", \"to\")"
        }
    }
}

/// The GulpQL field catalog.
public enum GulpQLFields {
    /// Every field and helper predicate.
    public static let all: [GulpQLFieldInfo] = [
        info("req.method", .text, "Request method", column: "method"),
        info("req.host", .text, "Host (lowercase)", column: "host"),
        info("req.port", .number, "Port", column: "port"),
        info("req.scheme", .text, "http or https", column: "scheme"),
        info("req.path", .text, "Path without the query", column: "path"),
        info("req.query", .text, "Query string without ?", column: "query"),
        info("req.url", .text, "scheme://host[:port]/path?query"),
        info("req.ext", .text, "File extension of the path", column: "extension"),
        info("req.length", .number, "Request size in bytes"),
        info("req.body", .text, "Request body"),
        info("req.line", .text, "Request line"),
        info("req.header", .text, "Last value of a request header", arity: 1...1),
        info("req.headers", .list, "Every value of a request header", arity: 1...1),
        info("req.cookie", .text, "A request cookie's value", arity: 1...1),
        info("req.param", .text, "A query, form or JSON parameter's value (decoded)", arity: 1...1),
        info("req.params", .list, "Parameter names"),
        info("req.has_param", .bool, "Has any parameter, or the named one", arity: 0...1),
        info("resp.status", .number, "Status code", column: "status"),
        info("resp.length", .number, "Response body length", column: "response_length"),
        info("resp.mime", .text, "Content-Type without parameters", column: "mime"),
        info("resp.title", .text, "HTML title", column: "title"),
        info("resp.body", .text, "Response body (decoded, first 2 MB)"),
        info("resp.time", .number, "Total time in ms"),
        info("resp.header", .text, "Last value of a response header", arity: 1...1),
        info("resp.cookie", .text, "Value of a cookie the response sets", arity: 1...1),
        info("resp.sets_cookie", .bool, "The response sets a cookie"),
        info("source", .text, "The tool: proxy, repeater, fuzzer…", column: "source"),
        info("in_scope", .bool, "In the project scope"),
        info("matches_scope", .bool, "Matches the current scope rules"),
        info("highlight", .text, "Highlight color", column: "highlight"),
        info("comment", .text, "Comment", column: "comment"),
        info("tag", .list, "Tags (imported, discovered…)"),
        info("has_response", .bool, "A response was received"),
        info("edited", .bool, "Edited in flight (intercept or rules)"),
        info("notes", .list, "Notebook notes on this exchange"),
        info("id", .number, "Row number", column: "id"),
        info("reflected", .bool, "A request parameter's value appears in the response", arity: 1...1),
        info("time_between", .bool, "Started between two dates/times (ISO 8601 or epoch)", arity: 2...2),
    ]

    static let byName: [String: GulpQLFieldInfo] = Dictionary(uniqueKeysWithValues: all.map { ($0.name, $0) })

    private static func info(
        _ name: String, _ kind: GulpQLFieldKind, _ help: String, arity: ClosedRange<Int> = 0...0,
        column: String? = nil
    ) -> GulpQLFieldInfo {
        GulpQLFieldInfo(name: name, arity: arity, kind: kind, help: help, column: column)
    }

    /// The field named `name`, if any.
    public static func named(_ name: String) -> GulpQLFieldInfo? { byName[name.lowercased()] }

    /// The closest known name (for "did you mean").
    static func suggestion(for name: String) -> String? {
        let scored = all.map { ($0.name, distance(name.lowercased(), $0.name)) }
        guard let best = scored.min(by: { $0.1 < $1.1 }), best.1 <= max(2, name.count / 3) else { return nil }
        return best.0
    }

    /// Levenshtein distance.
    static func distance(_ a: String, _ b: String) -> Int {
        let a = Array(a)
        let b = Array(b)
        guard !a.isEmpty else { return b.count }
        guard !b.isEmpty else { return a.count }
        var previous = Array(0...b.count)
        for i in 1...a.count {
            var current = [i] + Array(repeating: 0, count: b.count)
            for j in 1...b.count {
                current[j] = min(
                    previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1))
            }
            previous = current
        }
        return previous[b.count]
    }
}
