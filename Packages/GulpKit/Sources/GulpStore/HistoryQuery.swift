// GulpStore — History filters and sorting (F05 HIS-001/HIS-006), compiled to parameterised SQL.
// Column names come from a whitelist, never from user text.

import GRDB
import GulpCore

/// The History quick filters (HIS-006). An empty filter matches everything.
public struct HistoryFilter: Sendable, Hashable {
    /// Only exchanges from this tool.
    public var source: ToolSource?
    /// Only in-scope exchanges.
    public var inScopeOnly = false
    /// Hide images, CSS, JS and fonts.
    public var hideStaticAssets = false
    /// Status classes to keep (1…5 for 1xx…5xx); empty keeps all.
    public var statusClasses: Set<Int> = []
    /// Only requests with query parameters.
    public var onlyWithParams = false
    /// Only commented or highlighted exchanges.
    public var onlyAnnotated = false
    /// MIME type substring, e.g. `json`.
    public var mimeContains: String?
    /// Methods to keep; empty keeps all.
    public var methods: Set<String> = []
    /// Substring matched against host and path.
    public var text: String?

    /// Path extensions treated as static assets.
    public static let staticExtensions = [
        "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "css", "js", "mjs", "map", "woff",
        "woff2", "ttf", "otf", "eot",
    ]

    /// An empty filter.
    public init() {}

    /// The WHERE clause (without `WHERE`) and its arguments; `1` when the filter is empty.
    func sql() -> (clause: String, arguments: [DatabaseValue]) {
        var clauses: [String] = []
        var arguments: [DatabaseValue] = []
        if let source {
            clauses.append("source = ?")
            arguments.append(source.rawValue.databaseValue)
        }
        if inScopeOnly { clauses.append("in_scope = 1") }
        if hideStaticAssets {
            let marks = Array(repeating: "?", count: Self.staticExtensions.count).joined(separator: ", ")
            clauses.append("(extension IS NULL OR extension NOT IN (\(marks)))")
            arguments += Self.staticExtensions.map(\.databaseValue)
        }
        if !statusClasses.isEmpty {
            let ranges = statusClasses.sorted().map { _ in "(status >= ? AND status < ?)" }
            clauses.append("(" + ranges.joined(separator: " OR ") + ")")
            for c in statusClasses.sorted() {
                arguments += [(c * 100).databaseValue, (c * 100 + 100).databaseValue]
            }
        }
        if onlyWithParams { clauses.append("param_count > 0") }
        if onlyAnnotated {
            clauses.append("(highlight IS NOT NULL OR (comment IS NOT NULL AND comment != ''))")
        }
        if let mimeContains, !mimeContains.isEmpty {
            clauses.append("mime LIKE ?")
            arguments.append("%\(mimeContains.lowercased())%".databaseValue)
        }
        if !methods.isEmpty {
            let marks = Array(repeating: "?", count: methods.count).joined(separator: ", ")
            clauses.append("method IN (\(marks))")
            arguments += methods.sorted().map(\.databaseValue)
        }
        if let text, !text.isEmpty {
            clauses.append("(host LIKE ? OR path LIKE ?)")
            arguments += ["%\(text)%".databaseValue, "%\(text)%".databaseValue]
        }
        return (clauses.isEmpty ? "1" : clauses.joined(separator: " AND "), arguments)
    }
}

/// A sortable History column (HIS-001).
public enum HistorySortColumn: String, Sendable, Hashable, CaseIterable {
    case id, host, method, path, status, responseLength, mime, title, createdAt

    var sqlName: String {
        switch self {
        case .id: "id"
        case .host: "host"
        case .method: "method"
        case .path: "path"
        case .status: "status"
        case .responseLength: "response_length"
        case .mime: "mime"
        case .title: "title"
        case .createdAt: "created_at"
        }
    }
}

/// History ordering; ties break on id so paging is stable.
public struct HistorySort: Sendable, Hashable {
    /// Column.
    public var column: HistorySortColumn
    /// Ascending?
    public var ascending: Bool

    /// Oldest first (the proxy history default).
    public static let idAscending = HistorySort(column: .id, ascending: true)

    /// Create a sort.
    public init(column: HistorySortColumn, ascending: Bool) {
        self.column = column
        self.ascending = ascending
    }

    var sql: String {
        let direction = ascending ? "ASC" : "DESC"
        return column == .id ? "id \(direction)" : "\(column.sqlName) \(direction), id \(direction)"
    }
}
