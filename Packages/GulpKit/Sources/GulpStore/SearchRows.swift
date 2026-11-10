// GulpStore — global search (F05 HIS-050…053). A literal of 3+ characters goes through the FTS5
// trigram index (substring semantics, case-insensitive); every candidate is then checked against
// the exchange's decoded text, so the part (request/response) and section (headers/body) selectors
// are exact and each hit gets a preview. Regex mode prefilters on the longest literal run in the
// pattern when it has one; otherwise, and for 1–2 character queries, it scans a bounded number of
// the newest rows and says so.

import Foundation
import GRDB
import GulpCore

/// What to search for (HIS-050/051/052).
public struct SearchQuery: Sendable, Hashable {
    /// Which message.
    public enum Part: String, Sendable, Hashable, CaseIterable {
        /// Request and response.
        case both
        /// Requests only.
        case request
        /// Responses only.
        case response
    }

    /// Which part of a message.
    public enum Section: String, Sendable, Hashable, CaseIterable {
        /// Headers and body.
        case all
        /// The start line and headers.
        case headers
        /// The body.
        case body
    }

    /// The text (or regex).
    public var text: String
    /// Treat `text` as a regex (HIS-052).
    public var regex = false
    /// Case-sensitive matching (default: insensitive).
    public var caseSensitive = false
    /// Request, response or both.
    public var part = Part.both
    /// Headers, body or both.
    public var section = Section.all
    /// Which rows: the current table's filter, in-scope only (`inScopeOnly`), or all (empty).
    public var filter = HistoryFilter()
    /// Most hits returned.
    public var limit = 200
    /// Rows scanned when the index can't help.
    public var scanLimit = 20_000

    /// A query.
    public init(_ text: String) { self.text = text }
}

/// One match.
public struct SearchHit: Sendable, Hashable, Identifiable {
    /// The exchange.
    public var id: ExchangeID
    /// The tool it came from (results are grouped by it).
    public var source: ToolSource
    /// Method.
    public var method: String?
    /// Host.
    public var host: String
    /// Path and query.
    public var path: String
    /// Status.
    public var status: Int?
    /// Matched in the request.
    public var inRequest: Bool
    /// Matched in the response.
    public var inResponse: Bool
    /// Text around the first match.
    public var preview: String
}

/// Search results.
public struct SearchResults: Sendable, Hashable {
    /// Newest first.
    public var hits: [SearchHit]
    /// The trigram index was used (otherwise a bounded scan).
    public var usedIndex: Bool
    /// Rows whose bytes were examined.
    public var examined: Int
    /// More hits exist than `limit`, or the scan stopped at `scanLimit`.
    public var truncated: Bool
    /// Advice for the user (e.g. "type 3+ characters…").
    public var hint: String?
}

extension ProjectStore {
    /// Search requests and responses (HIS-050…052).
    public func search(_ query: SearchQuery) async throws -> SearchResults {
        await writer.flush()
        let text = query.text
        guard !text.isEmpty else {
            return SearchResults(hits: [], usedIndex: false, examined: 0, truncated: false, hint: nil)
        }
        let matcher = try SearchMatcher(query)
        let literal = query.regex ? SearchMatcher.longestLiteral(text) : text
        let (clause, arguments) = query.filter.sql()
        var sql: String
        var allArguments = arguments
        let indexed = literal.count >= 3
        if indexed {
            let column =
                switch query.part {
                case .both: "fts_exchanges"
                case .request: "request_text"
                case .response: "response_text"
                }
            sql = """
                SELECT id FROM exchanges WHERE id IN (SELECT rowid FROM fts_exchanges WHERE \(column) MATCH ?) \
                AND \(clause) ORDER BY id DESC
                """
            // An FTS5 phrase: the literal in double quotes, inner quotes doubled.
            let phrase = "\"" + literal.replacingOccurrences(of: "\"", with: "\"\"") + "\""
            allArguments = [phrase.databaseValue] + arguments
        } else {
            sql = "SELECT id FROM exchanges WHERE \(clause) ORDER BY id DESC LIMIT \(max(1, query.scanLimit))"
        }
        let finalSQL = sql
        let finalArguments = allArguments
        return try await pool.read { db in
            var hits: [SearchHit] = []
            var examined = 0
            var truncated = false
            let ids = try Row.fetchCursor(db, sql: finalSQL, arguments: StatementArguments(finalArguments))
            while let row = try ids.next() {
                let id: ExchangeID = row["id"]
                guard let exchange = try ExchangeRows.load(id, from: db) else { continue }
                examined += 1
                if examined % 256 == 0, Task.isCancelled { throw CancellationError() }
                guard let hit = matcher.hit(exchange) else { continue }
                if hits.count == query.limit {
                    truncated = true
                    break
                }
                hits.append(hit)
            }
            if !indexed, examined >= query.scanLimit { truncated = true }
            let hint: String? =
                indexed
                ? nil
                : query.regex
                    ? "No 3-character literal in the regex: scanned the newest \(examined) rows."
                    : "Type 3 or more characters to search the whole project; showing matches in the newest \(examined) rows."
            return SearchResults(
                hits: hits, usedIndex: indexed, examined: examined, truncated: truncated, hint: hint)
        }
    }

    /// "Find references" (HIS-053): every exchange containing `value`, newest first.
    public func findReferences(_ value: String, limit: Int = 500) async throws -> SearchResults {
        var query = SearchQuery(value)
        query.limit = limit
        return try await search(query)
    }

    /// Rebuild the search index from the stored exchanges (derived data, doc 04 §1), e.g. after an
    /// upgrade changed what is indexed. Returns the number of rows indexed.
    @discardableResult
    public func rebuildSearchIndex() async throws -> Int {
        await writer.flush()
        try await pool.write { db in
            try db.execute(sql: "INSERT INTO fts_exchanges(fts_exchanges) VALUES('delete-all')")
        }
        var last: ExchangeID = 0
        var total = 0
        while true {
            let after = last
            let done = try await pool.write { db -> (ExchangeID, Int)? in
                let ids = try ExchangeID.fetchAll(
                    db, sql: "SELECT id FROM exchanges WHERE id > ? ORDER BY id LIMIT 500", arguments: [after]
                )
                guard let tail = ids.last else { return nil }
                for id in ids {
                    guard let exchange = try ExchangeRows.load(id, from: db) else { continue }
                    try db.execute(
                        sql:
                            "INSERT INTO fts_exchanges (rowid, request_text, response_text) VALUES (?, ?, ?)",
                        arguments: [
                            id, ExchangeRows.searchText(exchange.request.bytes),
                            exchange.response.map(ExchangeRows.responseText),
                        ])
                }
                return (tail, ids.count)
            }
            guard let (tail, count) = done else { return total }
            last = tail
            total += count
        }
    }
}

/// Verifies a candidate against the query and builds its preview.
struct SearchMatcher: Sendable {
    let query: SearchQuery
    let regex: NSRegularExpression?

    init(_ query: SearchQuery) throws {
        self.query = query
        regex =
            query.regex
            ? try NSRegularExpression(
                pattern: query.text, options: query.caseSensitive ? [] : [.caseInsensitive])
            : nil
    }

    func hit(_ exchange: Exchange) -> SearchHit? {
        var preview: String?
        var inRequest = false
        var inResponse = false
        if query.part != .response {
            let (headers, body) = Self.texts(
                exchange.request.bytes, headerEnd: exchange.request.parsed.headerBlockEnd, body: nil,
                encoding: nil)
            if let found = find(headers, body) {
                inRequest = true
                preview = found
            }
        }
        if query.part != .request, let response = exchange.response {
            let raw =
                response.parsed.dechunkedBody?.rawBytes
                ?? Array(response.bytes.rawBytes[response.parsed.body])
            let (headers, body) = Self.texts(
                response.bytes, headerEnd: response.parsed.headerBlockEnd, body: raw,
                encoding: response.headerValue("content-encoding")?.string())
            if let found = find(headers, body) {
                inResponse = true
                preview = preview ?? found
            }
        }
        guard inRequest || inResponse, let preview else { return nil }
        let query = exchange.derived.query.map { "?" + $0 } ?? ""
        return SearchHit(
            id: exchange.id, source: exchange.source, method: exchange.derived.method,
            host: exchange.derived.host, path: (exchange.derived.path ?? "/") + query,
            status: exchange.response?.parsed.statusCode, inRequest: inRequest, inResponse: inResponse,
            preview: preview)
    }

    /// The message as text: headers, and the body (decoded, first 2 MB).
    static func texts(_ bytes: Bytes, headerEnd: Int, body: [UInt8]?, encoding: String?) -> (String, String) {
        let headers = bytes[0..<headerEnd].string()
        var raw = body ?? Array(bytes.rawBytes[headerEnd...])
        if let encoding, let plain = SearchDecoding.decode(raw, encoding: encoding) { raw = plain }
        if raw.count > 2 * 1024 * 1024 { raw = Array(raw[..<(2 * 1024 * 1024)]) }
        return (headers, String(decoding: raw, as: UTF8.self))
    }

    /// The preview of the first match in the selected sections, or nil.
    func find(_ headers: String, _ body: String) -> String? {
        let sections: [String] =
            switch query.section {
            case .all: [headers, body]
            case .headers: [headers]
            case .body: [body]
            }
        for text in sections {
            if let range = match(in: text) { return Self.preview(text, range) }
        }
        return nil
    }

    func match(in text: String) -> Range<String.Index>? {
        if let regex {
            guard let found = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) else {
                return nil
            }
            return Range(found.range, in: text)
        }
        return text.range(of: query.text, options: query.caseSensitive ? [] : [.caseInsensitive])
    }

    static func preview(_ text: String, _ range: Range<String.Index>) -> String {
        let start = text.index(range.lowerBound, offsetBy: -40, limitedBy: text.startIndex) ?? text.startIndex
        let end = text.index(range.upperBound, offsetBy: 40, limitedBy: text.endIndex) ?? text.endIndex
        let flat = text[start..<end].map { $0.isNewline ? "⏎" : $0 == "\t" ? " " : $0 }
        return (start > text.startIndex ? "…" : "") + String(flat) + (end < text.endIndex ? "…" : "")
    }

    /// The longest run of literal characters every match must contain (for the trigram
    /// prefilter): only top-level characters count (a group may be optional or an alternation), and
    /// any `|` makes the answer "" (no single literal is required).
    static func longestLiteral(_ pattern: String) -> String {
        var best = ""
        var current = ""
        var depth = 0
        var characters = Array(pattern)[...]
        func flush() {
            if current.count > best.count { best = current }
            current = ""
        }
        while let c = characters.popFirst() {
            switch c {
            case "\\":
                guard let next = characters.popFirst() else { break }
                // Escaped punctuation is literal; \d, \w, \s… are classes.
                if next.isLetter || next.isNumber || depth > 0 {
                    flush()
                } else {
                    current.append(next)
                }
            case "|":
                return ""
            case "(":
                depth += 1
                flush()
            case ")":
                depth -= 1
                flush()
            case "[":
                flush()
                while let d = characters.popFirst(), d != "]" {}
            case "?", "*":
                // The previous character is optional: drop it from the run.
                if !current.isEmpty { current.removeLast() }
                flush()
            case "{":
                if !current.isEmpty { current.removeLast() }
                flush()
                while let d = characters.popFirst(), d != "}" {}
            case ".", "^", "$", "+":
                flush()
            default:
                if depth == 0 { current.append(c) } else { flush() }
            }
        }
        flush()
        return best
    }
}
