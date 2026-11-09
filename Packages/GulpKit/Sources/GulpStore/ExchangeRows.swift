// GulpStore — mapping between `Exchange` and the `exchanges` table (doc 04 §4).

import Foundation
import GRDB
import GulpCore

/// One History-table row: the indexed columns only, never the message bytes (HIS-001/002).
public struct ExchangeSummary: Sendable, Hashable, Identifiable {
    /// Exchange id (the History "#").
    public var id: ExchangeID
    /// Producing tool.
    public var source: ToolSource
    /// When the send started.
    public var createdAt: Date
    /// Target scheme.
    public var scheme: Scheme
    /// Target host.
    public var host: String
    /// Target port.
    public var port: Int
    /// Request method.
    public var method: String?
    /// Request path.
    public var path: String?
    /// Raw query string.
    public var query: String?
    /// Response status.
    public var status: Int?
    /// Response body length.
    public var responseLength: Int?
    /// Response MIME type.
    public var mime: String?
    /// HTML title.
    public var title: String?
    /// Path extension.
    public var ext: String?
    /// Number of query parameters.
    public var paramCount: Int
    /// Highlight color.
    public var highlight: Highlight?
    /// Comment.
    public var comment: String?
    /// Lifecycle state, as stored (`complete`, `failed`, …).
    public var state: String
    /// Network error token, if failed.
    public var error: String?
    /// End-to-end time in milliseconds.
    public var totalMs: Double?
    /// Protocol of the exchange (HTTP/2 is flagged in the History, M3b).
    public var httpVersion: HTTPVersion

    /// Create a row (the store builds these from the `exchanges` table; tests and previews build
    /// them directly).
    public init(
        id: ExchangeID, source: ToolSource, createdAt: Date, scheme: Scheme, host: String, port: Int,
        method: String? = nil, path: String? = nil, query: String? = nil, status: Int? = nil,
        responseLength: Int? = nil, mime: String? = nil, title: String? = nil, ext: String? = nil,
        paramCount: Int = 0, highlight: Highlight? = nil, comment: String? = nil, state: String,
        error: String? = nil, totalMs: Double? = nil, httpVersion: HTTPVersion = .http1_1
    ) {
        self.id = id
        self.source = source
        self.createdAt = createdAt
        self.scheme = scheme
        self.host = host
        self.port = port
        self.method = method
        self.path = path
        self.query = query
        self.status = status
        self.responseLength = responseLength
        self.mime = mime
        self.title = title
        self.ext = ext
        self.paramCount = paramCount
        self.highlight = highlight
        self.comment = comment
        self.state = state
        self.error = error
        self.totalMs = totalMs
        self.httpVersion = httpVersion
    }

    /// The URL shown in the History table.
    public var url: String {
        let defaultPort = scheme == .https ? 443 : 80
        let authority = port == defaultPort ? host : "\(host):\(port)"
        let tail = (path ?? "/") + (query.map { "?\($0)" } ?? "")
        return "\(scheme.rawValue)://\(authority)\(tail)"
    }
}

enum ExchangeRows {
    static let summaryColumns = """
        id, source, created_at, scheme, host, port, method, path, query, status, response_length, mime, \
        title, extension, param_count, highlight, comment, state, error, timing_json, http_version
        """

    /// Remove an exchange row and its search text (before re-inserting an updated version).
    static func delete(_ id: ExchangeID, in db: Database) throws {
        try db.execute(sql: "DELETE FROM fts_exchanges WHERE rowid = ?", arguments: [id])
        try db.execute(sql: "DELETE FROM exchanges WHERE id = ?", arguments: [id])
    }

    /// Insert `exchange` (whose `id` is already assigned) with its blobs, tags and search text.
    static func insert(_ exchange: Exchange, inScope: Bool = false, in db: Database) throws {
        let d = exchange.derived
        let requestBlob = try BlobStore.store(exchange.request.bytes.rawBytes, in: db)
        let responseBlob = try exchange.response.map { try BlobStore.store($0.wireBytes.rawBytes, in: db) }
        let originalRequest = try exchange.edited?.originalRequest.map {
            try BlobStore.store($0.bytes.rawBytes, in: db)
        }
        let originalResponse = try exchange.edited?.originalResponse.map {
            try BlobStore.store($0.wireBytes.rawBytes, in: db)
        }
        let encoder = JSONEncoder()
        let timing = String(decoding: try encoder.encode(exchange.timing), as: UTF8.self)
        let tls = try exchange.tls.map { String(decoding: try encoder.encode($0), as: UTF8.self) }
        let (state, error) = stateColumns(exchange.state)
        let target = exchange.target
        let note = exchange.annotation
        let columns: [(String, (any DatabaseValueConvertible)?)] = [
            ("id", exchange.id), ("source", exchange.source.rawValue),
            ("created_at", exchange.timing.start.timeIntervalSince1970), ("scheme", target.scheme.rawValue),
            ("host", target.host), ("port", target.port), ("ip", target.ipOverride),
            ("sni", target.sniOverride),
            ("http_version", exchange.httpVersion.rawValue), ("method", d.method), ("path", d.path),
            ("query", d.query), ("request_blob", requestBlob), ("response_blob", responseBlob),
            ("original_request_blob", originalRequest), ("original_response_blob", originalResponse),
            ("status", d.status), ("response_length", d.responseLength), ("mime", d.mime), ("title", d.title),
            ("state", state), ("error", error), ("timing_json", timing), ("tls_json", tls),
            ("connection_id", Int64(bitPattern: exchange.connectionID)),
            ("client_address", exchange.clientAddress), ("highlight", note.highlight?.rawValue),
            ("comment", note.comment), ("param_count", d.paramCount), ("has_cookies", d.hasCookies),
            ("sets_cookies", d.setsCookies), ("extension", d.ext), ("in_scope", inScope),
        ]
        let names = columns.map(\.0).joined(separator: ", ")
        let marks = Array(repeating: "?", count: columns.count).joined(separator: ", ")
        try db.execute(
            sql: "INSERT INTO exchanges (\(names)) VALUES (\(marks))",
            arguments: StatementArguments(columns.map(\.1)))
        for tag in exchange.annotation.tags {
            try db.execute(
                sql: "INSERT OR IGNORE INTO exchange_tags (exchange_id, tag) VALUES (?, ?)",
                arguments: [exchange.id, tag])
        }
        try db.execute(
            sql: "INSERT INTO fts_exchanges (rowid, request_text, response_text) VALUES (?, ?, ?)",
            arguments: [exchange.id, searchText(exchange.request.bytes), exchange.response.map(responseText)])
    }

    /// `exchanges.state` / `exchanges.error` for a state.
    static func stateColumns(_ state: ExchangeState) -> (String, String?) {
        switch state {
        case .pending: ("pending", nil)
        case .complete: ("complete", nil)
        case .dropped: ("dropped", nil)
        case .intercepted: ("intercepted", nil)
        case .failed(let error): ("failed", error.code)
        }
    }

    static func state(_ text: String, error: String?) -> ExchangeState {
        switch text {
        case "pending": .pending
        case "dropped": .dropped
        case "intercepted": .intercepted
        case "failed": .failed(GulpNetworkError(code: error ?? "other"))
        default: .complete
        }
    }

    /// Text indexed for search: the first 256 KB (doc 04 §4 "FTS").
    static func searchText(_ bytes: Bytes) -> String {
        bytes[0..<min(bytes.count, 262_144)].string()
    }

    /// Response headers always; the body only for text-like MIME types (doc 04 §4 "FTS").
    static func responseText(_ response: RawResponse) -> String {
        let mime = response.headerValue("content-type")?.string().lowercased() ?? ""
        let textual = ["text/", "json", "xml", "javascript", "html", "x-www-form-urlencoded"].contains {
            mime.contains($0)
        }
        let end = textual ? response.bytes.count : response.parsed.headerBlockEnd
        return searchText(response.bytes[0..<end])
    }

    /// Load a full exchange (bytes included).
    static func load(_ id: ExchangeID, from db: Database) throws -> Exchange? {
        let sql = "SELECT * FROM exchanges WHERE id = ?"
        guard let row = try Row.fetchOne(db, sql: sql, arguments: [id]) else { return nil }
        let requestBlob: Int64 = row["request_blob"]
        let request = RawRequest(Bytes(try BlobStore.load(requestBlob, from: db) ?? []))
        let isHead = request.bytes[request.parsed.method].string() == "HEAD"
        var response: RawResponse?
        if let blob: Int64 = row["response_blob"], let bytes = try BlobStore.load(blob, from: db) {
            response = RawResponse(wire: Bytes(bytes), headRequest: isHead)
        }
        let source = ToolSource(rawValue: row["source"]) ?? .proxy
        var edited: EditInfo?
        let originalRequestBlob: Int64? = row["original_request_blob"]
        let originalResponseBlob: Int64? = row["original_response_blob"]
        if originalRequestBlob != nil || originalResponseBlob != nil {
            let originalRequest = try originalRequestBlob.flatMap { try BlobStore.load($0, from: db) }
            let originalResponse = try originalResponseBlob.flatMap { try BlobStore.load($0, from: db) }
            edited = EditInfo(
                originalRequest: originalRequest.map { RawRequest(Bytes($0)) },
                originalResponse: originalResponse.map { RawResponse(wire: Bytes($0), headRequest: isHead) },
                editedBy: source)
        }
        let decoder = JSONDecoder()
        let timingJSON: String? = row["timing_json"]
        let tlsJSON: String? = row["tls_json"]
        let timing = timingJSON.flatMap { try? decoder.decode(Timing.self, from: Data($0.utf8)) } ?? Timing()
        let tls = tlsJSON.flatMap { try? decoder.decode(TLSInfo.self, from: Data($0.utf8)) }
        let tags = try String.fetchAll(
            db, sql: "SELECT tag FROM exchange_tags WHERE exchange_id = ? ORDER BY tag", arguments: [id])
        let target = HTTPTarget(
            scheme: Scheme(rawValue: row["scheme"]) ?? .http, host: row["host"], port: row["port"],
            sniOverride: row["sni"], ipOverride: row["ip"])
        let connection: Int64? = row["connection_id"]
        let highlight: String? = row["highlight"]
        let annotation = Annotation(
            comment: row["comment"], highlight: highlight.flatMap(Highlight.init), tags: tags)
        return Exchange(
            id: id, source: source, target: target,
            httpVersion: HTTPVersion(rawValue: row["http_version"]) ?? .http1_1, request: request,
            response: response, state: state(row["state"], error: row["error"]), timing: timing,
            clientAddress: row["client_address"], connectionID: UInt64(bitPattern: connection ?? 0), tls: tls,
            edited: edited, annotation: annotation)
    }

    static func summary(_ row: Row) -> ExchangeSummary {
        let timingJSON: String? = row["timing_json"]
        let timing = timingJSON.flatMap { try? JSONDecoder().decode(Timing.self, from: Data($0.utf8)) }
        let highlight: String? = row["highlight"]
        return ExchangeSummary(
            id: row["id"], source: ToolSource(rawValue: row["source"]) ?? .proxy,
            createdAt: Date(timeIntervalSince1970: row["created_at"]),
            scheme: Scheme(rawValue: row["scheme"]) ?? .http, host: row["host"], port: row["port"],
            method: row["method"], path: row["path"], query: row["query"], status: row["status"],
            responseLength: row["response_length"], mime: row["mime"], title: row["title"],
            ext: row["extension"],
            paramCount: row["param_count"] ?? 0, highlight: highlight.flatMap(Highlight.init),
            comment: row["comment"], state: row["state"], error: row["error"], totalMs: timing?.totalMs,
            httpVersion: HTTPVersion(rawValue: row["http_version"] ?? "") ?? .http1_1)
    }
}
