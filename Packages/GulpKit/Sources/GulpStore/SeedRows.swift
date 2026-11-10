// GulpStore — synthetic traffic for performance checks (the M9 DoD: GulpQL over 1M rows). Rows are
// real exchanges built from a few hundred message templates (so blobs are shared), with derived
// columns computed exactly as for recorded traffic; they skip the search index (rebuildSearchIndex
// adds them). Ids come from the writer, so later recordings follow them.

import Foundation
import GRDB
import GulpCore

extension ProjectStore {
    /// The hosts synthetic rows use.
    public static let syntheticHosts = [
        "api.example.test", "www.example.test", "cdn.example.test", "api-v2.example.test",
        "auth.example.test",
        "static.example.test", "admin.example.test", "mobile-api.example.test",
    ]
    /// The statuses synthetic rows cycle through (mostly 200; 500/502/503 rare).
    public static let syntheticStatuses = [
        200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 302, 304, 404, 404, 401, 500, 502, 503,
    ]

    /// Insert `count` synthetic exchanges; returns the id range. Row `i` (0-based) uses host
    /// `syntheticHosts[i % 8]` and status `syntheticStatuses[i % 20]`, so counts are predictable.
    @discardableResult
    public func seedSyntheticExchanges(count: Int, batch: Int = 20_000) async throws -> Range<ExchangeID> {
        let ids = await writer.reserveIDs(count)
        // Templates: one per (host, status) pair — 8 × 20 = 160 messages, cycled by row index.
        struct Template: Sendable {
            var columns: [DatabaseValue]
        }
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        let templates = try await pool.write { db -> [Template] in
            var templates: [Template] = []
            for t in 0..<(Self.syntheticHosts.count * Self.syntheticStatuses.count) {
                let host = Self.syntheticHosts[t % Self.syntheticHosts.count]
                let status = Self.syntheticStatuses[t % Self.syntheticStatuses.count]
                let method = t % 7 == 0 ? "POST" : "GET"
                let path = "/v\(t % 3)/items/\(t)" + (t % 4 == 0 ? "?page=\(t % 9)" : "")
                let body = status == 200 ? "{\"ok\":true,\"n\":\(t)}" : "error \(status)"
                let request = RawRequest(
                    Bytes("\(method) \(path) HTTP/1.1\r\nHost: \(host)\r\nAccept: */*\r\n\r\n"))
                let response = RawResponse(
                    Bytes(
                        "HTTP/1.1 \(status) X\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)"
                            + "\r\n\r\n\(body)"))
                let target = HTTPTarget(scheme: .https, host: host)
                let d = DerivedFields(target: target, request: request, response: response)
                let requestBlob = try BlobStore.store(request.bytes.rawBytes, in: db)
                let responseBlob = try BlobStore.store(response.wireBytes.rawBytes, in: db)
                let values: [(any DatabaseValueConvertible)?] = [
                    "https", host, 443, "HTTP/1.1", d.method, d.path, d.query, requestBlob, responseBlob,
                    d.status,
                    d.responseLength, d.mime, d.title, "complete", d.paramCount, d.hasCookies, d.setsCookies,
                    d.ext,
                ]
                templates.append(Template(columns: values.map { $0?.databaseValue ?? .null }))
            }
            return templates
        }
        let frozen = templates.map(\.columns)
        let sql = """
            INSERT INTO exchanges (id, source, created_at, scheme, host, port, http_version, method, path, query, \
            request_blob, response_blob, status, response_length, mime, title, state, param_count, has_cookies, \
            sets_cookies, extension, in_scope, timing_json, connection_id) \
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '{}', 0)
            """
        var offset = 0
        while offset < count {
            let first = offset
            let last = min(count, offset + batch)
            try await pool.write { db in
                let statement = try db.cachedStatement(sql: sql)
                for i in first..<last {
                    let t = i % frozen.count
                    let source = i % 13 == 0 ? "repeater" : "proxy"
                    let created = start.timeIntervalSince1970 + Double(i) * 0.01
                    let columns = frozen[t]
                    var arguments: [DatabaseValue] = [
                        (ids.lowerBound + ExchangeID(i)).databaseValue, source.databaseValue,
                        created.databaseValue,
                    ]
                    arguments += columns
                    try statement.execute(arguments: StatementArguments(arguments))
                }
            }
            offset = last
        }
        return ids
    }
}
