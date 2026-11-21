// GulpCodec — reading traffic files (F20 PRJ-012/PRJ-013, F05 HIS-044, F23 ADV-051, F04 TGT-009):
// HAR (Gulp's own, browsers', mitmproxy's, Caido's), Postman v2.1 collections, the XML
// proxy-history export of the reference suite (base64 request/response items), Caido's JSON request
// export, and sitemap.xml / plain URL lists. OpenAPI documents are built into requests by
// `OpenAPIImport`. Everything here is pure: it turns bytes into `ImportedExchange`s and says what it
// skipped and why; storing (and dedup) is the workspace's `ImportExportService`.
//
// Raw bytes are the truth: when a format carries the exact bytes (Gulp's `_gulp` HAR field, the XML
// export's base64 items, Caido's `raw`), they are used unchanged. Formats that only carry parsed
// fields (plain HAR, Postman) are rebuilt as HTTP/1.1 text: pseudo-headers dropped, `Host` added if
// missing, a decoded body's `Content-Encoding`/`Transfer-Encoding` removed and `Content-Length` set
// to the body actually written.

import Foundation
import GulpCore

/// One exchange read from a file.
public struct ImportedExchange: Sendable, Equatable {
    /// Where it went.
    public var target: HTTPTarget
    /// The request bytes.
    public var request: RawRequest
    /// The response, if the file has one.
    public var response: RawResponse?
    /// HTTP version of the exchange.
    public var httpVersion: HTTPVersion
    /// When it started, if the file says.
    public var startedAt: Date?
    /// Duration in milliseconds, if the file says.
    public var durationMs: Double?
    /// A comment from the file.
    public var comment: String?
    /// A highlight from the file.
    public var highlight: Highlight?
    /// The tool that produced it, if the file says (Gulp's own HAR).
    public var source: ToolSource?

    /// An imported exchange.
    public init(
        target: HTTPTarget, request: RawRequest, response: RawResponse? = nil,
        httpVersion: HTTPVersion = .http1_1,
        startedAt: Date? = nil, durationMs: Double? = nil, comment: String? = nil,
        highlight: Highlight? = nil,
        source: ToolSource? = nil
    ) {
        self.target = target
        self.request = request
        self.response = response
        self.httpVersion = httpVersion
        self.startedAt = startedAt
        self.durationMs = durationMs
        self.comment = comment
        self.highlight = highlight
        self.source = source
    }
}

/// A file format the import service reads.
public enum TrafficFormat: String, Sendable, Hashable, CaseIterable, Codable {
    /// HTTP Archive 1.2 (Gulp, browsers, mitmproxy, Caido).
    case har
    /// Postman collection v2.1 (requests only).
    case postman
    /// OpenAPI 3.x / Swagger 2.0 (JSON): requests built for every operation.
    case openAPI = "openapi"
    /// The XML proxy-history export of the reference suite.
    case xmlHistory = "xml-history"
    /// Caido's JSON request export.
    case caido
    /// sitemap.xml.
    case sitemap
    /// One URL per line.
    case urlList = "urls"

    /// A readable name (never the reference suite's product name, CLAUDE.md §4).
    public var title: String {
        switch self {
        case .har: "HAR"
        case .postman: "Postman collection"
        case .openAPI: "OpenAPI / Swagger"
        case .xmlHistory: "XML proxy-history export"
        case .caido: "Caido export"
        case .sitemap: "sitemap.xml"
        case .urlList: "URL list"
        }
    }
}

/// Something in a file that was not imported.
public struct ImportSkip: Sendable, Hashable {
    /// Which item (an index, a name or a URL).
    public var item: String
    /// Why.
    public var reason: String

    /// A skip.
    public init(item: String, reason: String) {
        self.item = item
        self.reason = reason
    }
}

/// What a file held.
public struct ImportBatch: Sendable {
    /// The format read.
    public var format: TrafficFormat
    /// The exchanges, in file order.
    public var exchanges: [ImportedExchange]
    /// What was skipped.
    public var skipped: [ImportSkip]

    /// A batch.
    public init(format: TrafficFormat, exchanges: [ImportedExchange] = [], skipped: [ImportSkip] = []) {
        self.format = format
        self.exchanges = exchanges
        self.skipped = skipped
    }
}

/// Why a file could not be read at all.
public struct TrafficImportError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The reason.
    public var message: String

    /// An error.
    public init(_ message: String) {
        self.message = message
    }

    /// A readable form of the error: its message.
    public var description: String { message }
}

/// Reads traffic files.
public enum TrafficImport {
    /// The format of `data`, judged from its content.
    public static func detect(_ data: Data) -> TrafficFormat? {
        let head = String(decoding: data.prefix(4_096), as: UTF8.self).trimmingCharacters(
            in: .whitespacesAndNewlines)
        if head.hasPrefix("{") || head.hasPrefix("[") {
            guard let json = try? JSONSerialization.jsonObject(with: data) else { return nil }
            if let object = json as? [String: Any] {
                if let log = object["log"] as? [String: Any], log["entries"] != nil { return .har }
                if let info = object["info"] as? [String: Any],
                    (info["schema"] as? String)?.contains("postman") == true
                {
                    return .postman
                }
                if object["openapi"] != nil || object["swagger"] != nil { return .openAPI }
                if object["item"] != nil, object["info"] != nil { return .postman }
                if caidoRows(object) != nil { return .caido }
                return nil
            }
            return json is [Any] ? .caido : nil
        }
        if head.hasPrefix("<") {
            if head.contains("<items") { return .xmlHistory }
            if head.contains("<urlset") || head.contains("<sitemapindex") { return .sitemap }
            return nil
        }
        let lines = head.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
        if let first = lines.first(where: { !$0.isEmpty && !$0.hasPrefix("#") }),
            HTTPTarget(url: first) != nil
        {
            return .urlList
        }
        return nil
    }

    /// Read `data` as `format` (detected when nil). `baseURL` is where an OpenAPI document came from
    /// (used when it names no server).
    public static func read(_ data: Data, as format: TrafficFormat? = nil, baseURL: String? = nil) throws
        -> ImportBatch
    {
        guard let format = format ?? detect(data) else {
            throw TrafficImportError(
                "Unrecognized file: expected HAR, a Postman collection, OpenAPI/Swagger JSON, an XML proxy-history "
                    + "export, a Caido export, sitemap.xml or a list of URLs.")
        }
        switch format {
        case .har: return try HAR.read(data)
        case .postman: return try Postman.read(data)
        case .openAPI: return try OpenAPIImport.read(data, baseURL: baseURL)
        case .xmlHistory: return try XMLHistory.read(data)
        case .caido: return try readCaido(data)
        case .sitemap:
            return readURLs(XMLText.elements("loc", in: String(decoding: data, as: UTF8.self)), as: .sitemap)
        case .urlList:
            let lines = String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline)
                .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty && !$0.hasPrefix("#") }
            return readURLs(lines, as: .urlList)
        }
    }

    // MARK: URL lists and sitemap.xml (TGT-009)

    static func readURLs(_ urls: [String], as format: TrafficFormat) -> ImportBatch {
        var batch = ImportBatch(format: format)
        for url in urls {
            guard let target = HTTPTarget(url: url) else {
                batch.skipped.append(ImportSkip(item: url, reason: "not an http(s) URL"))
                continue
            }
            batch.exchanges.append(
                ImportedExchange(
                    target: target, request: Wire.request(method: "GET", url: url, target: target)))
        }
        return batch
    }

    // MARK: Caido (PRJ-013)

    /// The request rows of a Caido export: a bare array, or one under `requests`/`items`/`data`.
    static func caidoRows(_ json: Any) -> [[String: Any]]? {
        if let rows = json as? [[String: Any]] { return rows }
        guard let object = json as? [String: Any] else { return nil }
        for key in ["requests", "items", "data"] {
            if let rows = object[key] as? [[String: Any]] { return rows }
            if let nested = object[key] as? [String: Any], let rows = caidoRows(nested) { return rows }
        }
        return nil
    }

    static func readCaido(_ data: Data) throws -> ImportBatch {
        guard let json = try? JSONSerialization.jsonObject(with: data), let rows = caidoRows(json) else {
            throw TrafficImportError("Not a Caido export: expected an array of requests.")
        }
        var batch = ImportBatch(format: .caido)
        for (index, row) in rows.enumerated() {
            let label = "#\(index + 1)"
            let requestObject = row["request"] as? [String: Any] ?? row
            guard let raw = Wire.bytes(fromBase64OrText: requestObject["raw"]) else {
                batch.skipped.append(ImportSkip(item: label, reason: "no raw request"))
                continue
            }
            let request = RawRequest(Bytes(raw))
            let host = (requestObject["host"] ?? row["host"]) as? String
            let tls = ["is_tls", "isTls", "tls"].lazy.compactMap { (requestObject[$0] ?? row[$0]) as? Bool }
                .first
            let port = ((requestObject["port"] ?? row["port"]) as? NSNumber)?.intValue
            guard let target = Wire.target(host: host, port: port, tls: tls, request: request) else {
                batch.skipped.append(ImportSkip(item: label, reason: "no host"))
                continue
            }
            var response: RawResponse?
            if let responseObject = row["response"] as? [String: Any],
                let rawResponse = Wire.bytes(fromBase64OrText: responseObject["raw"])
            {
                response = RawResponse(wire: Bytes(rawResponse))
            }
            batch.exchanges.append(
                ImportedExchange(
                    target: target, request: request, response: response,
                    startedAt: Wire.date(row["created_at"] ?? row["createdAt"]),
                    comment: (row["comment"] ?? row["note"]) as? String,
                    highlight: (row["color"] as? String).flatMap(Wire.highlight)))
        }
        return batch
    }
}

/// Helpers for rebuilding wire bytes from parsed fields.
enum Wire {
    /// A minimal request for `url`.
    static func request(method: String, url: String, target: HTTPTarget) -> RawRequest {
        build(method: method, url: url, target: target, headers: [], body: [])
    }

    /// `path?query` of an absolute URL (`/` if none; the fragment dropped).
    static func requestTarget(_ url: String) -> String {
        ScopeService.requestPath(ofURL: url)
    }

    /// The `Host` value for a target (port only when not the scheme's default).
    static func hostHeader(_ target: HTTPTarget) -> String {
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        return standard ? target.host : "\(target.host):\(target.port)"
    }

    /// HTTP/1.1 request text: request line, `Host` first unless given, the headers as given
    /// (pseudo-headers dropped), and `Content-Length` matching the body when there is one.
    static func build(
        method: String, url: String, target: HTTPTarget, headers: [(String, String)], body: [UInt8],
        version: String = "HTTP/1.1"
    ) -> RawRequest {
        var kept = headers.filter { !$0.0.hasPrefix(":") }
        if !kept.contains(where: { $0.0.lowercased() == "host" }) {
            kept.insert(("Host", hostHeader(target)), at: 0)
        }
        kept = fixLength(kept, bodyCount: body.count, chunkedAllowed: false)
        var text = "\(method) \(requestTarget(url)) \(version)\r\n"
        for (name, value) in kept { text += "\(name): \(value)\r\n" }
        text += "\r\n"
        return RawRequest(Bytes(Array(text.utf8) + body))
    }

    /// HTTP/1.1 response text from parsed fields; the body is already decoded, so
    /// `Content-Encoding` and `Transfer-Encoding` are dropped and `Content-Length` set.
    static func response(
        status: Int, reason: String, headers: [(String, String)], body: [UInt8], version: String = "HTTP/1.1"
    ) -> RawResponse {
        var kept = headers.filter {
            let name = $0.0.lowercased()
            return !name.hasPrefix(":") && name != "content-encoding" && name != "transfer-encoding"
        }
        kept = fixLength(kept, bodyCount: body.count, chunkedAllowed: false)
        var text = "\(version) \(status)\(reason.isEmpty ? "" : " " + reason)\r\n"
        for (name, value) in kept { text += "\(name): \(value)\r\n" }
        text += "\r\n"
        return RawResponse(Bytes(Array(text.utf8) + body))
    }

    /// `headers` with one `Content-Length` equal to `bodyCount` (added when there's a body and none).
    static func fixLength(_ headers: [(String, String)], bodyCount: Int, chunkedAllowed: Bool) -> [(
        String, String
    )] {
        var result: [(String, String)] = []
        var hasLength = false
        for (name, value) in headers {
            if name.lowercased() == "content-length" {
                guard !hasLength else { continue }
                hasLength = true
                result.append((name, String(bodyCount)))
            } else {
                result.append((name, value))
            }
        }
        if !hasLength, bodyCount > 0 { result.append(("Content-Length", String(bodyCount))) }
        return result
    }

    /// Bytes from a base64 string (or, failing that, the string's UTF-8).
    static func bytes(fromBase64OrText value: Any?) -> [UInt8]? {
        guard let text = value as? String, !text.isEmpty else { return nil }
        if let data = Data(base64Encoded: text, options: .ignoreUnknownCharacters), !data.isEmpty,
            text.range(of: #"^[A-Za-z0-9+/=\s]+$"#, options: .regularExpression) != nil
        {
            return [UInt8](data)
        }
        return Array(text.utf8)
    }

    /// The target for a request: the given host/port/TLS, else its `Host` header.
    static func target(host: String?, port: Int?, tls: Bool?, request: RawRequest) -> HTTPTarget? {
        var name = host
        var hostPort: Int?
        if name == nil || name?.isEmpty == true, let header = request.headerValue("host")?.string() {
            let parts = header.split(separator: ":", maxSplits: 1)
            name = parts.first.map(String.init)
            hostPort = parts.count > 1 ? Int(parts[1]) : nil
        }
        guard let name, !name.isEmpty else { return nil }
        let scheme: Scheme = tls == true || (tls == nil && (port ?? hostPort) == 443) ? .https : .http
        return HTTPTarget(scheme: scheme, host: name, port: port ?? hostPort)
    }

    /// A date from ISO 8601 text or epoch seconds/milliseconds.
    static func date(_ value: Any?) -> Date? {
        if let number = value as? NSNumber {
            let raw = number.doubleValue
            return Date(timeIntervalSince1970: raw > 100_000_000_000 ? raw / 1_000 : raw)
        }
        guard let text = value as? String, !text.isEmpty else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: text) { return date }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: text)
            ?? Double(text).map { Date(timeIntervalSince1970: $0 > 100_000_000_000 ? $0 / 1_000 : $0) }
    }

    /// A highlight from a color name (any case; `grey` accepted).
    static func highlight(_ name: String) -> Highlight? {
        let lower = name.lowercased().trimmingCharacters(in: .whitespaces)
        return Highlight(rawValue: lower == "grey" ? "gray" : lower)
    }

    /// ISO 8601 with milliseconds (HAR's `startedDateTime`).
    static func isoString(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    /// The scheme://host[:port] + path?query URL of a request.
    static func url(_ target: HTTPTarget, request: RawRequest) -> String {
        var path = request.bytes[request.parsed.target].string()
        if path.contains("://") {
            return path
        }
        if path.isEmpty || !(path.hasPrefix("/") || path.hasPrefix("*")) { path = "/" + path }
        return "\(target.scheme.rawValue)://\(hostHeader(target))\(path)"
    }
}

/// A tiny reader for the flat XML these imports need (`<item>` blocks, `<loc>` values): elements by
/// name, CDATA sections and the five predefined entities. Not a general XML parser.
enum XMLText {
    /// The text content of every `<name ...>…</name>` in `text`, in order.
    static func elements(_ name: String, in text: String) -> [String] {
        blocks(name, in: text).map { decode($0.body) }
    }

    /// Each `<name attrs>body</name>`: its attribute text and raw body.
    static func blocks(_ name: String, in text: String) -> [(attributes: String, body: String)] {
        var result: [(String, String)] = []
        var cursor = text.startIndex
        let close = "</\(name)>"
        while let open = text.range(of: "<\(name)", range: cursor..<text.endIndex) {
            // The tag name must end here (so `<item` doesn't match `<items`).
            guard open.upperBound < text.endIndex else { break }
            let next = text[open.upperBound]
            guard next == ">" || next == " " || next == "\t" || next.isNewline || next == "/"
            else {
                cursor = open.upperBound
                continue
            }
            guard let tagEnd = text.range(of: ">", range: open.upperBound..<text.endIndex) else { break }
            let attributes = String(text[open.upperBound..<tagEnd.lowerBound])
            if attributes.hasSuffix("/") {
                result.append((attributes, ""))
                cursor = tagEnd.upperBound
                continue
            }
            guard let end = closing(close, in: text, from: tagEnd.upperBound) else { break }
            result.append((attributes, String(text[tagEnd.upperBound..<end.lowerBound])))
            cursor = end.upperBound
        }
        return result
    }

    /// The closing tag after `start`, skipping CDATA sections (which may contain anything).
    static func closing(_ close: String, in text: String, from start: String.Index) -> Range<String.Index>? {
        var cursor = start
        while cursor < text.endIndex {
            let cdata = text.range(of: "<![CDATA[", range: cursor..<text.endIndex)
            let end = text.range(of: close, range: cursor..<text.endIndex)
            guard let end else { return nil }
            if let cdata, cdata.lowerBound < end.lowerBound {
                guard let cdataEnd = text.range(of: "]]>", range: cdata.upperBound..<text.endIndex) else {
                    return nil
                }
                cursor = cdataEnd.upperBound
                continue
            }
            return end
        }
        return nil
    }

    /// Element text: CDATA kept verbatim, entities decoded elsewhere, surrounding whitespace trimmed
    /// outside CDATA.
    static func decode(_ body: String) -> String {
        var result = ""
        var cursor = body.startIndex
        var sawCDATA = false
        while let cdata = body.range(of: "<![CDATA[", range: cursor..<body.endIndex) {
            result += entities(String(body[cursor..<cdata.lowerBound]))
            guard let end = body.range(of: "]]>", range: cdata.upperBound..<body.endIndex) else { break }
            result += body[cdata.upperBound..<end.lowerBound]
            cursor = end.upperBound
            sawCDATA = true
        }
        result += entities(String(body[cursor...]))
        return sawCDATA ? result : result.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func entities(_ text: String) -> String {
        guard text.contains("&") else { return text }
        return text.replacingOccurrences(of: "&lt;", with: "<").replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&quot;", with: "\"").replacingOccurrences(of: "&apos;", with: "'")
            .replacingOccurrences(of: "&amp;", with: "&")
    }

    /// The value of `name="…"` in an attribute string.
    static func attribute(_ name: String, in attributes: String) -> String? {
        guard let range = attributes.range(of: #"\b\#(name)\s*=\s*"([^"]*)""#, options: .regularExpression)
        else {
            return nil
        }
        let match = String(attributes[range])
        guard let quote = match.firstIndex(of: "\"") else { return nil }
        return String(match[match.index(after: quote)...].dropLast())
    }
}

/// The XML proxy-history export (PRJ-013): `<items><item>…</item></items>` with `<host>`, `<port>`,
/// `<protocol>`, `<request base64="true">`, `<response base64="true">`, `<comment>`, and optionally
/// `<highlight>`.
enum XMLHistory {
    static func read(_ data: Data) throws -> ImportBatch {
        let text = String(decoding: data, as: UTF8.self)
        guard text.contains("<items") else { throw TrafficImportError("Not an XML proxy-history export.") }
        var batch = ImportBatch(format: .xmlHistory)
        for (index, item) in XMLText.blocks("item", in: text).enumerated() {
            let label = "item \(index + 1)"
            func field(_ name: String) -> (attributes: String, value: String)? {
                XMLText.blocks(name, in: item.body).first.map { ($0.attributes, XMLText.decode($0.body)) }
            }
            guard let requestField = field("request"), !requestField.value.isEmpty else {
                batch.skipped.append(ImportSkip(item: label, reason: "no request"))
                continue
            }
            guard let requestBytes = payload(requestField) else {
                batch.skipped.append(ImportSkip(item: label, reason: "request is not valid base64"))
                continue
            }
            let request = RawRequest(Bytes(requestBytes))
            let tls = field("protocol").map { $0.value.lowercased() == "https" }
            let port = field("port").flatMap { Int($0.value) }
            guard let target = Wire.target(host: field("host")?.value, port: port, tls: tls, request: request)
            else {
                batch.skipped.append(ImportSkip(item: label, reason: "no host"))
                continue
            }
            var response: RawResponse?
            if let responseField = field("response"), !responseField.value.isEmpty,
                let bytes = payload(responseField)
            {
                response = RawResponse(wire: Bytes(bytes))
            }
            let comment = field("comment")?.value
            batch.exchanges.append(
                ImportedExchange(
                    target: target, request: request, response: response,
                    startedAt: field("time").flatMap { date($0.value) },
                    comment: comment?.isEmpty == false ? comment : nil,
                    highlight: field("highlight").flatMap { Wire.highlight($0.value) }))
        }
        return batch
    }

    static func payload(_ field: (attributes: String, value: String)) -> [UInt8]? {
        if XMLText.attribute("base64", in: field.attributes) == "true" {
            return Data(base64Encoded: field.value, options: .ignoreUnknownCharacters).map { [UInt8]($0) }
        }
        return Array(field.value.utf8)
    }

    /// `Mon Nov 09 12:00:00 UTC 2026` (Java's `Date.toString`), or ISO 8601.
    static func date(_ text: String) -> Date? {
        if let iso = Wire.date(text) { return iso }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "EEE MMM dd HH:mm:ss zzz yyyy"
        return formatter.date(from: text)
    }
}
