// GulpScanner — what a passive check sees: one exchange with its response headers (and their byte
// ranges), the decoded body, the request's parameters and small HTML helpers. Markers are byte ranges
// into the stored messages (the request bytes and the response's wire bytes), so the issue view can
// highlight exactly the proof (SCN-002).

import Foundation
import GulpCore
import GulpHTTP

/// One exchange prepared for passive checks.
public struct PassiveMessage: Sendable {
    /// The exchange.
    public let exchange: Exchange
    /// The response.
    public let response: RawResponse
    /// `scheme://host:port`.
    public let origin: String
    /// The request path (no query).
    public let path: String
    /// Status code.
    public let status: Int
    /// `Content-Type` without parameters, lowercased ("" when absent).
    public let mime: String
    /// The body as text (dechunked and decoded, first 2 MB).
    public let body: String
    /// The body bytes as received are also the decoded ones (markers can point into the body).
    public let bodyIsRaw: Bool
    /// Query and form parameters (name, decoded value, raw value).
    public let params: [(name: String, value: String, raw: String)]
    /// Offset of the final response inside the wire bytes (after 1xx responses).
    let wireOffset: Int

    /// Prepare `exchange` (nil when it has no response).
    public init?(_ exchange: Exchange) {
        guard let response = exchange.response else { return nil }
        self.exchange = exchange
        self.response = response
        origin = Issue.origin(exchange.target)
        path = exchange.derived.path ?? "/"
        status = response.parsed.statusCode
        mime = exchange.derived.mime ?? ""
        let raw =
            response.parsed.dechunkedBody?.rawBytes ?? Array(response.bytes.rawBytes[response.parsed.body])
        var decoded = raw
        let encoding =
            response.headerValue("content-encoding")?.string().trimmingCharacters(in: .whitespaces) ?? ""
        if !encoding.isEmpty, encoding.lowercased() != "identity",
            let plain = try? ContentDecoding.decode(
                Bytes(raw), contentEncoding: encoding, limit: 2 * 1024 * 1024)
        {
            decoded = plain.rawBytes
        }
        if decoded.count > 2 * 1024 * 1024 { decoded = Array(decoded[..<(2 * 1024 * 1024)]) }
        body = String(decoding: decoded, as: UTF8.self)
        bodyIsRaw =
            response.parsed.dechunkedBody == nil && (encoding.isEmpty || encoding.lowercased() == "identity")
        wireOffset = response.wireBytes.count - response.bytes.count
        var pairs = Self.formPairs(exchange.derived.query ?? "")
        let request = exchange.request
        if request.headerValue("content-type")?.string().lowercased().contains("x-www-form-urlencoded")
            == true
        {
            pairs += Self.formPairs(request.bytes[request.parsed.body].string())
        }
        params = pairs
    }

    /// Is this an HTTPS exchange.
    public var isHTTPS: Bool { exchange.target.scheme == .https }

    /// Is the response an HTML document.
    public var isHTML: Bool { mime.contains("html") }

    /// The values of response header `name` with the marker of each whole header line.
    public func headers(_ name: String) -> [(value: String, marker: MarkerRange)] {
        let wanted = name.lowercased()
        return response.parsed.headers.compactMap { field in
            guard response.bytes[field.name].string().lowercased() == wanted else { return nil }
            return (response.bytes[field.value].string(), MarkerRange(field.line).shifted(wireOffset))
        }
    }

    /// The last value of response header `name`.
    public func header(_ name: String) -> String? { headers(name).last?.value }

    /// The marker of the status line (for "this header is missing" findings).
    public var statusLineMarker: MarkerRange {
        let end = response.bytes.rawBytes.firstIndex(of: 0x0D) ?? min(response.bytes.count, 64)
        return MarkerRange(0, end).shifted(wireOffset)
    }

    /// The marker of the first occurrence of `text` in the body (raw bodies only).
    public func bodyMarker(_ text: String) -> MarkerRange? {
        guard bodyIsRaw, !text.isEmpty else { return nil }
        let bytes = response.bytes.rawBytes
        let needle = Array(text.utf8)
        let start = response.parsed.body.lowerBound
        guard let found = Self.find(needle, in: bytes, from: start) else { return nil }
        return MarkerRange(found, found + needle.count).shifted(wireOffset)
    }

    /// The marker of the first occurrence of `text` in the request bytes.
    public func requestMarker(_ text: String) -> MarkerRange? {
        let needle = Array(text.utf8)
        guard !needle.isEmpty, let found = Self.find(needle, in: exchange.request.bytes.rawBytes, from: 0)
        else {
            return nil
        }
        return MarkerRange(found, found + needle.count)
    }

    /// A finding of `definition` on this exchange.
    public func finding(
        _ definition: IssueDefinition, path: String? = nil, insertionPoint: String? = nil,
        variant: String = "",
        detail: String, requestMarkers: [MarkerRange] = [], responseMarkers: [MarkerRange] = [],
        note: String? = nil,
        severity: IssueSeverity? = nil, confidence: IssueConfidence? = nil
    ) -> IssueFinding {
        IssueFinding(
            typeID: definition.id, name: definition.name, severity: severity ?? definition.severity,
            confidence: confidence ?? definition.confidence, host: origin, path: path ?? self.path,
            insertionPoint: insertionPoint, variant: variant, detail: detail,
            background: definition.background,
            remediation: definition.remediation, references: definition.references,
            evidence: IssueEvidence(
                exchangeID: exchange.id, requestMarkers: requestMarkers, responseMarkers: responseMarkers,
                note: note))
    }

    static func find(_ needle: [UInt8], in haystack: [UInt8], from start: Int) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count, start <= haystack.count - needle.count else {
            return nil
        }
        var index = start
        let first = needle[0]
        while index <= haystack.count - needle.count {
            if haystack[index] == first, Array(haystack[index..<(index + needle.count)]) == needle {
                return index
            }
            index += 1
        }
        return nil
    }

    static func formPairs(_ text: String) -> [(name: String, value: String, raw: String)] {
        text.split(separator: "&").compactMap { piece in
            let parts = piece.split(separator: "=", maxSplits: 1).map(String.init)
            guard let name = parts.first, !name.isEmpty else { return nil }
            let raw = parts.count > 1 ? parts[1] : ""
            let decode = { (s: String) in
                s.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? s
            }
            return (decode(name), decode(raw), raw)
        }
    }

    // MARK: HTML helpers (enough for passive checks; not a full parser)

    /// Start tags named `tag` with their attributes (lowercased names, unquoted values).
    public func tags(_ tag: String) -> [[String: String]] {
        Self.tags(tag, in: body)
    }

    static func tags(_ tag: String, in html: String) -> [[String: String]] {
        guard let regex = try? NSRegularExpression(pattern: "<\(tag)\\b([^>]*)>", options: [.caseInsensitive])
        else {
            return []
        }
        let range = NSRange(html.startIndex..., in: html)
        return regex.matches(in: html, range: range).compactMap { match in
            Range(match.range(at: 1), in: html).map { attributes(String(html[$0])) }
        }
    }

    static func attributes(_ text: String) -> [String: String] {
        guard
            let regex = try? NSRegularExpression(
                pattern: #"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*(?:=\s*("[^"]*"|'[^']*'|[^\s"'>]+))?"#)
        else { return [:] }
        var result: [String: String] = [:]
        for match in regex.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            guard let nameRange = Range(match.range(at: 1), in: text) else { continue }
            var value = ""
            if let valueRange = Range(match.range(at: 2), in: text) {
                value = String(text[valueRange])
                if value.hasPrefix("\"") || value.hasPrefix("'") {
                    value = String(value.dropFirst().dropLast())
                }
            }
            result[text[nameRange].lowercased()] = value
        }
        return result
    }

    /// `<form>` elements: their attributes and the HTML inside.
    func forms() -> [(attributes: [String: String], inner: String)] {
        guard
            let regex = try? NSRegularExpression(
                pattern: #"<form\b([^>]*)>(.*?)</form>"#,
                options: [.caseInsensitive, .dotMatchesLineSeparators])
        else { return [] }
        return regex.matches(in: body, range: NSRange(body.startIndex..., in: body)).compactMap { match in
            guard let attributes = Range(match.range(at: 1), in: body),
                let inner = Range(match.range(at: 2), in: body)
            else { return nil }
            return (Self.attributes(String(body[attributes])), String(body[inner]))
        }
    }
}

extension MarkerRange {
    func shifted(_ offset: Int) -> MarkerRange { MarkerRange(start + offset, end + offset) }
}
