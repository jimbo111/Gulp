// GulpScanner — insertion points (F08 SCN-020, SCN-021). An insertion point is a byte range of the
// base request (a query value, a form value, a JSON or XML value, a multipart field, a cookie, a
// selected header, a path segment, or the whole body) plus how a payload must be encoded to land
// there. Building a probe splices the encoded payload into those bytes and fixes Content-Length —
// nothing else in the request is re-serialized (raw bytes are the truth).

import Foundation
import GulpCodec
import GulpCore

/// Where an insertion point sits (SCN-020).
public enum InsertionPointKind: String, Sendable, Codable, Hashable, CaseIterable {
    case urlParam = "url param"
    case bodyParam = "body param"
    case jsonValue = "json value"
    case xmlValue = "xml value"
    case multipartField = "multipart field"
    case cookie
    case header
    case pathSegment = "path segment"
    case wholeBody = "whole body"
    case custom
    /// A field inside a protobuf message of a gRPC, gRPC-Web or Connect request (GRP-005).
    case protobufField = "protobuf field"
}

/// How a payload is written into an insertion point.
public enum PayloadEncoding: String, Sendable, Codable, Hashable {
    /// Percent-encoding for URLs and form bodies.
    case url
    /// Inside a JSON string literal.
    case jsonString
    /// A JSON number/literal position: the payload becomes a JSON string.
    case jsonLiteral
    /// XML text or attribute.
    case xml
    /// As-is (headers, multipart, whole body).
    case none
    /// Written into a protobuf field and the message re-encoded (lengths and envelope recomputed).
    case protobuf
}

/// One insertion point.
public struct InsertionPoint: Sendable, Hashable {
    /// Kind.
    public var kind: InsertionPointKind
    /// Parameter, header, cookie or JSON-path name.
    public var name: String
    /// The value in the base request (decoded).
    public var baseValue: String
    /// The byte range of the value in the base request.
    public var range: Range<Int>
    /// How payloads are encoded here.
    public var encoding: PayloadEncoding
    /// For `.protobufField`: the field path (field numbers, outer to inner).
    public var protoPath: [Int]? = nil
    /// For `.protobufField`: which message of the request body.
    public var messageIndex = 0

    /// A label for issues and logs (`url param id`).
    public var label: String { "\(kind.rawValue) \(name)" }

    /// The base request with `payload` written here. `encoded` payloads are already in wire form
    /// (a CRLF probe's `%0d%0a`) and are spliced in as they are.
    public func build(_ base: RawRequest, payload: String, encoded: Bool = false) -> RawRequest {
        if let protoPath {
            return Self.buildProtobuf(base, path: protoPath, message: messageIndex, payload: payload)
        }
        let bytes = base.bytes.rawBytes
        let value = encoded ? Array(payload.utf8) : Array(Self.encode(payload, encoding).utf8)
        let spliced = Array(bytes[..<range.lowerBound]) + value + Array(bytes[range.upperBound...])
        return RawRequest(Bytes(spliced)).updatingContentLength()
    }

    /// The request with the protobuf field at `path` set to `payload` (same wire type where the
    /// text parses for it) and the message, envelope and Content-Length re-encoded.
    static func buildProtobuf(_ base: RawRequest, path: [Int], message index: Int, payload: String)
        -> RawRequest
    {
        guard let call = RPC.parse(request: base, response: nil), call.requests.indices.contains(index),
            let message = try? Protobuf.decode(call.requests[index].payload),
            let old = message.value(at: path),
            let edited = message.setting(path, to: ProtoValue.parsing(Array(payload.utf8), as: old.wireType)),
            let rebuilt = RPC.replacingMessage(base, at: index, with: edited.encoded)
        else { return base }
        return rebuilt
    }

    static func encode(_ payload: String, _ encoding: PayloadEncoding) -> String {
        switch encoding {
        case .url:
            var allowed = CharacterSet.alphanumerics
            allowed.insert(charactersIn: "-._~")
            return payload.addingPercentEncoding(withAllowedCharacters: allowed) ?? payload
        case .jsonString:
            let data =
                (try? JSONSerialization.data(withJSONObject: [payload], options: [.fragmentsAllowed]))
                ?? Data()
            let text = String(decoding: data, as: UTF8.self)  // ["…"]
            return String(text.dropFirst(2).dropLast(2))
        case .jsonLiteral:
            let data =
                (try? JSONSerialization.data(withJSONObject: [payload], options: [.fragmentsAllowed]))
                ?? Data()
            return String(String(decoding: data, as: UTF8.self).dropFirst().dropLast())
        case .xml:
            return payload.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(
                of: "<", with: "&lt;"
            )
            .replacingOccurrences(of: ">", with: "&gt;")
        case .none, .protobuf:
            return payload
        }
    }
}

/// Which insertion points a scan uses (SCN-021).
public struct InsertionPolicy: Sendable, Codable, Hashable {
    /// Kinds tested.
    public var kinds: Set<InsertionPointKind>
    /// Headers tested when present.
    public var headers: [String]
    /// Skip parameters whose name matches (case-insensitive regex; empty: none).
    public var skipNames: String
    /// At most this many points per request.
    public var maxPerRequest: Int

    /// The default policy: parameters, JSON/XML values, multipart fields, cookies, a few headers
    /// and path segments; framework/CSRF tokens skipped.
    public init(
        kinds: Set<InsertionPointKind> = [
            .urlParam, .bodyParam, .jsonValue, .xmlValue, .multipartField, .cookie, .header, .pathSegment,
            .wholeBody, .custom, .protobufField,
        ],
        headers: [String] = ["User-Agent", "Referer", "X-Forwarded-For"],
        skipNames: String =
            "^(csrf|_csrf|csrf_token|authenticity_token|__requestverificationtoken|__viewstate|__eventvalidation)$",
        maxPerRequest: Int = 50
    ) {
        self.kinds = kinds
        self.headers = headers
        self.skipNames = skipNames
        self.maxPerRequest = maxPerRequest
    }
}

/// Insertion point discovery (SCN-020).
public enum InsertionPoints {
    /// The insertion points of `request` under `policy`. Path segments are offered only for
    /// requests without parameters (a REST-style path is then the input).
    public static func derive(_ request: RawRequest, policy: InsertionPolicy = InsertionPolicy())
        -> [InsertionPoint]
    {
        let bytes = request.bytes.rawBytes
        let parsed = request.parsed
        var points: [InsertionPoint] = []
        // Query parameters.
        let target = parsed.target
        let targetText = Array(bytes[target])
        let question = targetText.firstIndex(of: UInt8(ascii: "?"))
        if let question {
            points += pairs(
                bytes, from: target.lowerBound + question + 1, to: target.upperBound,
                separator: UInt8(ascii: "&")
            )
            .map {
                InsertionPoint(
                    kind: .urlParam, name: $0.name, baseValue: $0.value, range: $0.range, encoding: .url)
            }
        }
        // Headers and cookies.
        let wanted = Set(policy.headers.map { $0.lowercased() })
        for field in parsed.headers {
            let name = String(decoding: bytes[field.name], as: UTF8.self)
            let lower = name.lowercased()
            if lower == "cookie" {
                points += pairs(
                    bytes, from: field.value.lowerBound, to: field.value.upperBound,
                    separator: UInt8(ascii: ";")
                )
                .map {
                    InsertionPoint(
                        kind: .cookie, name: $0.name, baseValue: $0.value, range: $0.range, encoding: .url)
                }
            } else if wanted.contains(lower) {
                points.append(
                    InsertionPoint(
                        kind: .header, name: name,
                        baseValue: String(decoding: bytes[field.value], as: UTF8.self),
                        range: field.value, encoding: .none))
            }
        }
        // Protobuf fields of RPC requests (GRP-005): every text and numeric leaf of each message.
        if let call = RPC.parse(request: request, response: nil) {
            for (index, message) in call.requests.enumerated() where !message.json {
                guard let decoded = try? Protobuf.decode(message.payload) else { continue }
                points += protobufLeaves(decoded, prefix: []).map { leaf in
                    InsertionPoint(
                        kind: .protobufField, name: leaf.path.map(String.init).joined(separator: "."),
                        baseValue: leaf.value, range: 0..<0, encoding: .protobuf, protoPath: leaf.path,
                        messageIndex: index)
                }
            }
            return filter(points, policy)
        }
        // Body.
        let body = parsed.body
        let rawType = request.headerValue("content-type")?.string() ?? ""
        let type = rawType.lowercased()
        if !body.isEmpty {
            let text = Array(bytes[body])
            if type.contains("x-www-form-urlencoded") {
                points += pairs(
                    bytes, from: body.lowerBound, to: body.upperBound, separator: UInt8(ascii: "&")
                )
                .map {
                    InsertionPoint(
                        kind: .bodyParam, name: $0.name, baseValue: $0.value, range: $0.range, encoding: .url)
                }
            } else if type.contains("json") || text.first == UInt8(ascii: "{")
                || text.first == UInt8(ascii: "[")
            {
                var jsonPoints = JSONScanner.values(bytes, in: body)
                // GraphQL (ADV-043): test only the operation's variables, never the query text itself.
                if GraphQL.isGraphQL(request: request) {
                    jsonPoints = jsonPoints.filter {
                        $0.name == "variables" || $0.name.hasPrefix("variables.")
                            || $0.name.hasPrefix("variables[")
                    }
                }
                points += jsonPoints
            } else if type.contains("xml") || text.first == UInt8(ascii: "<") {
                points += XMLScanner.values(bytes, in: body)
                points.append(
                    InsertionPoint(
                        kind: .wholeBody, name: "body", baseValue: String(decoding: text, as: UTF8.self),
                        range: body,
                        encoding: .none))
            } else if type.contains("multipart/form-data"), let boundary = boundary(rawType) {
                // The boundary comes from the original header: it is case-sensitive (RFC 2046).
                points += multipart(bytes, body: body, boundary: boundary)
            }
        }
        // REST path segments when nothing else carries input.
        if points.allSatisfy({ $0.kind == .header || $0.kind == .cookie }) {
            let end = question.map { target.lowerBound + $0 } ?? target.upperBound
            var start = target.lowerBound
            if targetText.starts(with: Array("http".utf8)),
                let slash = targetText.indices.first(where: { index in
                    index > 8 && targetText[index] == UInt8(ascii: "/")
                })
            {
                start = target.lowerBound + slash
            }
            var index = start
            while index < end {
                if bytes[index] == UInt8(ascii: "/") {
                    let segmentStart = index + 1
                    var segmentEnd = segmentStart
                    while segmentEnd < end, bytes[segmentEnd] != UInt8(ascii: "/") { segmentEnd += 1 }
                    if segmentEnd > segmentStart {
                        let value = String(decoding: bytes[segmentStart..<segmentEnd], as: UTF8.self)
                        points.append(
                            InsertionPoint(
                                kind: .pathSegment, name: value,
                                baseValue: value.removingPercentEncoding ?? value,
                                range: segmentStart..<segmentEnd, encoding: .url))
                    }
                    index = segmentEnd
                } else {
                    index += 1
                }
            }
        }
        return filter(points, policy)
    }

    /// Text and numeric leaves of a protobuf message (first occurrence of each field number;
    /// nested messages descended up to 8 levels).
    static func protobufLeaves(_ message: ProtoMessage, prefix: [Int]) -> [(path: [Int], value: String)] {
        var leaves: [(path: [Int], value: String)] = []
        var seen: Set<Int> = []
        for field in message.fields where seen.insert(field.number).inserted {
            let path = prefix + [field.number]
            switch field.value {
            case .varint(let v): leaves.append((path, String(v)))
            case .bytes(let bytes):
                switch Protobuf.readings(bytes).first {
                case .string(let text): leaves.append((path, text))
                case .message(let nested) where prefix.count < 8:
                    leaves += protobufLeaves(nested, prefix: path)
                default: break
                }
            default: break
            }
        }
        return leaves
    }

    /// Apply the policy: kinds, skipped names and the per-request cap.
    static func filter(_ points: [InsertionPoint], _ policy: InsertionPolicy) -> [InsertionPoint] {
        let skip =
            policy.skipNames.isEmpty
            ? nil : try? NSRegularExpression(pattern: policy.skipNames, options: [.caseInsensitive])
        let kept = points.filter { point in
            guard policy.kinds.contains(point.kind) else { return false }
            if let skip, point.kind != .header, point.kind != .wholeBody {
                let range = NSRange(point.name.startIndex..., in: point.name)
                if skip.firstMatch(in: point.name, range: range) != nil { return false }
            }
            return true
        }
        return Array(kept.prefix(policy.maxPerRequest))
    }

    /// A custom point over `range` (marked by the user, SCN-021).
    public static func custom(_ request: RawRequest, range: Range<Int>, name: String = "custom")
        -> InsertionPoint
    {
        InsertionPoint(
            kind: .custom, name: name,
            baseValue: String(decoding: request.bytes.rawBytes[range], as: UTF8.self), range: range,
            encoding: .none)
    }

    /// `name=value` pairs between `from` and `to`, with each value's byte range.
    static func pairs(_ bytes: [UInt8], from: Int, to: Int, separator: UInt8) -> [(
        name: String, value: String, range: Range<Int>
    )] {
        var result: [(String, String, Range<Int>)] = []
        var start = from
        while start < to {
            var end = start
            while end < to, bytes[end] != separator { end += 1 }
            var nameStart = start
            while nameStart < end, bytes[nameStart] == UInt8(ascii: " ") { nameStart += 1 }
            if let equals = bytes[nameStart..<end].firstIndex(of: UInt8(ascii: "=")) {
                let name = String(decoding: bytes[nameStart..<equals], as: UTF8.self)
                let raw = String(decoding: bytes[(equals + 1)..<end], as: UTF8.self)
                let value = raw.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? raw
                if !name.isEmpty {
                    result.append(((name.removingPercentEncoding ?? name), value, (equals + 1)..<end))
                }
            }
            start = end + 1
        }
        return result
    }

    static func boundary(_ type: String) -> String? {
        guard let range = type.range(of: "boundary=", options: .caseInsensitive) else { return nil }
        return String(type[range.upperBound...].split(separator: ";").first ?? "").trimmingCharacters(
            in: CharacterSet(charactersIn: "\" "))
    }

    /// Non-file multipart fields.
    static func multipart(_ bytes: [UInt8], body: Range<Int>, boundary: String) -> [InsertionPoint] {
        let delimiter = Array(("--" + boundary).utf8)
        var points: [InsertionPoint] = []
        var index = body.lowerBound
        var starts: [Int] = []
        while index + delimiter.count <= body.upperBound {
            if Array(bytes[index..<(index + delimiter.count)]) == delimiter {
                starts.append(index)
                index += delimiter.count
            } else {
                index += 1
            }
        }
        for (position, start) in starts.enumerated() where position + 1 < starts.count {
            let partStart = start + delimiter.count + 2  // CRLF after the delimiter
            let partEnd = starts[position + 1] - 2  // CRLF before the next delimiter
            guard partStart < partEnd else { continue }
            let part = Array(bytes[partStart..<partEnd])
            let (headerEnd, terminator) = HTTP1.headerBlockEnd(part)
            guard terminator != 0 else { continue }
            let head = String(decoding: part[..<headerEnd], as: UTF8.self)
            guard !head.lowercased().contains("filename="),
                let nameRange = head.range(of: "name=\"")
            else { continue }
            let name = String(head[nameRange.upperBound...].prefix { $0 != "\"" })
            let valueRange = (partStart + headerEnd)..<partEnd
            points.append(
                InsertionPoint(
                    kind: .multipartField, name: name,
                    baseValue: String(decoding: bytes[valueRange], as: UTF8.self),
                    range: valueRange, encoding: .none))
        }
        return points
    }
}

/// Scalar values in a JSON body, by path (`user.name`, `items[0]`).
enum JSONScanner {
    static func values(_ bytes: [UInt8], in body: Range<Int>) -> [InsertionPoint] {
        var points: [InsertionPoint] = []
        var index = body.lowerBound
        func skipSpace() {
            while index < body.upperBound, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
        }
        func string() -> (String, Range<Int>)? {
            guard index < body.upperBound, bytes[index] == UInt8(ascii: "\"") else { return nil }
            let start = index + 1
            index = start
            while index < body.upperBound, bytes[index] != UInt8(ascii: "\"") {
                index += bytes[index] == UInt8(ascii: "\\") ? 2 : 1
            }
            let end = min(index, body.upperBound)
            index = min(index + 1, body.upperBound)
            let raw = String(decoding: bytes[start..<end], as: UTF8.self)
            let decoded =
                (try? JSONSerialization.jsonObject(
                    with: Data(("\"" + raw + "\"").utf8), options: [.fragmentsAllowed])) as? String
            return (decoded ?? raw, start..<end)
        }
        func value(_ path: String, depth: Int) {
            guard depth < 32 else { return }
            skipSpace()
            guard index < body.upperBound else { return }
            switch bytes[index] {
            case UInt8(ascii: "{"):
                index += 1
                while index < body.upperBound {
                    skipSpace()
                    if index < body.upperBound, bytes[index] == UInt8(ascii: "}") {
                        index += 1
                        return
                    }
                    guard let (key, _) = string() else { return }
                    skipSpace()
                    if index < body.upperBound, bytes[index] == UInt8(ascii: ":") { index += 1 }
                    value(path.isEmpty ? key : path + "." + key, depth: depth + 1)
                    skipSpace()
                    if index < body.upperBound, bytes[index] == UInt8(ascii: ",") { index += 1 }
                }
            case UInt8(ascii: "["):
                index += 1
                var position = 0
                while index < body.upperBound {
                    skipSpace()
                    if index < body.upperBound, bytes[index] == UInt8(ascii: "]") {
                        index += 1
                        return
                    }
                    value("\(path)[\(position)]", depth: depth + 1)
                    position += 1
                    skipSpace()
                    if index < body.upperBound, bytes[index] == UInt8(ascii: ",") { index += 1 }
                }
            case UInt8(ascii: "\""):
                if let (text, range) = string() {
                    points.append(
                        InsertionPoint(
                            kind: .jsonValue, name: path, baseValue: text, range: range, encoding: .jsonString
                        ))
                }
            default:
                let start = index
                while index < body.upperBound, !",}] \t\r\n".utf8.contains(bytes[index]) { index += 1 }
                let literal = String(decoding: bytes[start..<index], as: UTF8.self)
                if !literal.isEmpty, literal != "null" {
                    points.append(
                        InsertionPoint(
                            kind: .jsonValue, name: path, baseValue: literal, range: start..<index,
                            encoding: .jsonLiteral))
                }
            }
        }
        value("", depth: 0)
        return points
    }
}

/// Text and attribute values in an XML body.
enum XMLScanner {
    static func values(_ bytes: [UInt8], in body: Range<Int>) -> [InsertionPoint] {
        let text = String(decoding: bytes[body], as: UTF8.self)
        guard let regex = try? NSRegularExpression(pattern: #"<([A-Za-z_][\w.-]*)(?:\s[^>]*)?>([^<]+)</\1>"#)
        else { return [] }
        var points: [InsertionPoint] = []
        for match in regex.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            guard let name = Range(match.range(at: 1), in: text),
                let value = Range(match.range(at: 2), in: text)
            else { continue }
            let prefix = text[text.startIndex..<value.lowerBound].utf8.count
            let length = text[value].utf8.count
            let start = body.lowerBound + prefix
            points.append(
                InsertionPoint(
                    kind: .xmlValue, name: String(text[name]), baseValue: String(text[value]),
                    range: start..<(start + length),
                    encoding: .xml))
        }
        return points
    }
}
