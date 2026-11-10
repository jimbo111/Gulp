// GulpFuzzer — reading responses (F07 FUZ-020…FUZ-024): grep-match columns, grep-extract columns,
// payload reflection, and anomalies against a baseline. Grep runs on the status line, headers and the
// decompressed body (capped), with regexes compiled once per attack.

import Foundation
import GulpCore
import GulpHTTP

/// A grep-match column (FUZ-021).
public struct GrepMatch: Sendable, Hashable, Codable {
    /// Text or regex.
    public var pattern: String
    /// `pattern` is a regex.
    public var isRegex: Bool
    /// Match case.
    public var caseSensitive: Bool

    /// A column.
    public init(_ pattern: String, isRegex: Bool = false, caseSensitive: Bool = false) {
        self.pattern = pattern
        self.isRegex = isRegex
        self.caseSensitive = caseSensitive
    }

    /// Common SQL error strings (a preset).
    public static let sqlErrors = GrepMatch(
        #"SQL syntax|SQLITE_ERROR|sqlite3?\.|ORA-\d{5}|PostgreSQL.*ERROR|Unclosed quotation mark|ODBC|syntax error at or near"#,
        isRegex: true)
    /// Stack traces and framework error pages (a preset).
    public static let stackTraces = GrepMatch(
        #"Traceback \(most recent call last\)|at [\w.$]+\([\w]+\.java:\d+\)|Exception in thread|Fatal error:|Stack trace:"#,
        isRegex: true)
}

/// A grep-extract column (FUZ-022).
public enum GrepExtract: Sendable, Hashable, Codable {
    /// The text between two delimiters (the first occurrence).
    case between(start: String, end: String)
    /// A regex capture group (0 = the whole match).
    case regex(pattern: String, group: Int)
}

/// Whether the payload came back (FUZ-024).
public enum Reflection: String, Sendable, Hashable, Codable {
    /// Not found.
    case none
    /// Found exactly as sent.
    case raw
    /// Found URL- or HTML-encoded.
    case encoded
}

/// What one response showed.
public struct ResponseFindings: Sendable, Hashable, Codable {
    /// One flag per grep-match column.
    public var matches: [Bool]
    /// One value per grep-extract column.
    public var extracts: [String?]
    /// Payload reflection.
    public var reflection: Reflection

    /// Findings.
    public init(matches: [Bool], extracts: [String?], reflection: Reflection) {
        self.matches = matches
        self.extracts = extracts
        self.reflection = reflection
    }
}

/// Compiled grep rules for an attack.
public struct ResponseAnalyzer: Sendable {
    /// Bytes of body grep looks at.
    public static let bodyLimit = 2 * 1024 * 1024
    let matchers: [NSRegularExpression]
    let extractors: [(NSRegularExpression, Int)]

    /// Compile `matches` and `extracts` (invalid regexes throw).
    public init(matches: [GrepMatch], extracts: [GrepExtract]) throws {
        matchers = try matches.map { match in
            let pattern =
                match.isRegex ? match.pattern : NSRegularExpression.escapedPattern(for: match.pattern)
            do {
                return try NSRegularExpression(
                    pattern: pattern, options: match.caseSensitive ? [] : [.caseInsensitive])
            } catch {
                throw FuzzTemplateError(message: "grep: invalid regex \(match.pattern)")
            }
        }
        extractors = try extracts.map { extract in
            switch extract {
            case .between(let start, let end):
                let pattern =
                    NSRegularExpression.escapedPattern(for: start) + "(.*?)"
                    + NSRegularExpression.escapedPattern(for: end)
                return (try NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]), 1)
            case .regex(let pattern, let group):
                do {
                    return (try NSRegularExpression(pattern: pattern), group)
                } catch {
                    throw FuzzTemplateError(message: "extract: invalid regex \(pattern)")
                }
            }
        }
    }

    /// The text grep reads: status line, headers, the decompressed body (capped) and, for a chunked
    /// response, its trailers (where gRPC puts `grpc-status`, F33) as `name: value` lines.
    public static func text(of response: RawResponse) -> String {
        let head = response.bytes[0..<min(response.parsed.headerBlockEnd, response.bytes.count)].rawBytes
        let body = ((try? response.decodedBody(limit: bodyLimit)) ?? nil)?.rawBytes ?? []
        var text = String(decoding: head + body.prefix(bodyLimit), as: UTF8.self)
        if response.headerValue("transfer-encoding")?.string().lowercased().contains("chunked") == true {
            let trailers = HTTP2Text.responseParts(response).trailers
            if !trailers.isEmpty {
                text += "\r\n" + trailers.map { "\($0.name): \($0.value)" }.joined(separator: "\r\n")
            }
        }
        return text
    }

    /// Analyze a response for an item whose payloads were `payloads`.
    public func analyze(_ response: RawResponse?, payloads: [[UInt8]]) -> ResponseFindings {
        guard let response else {
            return ResponseFindings(
                matches: matchers.map { _ in false }, extracts: extractors.map { _ in nil }, reflection: .none
            )
        }
        let text = Self.text(of: response)
        let range = NSRange(text.startIndex..., in: text)
        let matches = matchers.map { $0.firstMatch(in: text, range: range) != nil }
        let extracts: [String?] = extractors.map { regex, group in
            guard let match = regex.firstMatch(in: text, range: range), group < match.numberOfRanges,
                let captured = Range(match.range(at: group), in: text)
            else { return nil }
            return String(text[captured])
        }
        return ResponseFindings(
            matches: matches, extracts: extracts, reflection: Self.reflection(of: payloads, in: text))
    }

    /// Whether any (non-trivial) payload appears in `text`, raw or encoded.
    static func reflection(of payloads: [[UInt8]], in text: String) -> Reflection {
        var best = Reflection.none
        for payload in payloads where payload.count >= 3 {
            let raw = String(decoding: payload, as: UTF8.self)
            if text.contains(raw) { return .raw }
            let encodings = [
                raw.addingPercentEncoding(withAllowedCharacters: .alphanumerics),
                raw.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
                    .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(
                        of: "\"", with: "&quot;"),
            ]
            if encodings.contains(where: { $0.map { $0 != raw && text.contains($0) } ?? false }) {
                best = .encoded
            }
        }
        return best
    }
}

/// What makes a row stand out against the baseline (FUZ-023).
public enum Anomaly: String, Sendable, Hashable, Codable, CaseIterable {
    /// A different status code.
    case status
    /// Length differs by more than the tolerance.
    case length
    /// Much slower.
    case time
    /// A network error.
    case error
}

/// The baseline response (FUZ-023).
public struct Baseline: Sendable, Hashable, Codable {
    /// Status.
    public var status: Int?
    /// Length.
    public var length: Int
    /// Time in ms.
    public var timeMs: Double

    /// A baseline.
    public init(status: Int?, length: Int, timeMs: Double) {
        self.status = status
        self.length = length
        self.timeMs = timeMs
    }

    /// The anomalies of a row: status differs; length off by more than `lengthTolerance` (fraction,
    /// at least 8 bytes); time over `timeFactor` × baseline (and +200 ms).
    public func anomalies(
        status other: Int?, length: Int, timeMs: Double, error: Bool, lengthTolerance: Double = 0.05,
        timeFactor: Double = 3
    ) -> Set<Anomaly> {
        var result: Set<Anomaly> = []
        if error { result.insert(.error) }
        if other != status { result.insert(.status) }
        if abs(length - self.length) > max(8, Int(Double(self.length) * lengthTolerance)) {
            result.insert(.length)
        }
        if timeMs > self.timeMs * timeFactor + 200 { result.insert(.time) }
        return result
    }
}

/// Lengths bucketed for the "length histogram" (FUZ-023): (length, rows).
public func lengthHistogram(_ lengths: [Int]) -> [(length: Int, count: Int)] {
    Dictionary(grouping: lengths, by: { $0 }).map { ($0.key, $0.value.count) }.sorted {
        $0.count == $1.count ? $0.length < $1.length : $0.count > $1.count
    }
}
