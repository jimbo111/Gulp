// GulpProxy — Match & Replace (F01 PRX-020…PRX-022): ordered rules that rewrite requests and
// responses as they pass through the proxy, and (per rule) through every tool via the F03 hook
// pipeline (PRX-021).
//
// Concept: matching runs on a byte-for-byte Latin-1 view of the message (byte 0xNN ↔ scalar
// U+00NN), so a regex can match any bytes — including invalid UTF-8 — and replacing never re-encodes
// the bytes it didn't touch. Patterns and replacements the user types are UTF-8; they are converted
// to the same view, so `é` in a rule matches the UTF-8 bytes C3 A9.

import Foundation
import GulpCore
import GulpHTTP
import NIOConcurrencyHelpers

/// What a rule rewrites (PRX-020). The WebSocket kinds apply once WebSockets land (M4b).
public enum MatchReplaceKind: String, Sendable, Codable, CaseIterable {
    case requestHeader, requestBody, requestFirstLine, requestParamName, requestParamValue
    case responseHeader, responseBody, responseFirstLine
    case webSocketToServer, webSocketToClient

    /// Whether the rule applies to requests (else responses or WebSocket messages).
    public var isRequest: Bool {
        switch self {
        case .requestHeader, .requestBody, .requestFirstLine, .requestParamName, .requestParamValue: true
        default: false
        }
    }
}

/// One Match & Replace rule (PRX-020).
public struct MatchReplaceRule: Sendable, Codable, Hashable, Identifiable {
    /// Stable identity.
    public var id: UUID
    /// Whether the rule runs.
    public var enabled: Bool
    /// What it rewrites.
    public var kind: MatchReplaceKind
    /// Literal text or a regex. Empty with a header kind means "add the replacement as a header".
    public var match: String
    /// Replacement; `$1`… refer to regex groups. Empty with a header kind removes the matched line.
    public var replace: String
    /// Whether `match` is a regular expression.
    public var isRegex: Bool
    /// Free text.
    public var comment: String
    /// Also apply to Repeater, Fuzzer, Scanner… (PRX-021); otherwise proxy traffic only.
    public var applyToTools: Bool

    /// A rule.
    public init(
        id: UUID = UUID(), enabled: Bool = true, kind: MatchReplaceKind, match: String, replace: String,
        isRegex: Bool = false, comment: String = "", applyToTools: Bool = false
    ) {
        self.id = id
        self.enabled = enabled
        self.kind = kind
        self.match = match
        self.replace = replace
        self.isRegex = isRegex
        self.comment = comment
        self.applyToTools = applyToTools
    }

    /// Built-in presets, disabled by default (PRX-022).
    public static let presets: [MatchReplaceRule] = [
        MatchReplaceRule(
            enabled: false, kind: .requestHeader, match: "(?i)^User-Agent:.*$",
            replace: "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
                + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
            isRegex: true, comment: "Emulate iOS Safari"),
        MatchReplaceRule(
            enabled: false, kind: .requestHeader, match: "(?i)^User-Agent:.*$",
            replace: "User-Agent: Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
            isRegex: true, comment: "Emulate Android Chrome"),
        MatchReplaceRule(
            enabled: false, kind: .requestHeader, match: "(?i)^If-Modified-Since:.*$", replace: "",
            isRegex: true, comment: "Remove If-Modified-Since (avoid 304s)"),
        MatchReplaceRule(
            enabled: false, kind: .requestHeader, match: "(?i)^If-None-Match:.*$", replace: "",
            isRegex: true, comment: "Remove If-None-Match (avoid 304s)"),
        MatchReplaceRule(
            enabled: false, kind: .requestHeader, match: "(?i)^Accept-Encoding:.*$", replace: "",
            isRegex: true, comment: "Remove Accept-Encoding (plaintext responses)"),
        MatchReplaceRule(
            enabled: false, kind: .requestHeader, match: "", replace: "X-Forwarded-For: 127.0.0.1",
            comment: "Add X-Forwarded-For: 127.0.0.1"),
        MatchReplaceRule(
            enabled: false, kind: .responseHeader, match: "(?i)^Strict-Transport-Security:.*$",
            replace: "", isRegex: true, comment: "Hide HSTS"),
    ]
}

/// Applies Match & Replace rules to raw messages.
public enum MatchReplace {
    /// `request` with every enabled request rule applied, in order.
    public static func apply(_ rules: [MatchReplaceRule], to request: RawRequest) -> RawRequest {
        var bytes = request.bytes.rawBytes
        for rule in rules where rule.enabled && rule.kind.isRequest {
            bytes = applyOne(rule, to: bytes, isRequest: true)
        }
        return bytes == request.bytes.rawBytes ? request : RawRequest(Bytes(bytes))
    }

    /// `response` with every enabled response rule applied, in order.
    public static func apply(_ rules: [MatchReplaceRule], to response: RawResponse) -> RawResponse {
        var bytes = response.bytes.rawBytes
        for rule in rules where rule.enabled {
            switch rule.kind {
            case .responseHeader, .responseBody, .responseFirstLine:
                bytes = applyOne(rule, to: bytes, isRequest: false)
            default:
                continue
            }
        }
        guard bytes != response.bytes.rawBytes else { return response }
        return RawResponse(Bytes(bytes), interim: response.interim, headRequest: response.isHeadResponse)
    }

    static func applyOne(_ rule: MatchReplaceRule, to message: [UInt8], isRequest: Bool) -> [UInt8] {
        let (end, terminator) = HTTP1.headerBlockEnd(message)
        guard terminator != 0 else { return message }
        let head = Array(message[..<end])
        let body = Array(message[end...])
        switch rule.kind {
        case .requestFirstLine, .responseFirstLine:
            let lf = head.firstIndex(of: 0x0A) ?? head.count
            let lineEnd = lf < head.count && lf > 0 && head[lf - 1] == 0x0D ? lf - 1 : lf
            let line = rewrite(Array(head[..<lineEnd]), rule)
            return line + head[lineEnd...] + body
        case .requestHeader, .responseHeader:
            return rewriteHeaders(head, rule) + body
        case .requestBody, .responseBody:
            let newBody = rewrite(body, rule)
            guard newBody != body else { return message }
            return fixContentLength(head, length: newBody.count, isRequest: isRequest) + newBody
        case .requestParamName, .requestParamValue:
            return rewriteParams(head, body, rule)
        case .webSocketToServer, .webSocketToClient:
            return message
        }
    }

    /// Header rules: an empty match adds the replacement as a header line; otherwise every header
    /// line ("Name: value") is rewritten, and a line rewritten to nothing is removed.
    static func rewriteHeaders(_ head: [UInt8], _ rule: MatchReplaceRule) -> [UInt8] {
        // `head` is the start line, the header lines, and the empty line that ends the block.
        let lines = splitLines(head)
        guard lines.count >= 2, let blank = lines.last, blank.text.isEmpty else { return head }
        let ending: [UInt8] = lines[0].ending.isEmpty ? [0x0D, 0x0A] : lines[0].ending
        var out = lines[0].text + lines[0].ending
        for line in lines.dropFirst().dropLast() {
            if rule.match.isEmpty {
                out += line.text + line.ending
            } else {
                let rewritten = rewrite(line.text, rule)
                if !rewritten.isEmpty { out += rewritten + line.ending }  // rewritten to nothing: removed
            }
        }
        if rule.match.isEmpty, !rule.replace.isEmpty { out += Array(rule.replace.utf8) + ending }
        return out + blank.ending
    }

    /// Parameter rules: the query string and an `application/x-www-form-urlencoded` body.
    static func rewriteParams(_ head: [UInt8], _ body: [UInt8], _ rule: MatchReplaceRule) -> [UInt8] {
        var lines = splitLines(head)
        guard !lines.isEmpty else { return head + body }
        var first = lines[0].text
        if let question = first.firstIndex(of: 0x3F) {
            let afterQuery = first[(question + 1)...].firstIndex(of: 0x20) ?? first.count
            let query = Array(first[(question + 1)..<afterQuery])
            first = Array(first[...question]) + rewritePairs(query, rule) + first[afterQuery...]
            lines[0].text = first
        }
        var newHead = lines.flatMap { $0.text + $0.ending }
        var newBody = body
        let request = RawRequest(Bytes(head))
        let contentType = request.headerValue("content-type")?.string().lowercased() ?? ""
        let form = contentType.contains("application/x-www-form-urlencoded")
        if form, !body.isEmpty {
            newBody = rewritePairs(body, rule)
            if newBody != body {
                newHead = fixContentLength(newHead, length: newBody.count, isRequest: true)
            }
        }
        return newHead + newBody
    }

    static func rewritePairs(_ pairs: [UInt8], _ rule: MatchReplaceRule) -> [UInt8] {
        let split = pairs.split(separator: 0x26, omittingEmptySubsequences: false)
        let parts = split.map { pair -> [UInt8] in
            let pair = Array(pair)
            let equals = pair.firstIndex(of: 0x3D)
            let name = equals.map { Array(pair[..<$0]) } ?? pair
            let value = equals.map { Array(pair[($0 + 1)...]) }
            if rule.kind == .requestParamName {
                return rewrite(name, rule) + (value.map { [0x3D] + $0 } ?? [])
            }
            guard let value else { return pair }
            return name + [0x3D] + rewrite(value, rule)
        }
        return Array(parts.joined(separator: [0x26]))
    }

    /// Replace `rule.match` in `bytes` (literal or regex with `$n` groups).
    static func rewrite(_ bytes: [UInt8], _ rule: MatchReplaceRule) -> [UInt8] {
        let text = Latin1.string(bytes)
        let pattern = Latin1.string(Array(rule.match.utf8))
        let replacement = Latin1.string(Array(rule.replace.utf8))
        guard !pattern.isEmpty else { return bytes }
        if !rule.isRegex { return Latin1.bytes(replacingAll(text, pattern, with: replacement)) }
        guard let regex = try? Regex(pattern) else { return bytes }
        var result = ""
        var cursor = text.startIndex
        for match in text.matches(of: regex) {
            result += text[cursor..<match.range.lowerBound]
            result += expand(replacement, match.output)
            cursor = match.range.upperBound
        }
        result += text[cursor...]
        return Latin1.bytes(result)
    }

    /// Every occurrence of `target` in `text` replaced (no Foundation).
    static func replacingAll(_ text: String, _ target: String, with replacement: String) -> String {
        var result = ""
        var rest = text[...]
        while let range = rest.firstRange(of: target) {
            result += rest[..<range.lowerBound]
            result += replacement
            rest = rest[range.upperBound...]
        }
        return result + rest
    }

    /// `$0`…`$9` in `template` replaced by the match's groups.
    static func expand(_ template: String, _ output: AnyRegexOutput) -> String {
        var result = ""
        var characters = template[...]
        while let first = characters.first {
            characters = characters.dropFirst()
            if first == "$", let digit = characters.first?.wholeNumberValue {
                characters = characters.dropFirst()
                if digit < output.count, let group = output[digit].substring { result += group }
                continue
            }
            result.append(first)
        }
        return result
    }

    /// Set (or leave alone) a `Content-Length` header so it matches a rewritten body. Chunked
    /// messages and messages without Content-Length are left as they are.
    static func fixContentLength(_ head: [UInt8], length: Int, isRequest: Bool) -> [UInt8] {
        var lines = splitLines(head)
        for index in lines.indices.dropFirst() {
            let text = Latin1.string(lines[index].text)
            guard let colon = text.firstIndex(of: ":") else { continue }
            if text[..<colon].lowercased() == "content-length" {
                lines[index].text = Array("\(text[..<colon]): \(length)".utf8)
            }
        }
        return lines.flatMap { $0.text + $0.ending }
    }

    struct Line {
        var text: [UInt8]
        var ending: [UInt8]
    }

    /// Lines with their own endings (CRLF or bare LF), the last possibly without one.
    static func splitLines(_ bytes: [UInt8]) -> [Line] {
        var lines: [Line] = []
        var start = 0
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x0A {
                let crlf = index > start && bytes[index - 1] == 0x0D
                let textEnd = crlf ? index - 1 : index
                let ending: [UInt8] = crlf ? [0x0D, 0x0A] : [0x0A]
                lines.append(Line(text: Array(bytes[start..<textEnd]), ending: ending))
                start = index + 1
            }
            index += 1
        }
        if start < bytes.count { lines.append(Line(text: Array(bytes[start...]), ending: [])) }
        return lines
    }
}

/// Byte ↔ scalar mapping that never loses a byte (0xNN ↔ U+00NN).
enum Latin1 {
    static func string(_ bytes: [UInt8]) -> String {
        var scalars = String.UnicodeScalarView()
        scalars.append(contentsOf: bytes.map { Unicode.Scalar($0) })
        return String(scalars)
    }

    static func bytes(_ text: String) -> [UInt8] {
        var out: [UInt8] = []
        for scalar in text.unicodeScalars {
            if scalar.value < 0x100 {
                out.append(UInt8(scalar.value))
            } else {
                out += Array(String(scalar).utf8)
            }
        }
        return out
    }
}

/// Match & Replace as an F03 hook (PRX-021): proxy traffic always; other tools only for rules with
/// `applyToTools`. Rules can be swapped at any time.
public final class MatchReplaceHook: RequestHook, ResponseHook, Sendable {
    private let rules: NIOLockedValueBox<[MatchReplaceRule]>

    /// A hook running `rules`.
    public init(rules: [MatchReplaceRule] = []) {
        self.rules = NIOLockedValueBox(rules)
    }

    /// Replace the rule list.
    public func setRules(_ newRules: [MatchReplaceRule]) {
        rules.withLockedValue { $0 = newRules }
    }

    /// This hook's `HookSet` member.
    public var kind: HookSet { .matchReplace }

    func active(for source: ToolSource) -> [MatchReplaceRule] {
        rules.withLockedValue { $0 }.filter { $0.enabled && (source == .proxy || $0.applyToTools) }
    }

    /// Rewrite an outgoing request.
    public func willSend(_ req: inout OutgoingRequest, context: HookContext) async throws {
        req.request = MatchReplace.apply(active(for: context.source), to: req.request)
    }

    /// Rewrite a received response.
    public func didReceive(
        _ response: inout RawResponse, for request: OutgoingRequest, context: HookContext
    ) async throws {
        response = MatchReplace.apply(active(for: context.source), to: response)
    }
}
