// GulpAI — the redaction pipeline (F22 AI-003). Before anything leaves the app for the provider, mask
// secrets and obvious credentials so they are never sent. Redaction is on by default; the user sees a
// preview and can edit or cancel. Pure string work, so it is fully tested.

import Foundation

/// Masks secrets in text destined for an LLM provider.
public struct Redactor: Sendable {
    /// Whether `redact` masks anything (on by default; AI-003).
    public var enabled: Bool
    private let rules: [(name: String, regex: NSRegularExpression, template: String)]

    /// The default rule set: auth headers, cookies, private-key blocks, bearer tokens, JWTs, common
    /// API keys, and secret-named JSON fields and `key=value` assignments. Rules run in order, so the
    /// broad ones (a whole header value, a whole key block) mask first.
    public init(enabled: Bool = true) {
        self.enabled = enabled
        // Redaction runs over whole HTTP messages, which the target controls, so every pattern must
        // stay linear: a name or token is matched only from the START of a run of its characters
        // (the lookbehind), name fragments are bounded, and runs that cannot give anything back are
        // possessive. Without that, a 1 MB run of name characters backtracks quadratically.
        //
        // Field names that carry secrets (`access_token`, `client_secret`, `api-key`, `password`, …),
        // up to 64 characters around the keyword.
        let secretName =
            #"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{0,64}?"#
            + #"(?:api[_\-]?key|secret|token|pass(?:word|wd|phrase))[A-Za-z0-9_\-]{0,64}+"#
        let rules: [(String, String, String)] = [
            // Header rules keep the header name and mask the value.
            ("authorization", #"(?im)^((?:proxy-)?authorization:[ \t]*)(.+)$"#, "$1[REDACTED]"),
            ("cookie", #"(?im)^((?:set-)?cookie:[ \t]*)(.+)$"#, "$1[REDACTED]"),
            // The whole PEM block, body included; to the end of the text when the END line is cut off
            // (then the match runs to the end, so the lazy body is scanned at most once).
            (
                "private-key",
                #"-----BEGIN (?:[A-Z0-9]++ ){0,3}PRIVATE KEY-----[\s\S]*?"#
                    + #"(?:-----END (?:[A-Z0-9]++ ){0,3}PRIVATE KEY-----|\z)"#,
                "[REDACTED]"
            ),
            ("bearer", #"(?i)\bBearer\s+[A-Za-z0-9._~+/\-]{8,}=*"#, "[REDACTED]"),
            ("aws-key", #"\bAKIA[0-9A-Z]{16}\b"#, "[REDACTED]"),
            ("google-key", #"\bAIza[0-9A-Za-z_\-]{35}\b"#, "[REDACTED]"),
            ("slack", #"\bxox[baprs]-[0-9A-Za-z\-]{10,}"#, "[REDACTED]"),
            ("github", #"\bgh[pousr]_[0-9A-Za-z]{30,}\b"#, "[REDACTED]"),
            // A JSON string field with a secret name keeps its key and quotes and loses its value.
            ("json-secret", #"(?i)("\#(secretName)"\s*+:\s*+")(?:[^"\\]|\\.)*+(")"#, "$1[REDACTED]$2"),
            // A JWT anywhere (header and payload are base64url JSON, so both start with `eyJ`).
            (
                "jwt", #"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]++\.eyJ[A-Za-z0-9_\-]++\.[A-Za-z0-9_\-]*+"#,
                "[REDACTED]"
            ),
            // `name=value` / `name: value` assignments (query strings, forms, config, YAML).
            (
                "api-key-assign", #"(?i)(\#(secretName)\s*+[=:]\s*+['"]?)[A-Za-z0-9._~+/\-]{8,}+=*+"#,
                "$1[REDACTED]"
            ),
        ]
        self.rules = rules.map { name, pattern, template in
            // The patterns are literals above; one that does not compile is a programming error.
            (name, try! NSRegularExpression(pattern: pattern), template)
        }
    }

    /// The result of redacting text.
    public struct Result: Sendable, Equatable {
        /// The text with secrets replaced by `[REDACTED]`.
        public var text: String
        /// How many masks were applied, by rule name.
        public var counts: [String: Int]
        /// How many masks were applied in all.
        public var total: Int { counts.values.reduce(0, +) }
    }

    /// Mask secrets in `text`. With `enabled == false`, returns the text unchanged.
    public func redact(_ text: String) -> Result {
        guard enabled else { return Result(text: text, counts: [:]) }
        var output = text
        var counts: [String: Int] = [:]
        for (name, regex, template) in rules {
            let range = NSRange(output.startIndex..., in: output)
            let matches = regex.numberOfMatches(in: output, range: range)
            guard matches > 0 else { continue }
            counts[name, default: 0] += matches
            output = regex.stringByReplacingMatches(in: output, range: range, withTemplate: template)
        }
        return Result(text: output, counts: counts)
    }
}
