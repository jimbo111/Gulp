// GulpAI — the redaction pipeline (F22 AI-003). Before anything leaves the app for the provider, mask
// secrets and obvious credentials so they are never sent. Redaction is on by default; the user sees a
// preview and can edit or cancel. Pure string work, so it is fully tested.

import Foundation

/// Masks secrets in text destined for an LLM provider.
public struct Redactor: Sendable {
    public var enabled: Bool
    private let rules: [(name: String, regex: NSRegularExpression)]

    /// The default rule set: auth headers, cookies, bearer tokens, common API keys and private keys.
    public init(enabled: Bool = true) {
        self.enabled = enabled
        let patterns: [(String, String)] = [
            ("authorization", #"(?im)^(authorization:\s*)(.+)$"#),
            ("cookie", #"(?im)^((?:set-)?cookie:\s*)(.+)$"#),
            ("bearer", #"(?i)\bBearer\s+[A-Za-z0-9._\-]{8,}"#),
            ("aws-key", #"\bAKIA[0-9A-Z]{16}\b"#),
            ("google-key", #"\bAIza[0-9A-Za-z_\-]{35}\b"#),
            ("slack", #"\bxox[baprs]-[0-9A-Za-z\-]{10,}"#),
            ("github", #"\bgh[pousr]_[0-9A-Za-z]{30,}\b"#),
            ("private-key", #"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"#),
            (
                "api-key-assign",
                #"(?i)(api[_\-]?key|secret|token|password)\s*[=:]\s*['\"]?[A-Za-z0-9._\-]{8,}"#
            ),
        ]
        rules = patterns.compactMap { name, pattern in
            (try? NSRegularExpression(pattern: pattern)).map { (name, $0) }
        }
    }

    /// The result of redacting text.
    public struct Result: Sendable, Equatable {
        public var text: String
        /// How many masks were applied, by rule name.
        public var counts: [String: Int]
        public var total: Int { counts.values.reduce(0, +) }
    }

    /// Mask secrets in `text`. With `enabled == false`, returns the text unchanged.
    public func redact(_ text: String) -> Result {
        guard enabled else { return Result(text: text, counts: [:]) }
        var output = text
        var counts: [String: Int] = [:]
        for (name, regex) in rules {
            let range = NSRange(output.startIndex..., in: output)
            let matches = regex.matches(in: output, range: range)
            guard !matches.isEmpty else { continue }
            counts[name, default: 0] += matches.count
            // Header rules keep the header name (group 1) and mask the value (group 2); others mask all.
            let template = regex.numberOfCaptureGroups >= 2 ? "$1[REDACTED]" : "[REDACTED]"
            output = regex.stringByReplacingMatches(in: output, range: range, withTemplate: template)
        }
        return Result(text: output, counts: counts)
    }
}
