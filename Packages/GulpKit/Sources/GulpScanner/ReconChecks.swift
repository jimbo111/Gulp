// GulpScanner — passive secret & JavaScript-endpoint recon (F27, M19 first increment). Every
// in-scope response and every JavaScript file is scanned for credentials (a curated ruleset plus a
// high-entropy fallback for generic `key = "…"` assignments) and, in JavaScript, for hard-coded API
// endpoints. Findings become `recon.secret` / `recon.endpoint` issues. Burp only does this through
// extensions; here it is always-on and tested. Nothing is sent — it reads responses the proxy
// already captured.

import Foundation
import GulpCore

/// A credential pattern: a name, a regex, and whether the match itself is high-entropy enough to
/// trust without further checks (prefixed vendor tokens are trustworthy; generic ones need entropy).
struct SecretRule: Sendable {
    let name: String
    let regex: NSRegularExpression
    /// The capture group holding the secret value (0 = whole match).
    let group: Int
    /// Require the captured value to clear the entropy bar (for generic assignments).
    let needsEntropy: Bool

    init?(_ name: String, _ pattern: String, group: Int = 0, needsEntropy: Bool = false) {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return nil
        }
        self.name = name
        self.regex = regex
        self.group = group
        self.needsEntropy = needsEntropy
    }
}

/// Passive recon checks (F27).
public enum ReconChecks {
    /// The credential ruleset. Vendor-prefixed tokens are matched exactly; the last rule is a
    /// generic high-entropy assignment caught only when the value's entropy is high.
    static let secretRules: [SecretRule] = [
        SecretRule("AWS access key id", #"\bAKIA[0-9A-Z]{16}\b"#),
        SecretRule("AWS secret access key", #"aws_secret_access_key["' :=]+([A-Za-z0-9/+]{40})"#, group: 1),
        SecretRule("Google API key", #"\bAIza[0-9A-Za-z\-_]{35}\b"#),
        SecretRule("GitHub token", #"\bgh[pousr]_[0-9A-Za-z]{36,}\b"#),
        SecretRule("GitLab token", #"\bglpat-[0-9A-Za-z\-_]{20}\b"#),
        SecretRule("Slack token", #"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"#),
        SecretRule("Stripe secret key", #"\b[sr]k_live_[0-9A-Za-z]{24,}\b"#),
        SecretRule("Twilio key", #"\bSK[0-9a-fA-F]{32}\b"#),
        SecretRule("Private key block", #"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"#),
        SecretRule("JSON Web Token", #"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"#),
        SecretRule(
            "High-entropy secret",
            #"(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|access[_-]?token)["' :=]{1,4}["']([A-Za-z0-9/+_\-]{16,})["']"#,
            group: 1, needsEntropy: true),
    ].compactMap { $0 }

    /// Endpoint patterns found in JavaScript (fetch/axios/XHR URLs and path-like string literals).
    static let endpointRules: [NSRegularExpression] = [
        #"(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\(\s*["'`]([^"'`]+)["'`]"#,
        #"["'`](/(?:api|v\d|graphql|rest|internal|admin)/[A-Za-z0-9/_\-.{}:]*)["'`]"#,
        #"(?:url|endpoint|path|uri)\s*[:=]\s*["'`]([^"'`\s]{2,})["'`]"#,
    ].compactMap { try? NSRegularExpression(pattern: $0, options: [.caseInsensitive]) }

    /// Shannon entropy (bits per character) of a string.
    static func entropy(_ text: String) -> Double {
        guard !text.isEmpty else { return 0 }
        var counts: [Character: Int] = [:]
        for character in text { counts[character, default: 0] += 1 }
        let length = Double(text.count)
        return counts.values.reduce(0.0) { sum, count in
            let p = Double(count) / length
            return sum - p * log2(p)
        }
    }

    /// Whether `value` looks like a real secret: long enough and high-entropy, not a repeated/obvious
    /// placeholder.
    static func looksSecret(_ value: String) -> Bool {
        guard value.count >= 16 else { return false }
        let lower = value.lowercased()
        for placeholder in [
            "example", "changeme", "your_", "xxxx", "placeholder", "redacted", "0000", "test",
        ] {
            if lower.contains(placeholder) { return false }
        }
        return entropy(value) >= 3.5
    }

    /// Scan a response message for secrets and (for JavaScript) endpoints.
    static func scan(_ message: PassiveMessage) -> [IssueFinding] {
        let isJS = message.mime.contains("javascript") || message.path.hasSuffix(".js")
        // Only scan textual bodies; skip images/binaries.
        guard isJS || message.mime.contains("text") || message.mime.contains("json") || message.isHTML else {
            return []
        }
        let body = message.body
        guard body.count < 2_000_000 else { return [] }  // skip huge bundles
        var findings: [IssueFinding] = []
        var seen: Set<String> = []

        for rule in secretRules {
            let range = NSRange(body.startIndex..., in: body)
            for match in rule.regex.matches(in: body, range: range) {
                guard let valueRange = Range(match.range(at: rule.group), in: body) else { continue }
                let value = String(body[valueRange])
                if rule.needsEntropy, !looksSecret(value) { continue }
                guard seen.insert(value).inserted else { continue }
                let redacted = value.count > 12 ? "\(value.prefix(4))…\(value.suffix(4))" : value
                findings.append(
                    message.finding(
                        PassiveChecks.d("recon.secret"), variant: rule.name,
                        detail: "A response contains what looks like a **\(rule.name)** (`\(redacted)`).",
                        responseMarkers: message.bodyMarker(value).map { [$0] } ?? []))
                if findings.count >= 20 { break }
            }
        }

        if isJS {
            var endpoints: Set<String> = []
            for regex in endpointRules {
                let range = NSRange(body.startIndex..., in: body)
                for match in regex.matches(in: body, range: range) {
                    let groupIndex = match.numberOfRanges > 1 ? 1 : 0
                    guard let endpointRange = Range(match.range(at: groupIndex), in: body) else { continue }
                    let endpoint = String(body[endpointRange])
                    if endpoint.hasPrefix("/") || endpoint.hasPrefix("http") { endpoints.insert(endpoint) }
                }
            }
            if !endpoints.isEmpty {
                let list = endpoints.sorted().prefix(30).joined(separator: ", ")
                findings.append(
                    message.finding(
                        PassiveChecks.d("recon.endpoint"),
                        detail: "This JavaScript hard-codes \(endpoints.count) endpoint(s): \(list)."))
            }
        }
        return findings
    }
}
