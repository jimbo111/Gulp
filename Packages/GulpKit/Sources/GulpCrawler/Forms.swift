// GulpCrawler — form submission (F09 CRL-004) and robots/sitemap hints (CRL-005). Forms are filled
// with safe, plausible values chosen by field name and type; GET forms are submitted by default,
// POST forms only in "submit forms" mode, and never a form (or link) that looks destructive.

import Foundation
import GulpCore

/// Which forms the crawler submits (CRL-004).
public enum FormPolicy: String, Sendable, Codable, Hashable, CaseIterable {
    /// Discover forms but submit none.
    case none
    /// Submit GET forms (default).
    case get
    /// Submit GET and POST forms ("submit forms" mode; the UI confirms it).
    case all
}

/// Field-name heuristics and the destructive-action guard.
public struct FormFiller: Sendable, Codable, Hashable {
    /// `name` pattern (case-insensitive regex) → value, checked in order before the type defaults.
    public var rules: [Rule]
    /// Never submit forms (or follow links) whose action, path, field names or button values match
    /// this pattern (case-insensitive regex).
    public var neverSubmit: String

    /// One name → value rule.
    public struct Rule: Sendable, Codable, Hashable {
        /// Regex on the field name.
        public var pattern: String
        /// The value.
        public var value: String

        /// A rule.
        public init(_ pattern: String, _ value: String) {
            self.pattern = pattern
            self.value = value
        }
    }

    /// The default heuristics.
    public init(
        rules: [Rule] = [
            Rule("e-?mail", "gulp@example.com"), Rule("pass", "Gulp-Test-1!"), Rule("user|login", "gulp"),
            Rule("phone|tel|mobile", "5555550100"), Rule("zip|postal", "10001"),
            Rule("url|website|homepage", "https://example.com"),
            Rule("date", "2026-01-01"),
            Rule(#"^(age|qty|quantity|count|amount|number|num|id|page|limit)$|[_-](id|num|count|qty)$"#, "1"),
            Rule("name", "Gulp"), Rule("search|query|^q$|term", "gulp"),
        ],
        neverSubmit: String =
            #"log-?out|sign-?out|delete|remove|destroy|drop|deactivate|unsubscribe|reset|cancel-account"#
    ) {
        self.rules = rules
        self.neverSubmit = neverSubmit
    }

    /// Whether `text` (a URL, action or button value) looks destructive.
    public func isDestructive(_ text: String) -> Bool {
        !neverSubmit.isEmpty
            && text.range(of: neverSubmit, options: [.regularExpression, .caseInsensitive]) != nil
    }

    /// Whether the policy allows submitting `form` and it doesn't look destructive.
    public func shouldSubmit(_ form: HTMLForm, policy: FormPolicy) -> Bool {
        switch policy {
        case .none: return false
        case .get: if form.method != "GET" { return false }
        case .all: if form.method != "GET" && form.method != "POST" { return false }
        }
        if form.enctype.contains("multipart") { return false }  // file uploads: not in static mode
        if isDestructive(form.action) { return false }
        return !form.fields.contains {
            isDestructive($0.name) || ($0.type == "submit" && isDestructive($0.value))
        }
    }

    /// Name/value pairs to submit: hidden and preset values are kept, empty inputs filled by the
    /// rules or the type default, checked checkboxes/radios only, the first submit button.
    public func values(for form: HTMLForm) -> [(name: String, value: String)] {
        var pairs: [(name: String, value: String)] = []
        var radioDone: Set<String> = []
        var submitted = false
        for field in form.fields {
            switch field.type {
            case "submit", "image":
                if !submitted {
                    pairs.append((field.name, field.value))
                    submitted = true
                }
            case "reset", "button", "file": continue
            case "checkbox":
                if field.checked { pairs.append((field.name, field.value.isEmpty ? "on" : field.value)) }
            case "radio":
                if field.checked || !radioDone.contains(field.name) {
                    if radioDone.insert(field.name).inserted { pairs.append((field.name, field.value)) }
                }
            case "hidden":
                pairs.append((field.name, field.value))
            default:
                pairs.append((field.name, field.value.isEmpty ? fill(field) : field.value))
            }
        }
        return pairs
    }

    func fill(_ field: FormField) -> String {
        for rule in rules
        where field.name.range(of: rule.pattern, options: [.regularExpression, .caseInsensitive]) != nil {
            return rule.value
        }
        switch field.type {
        case "email": return "gulp@example.com"
        case "password": return "Gulp-Test-1!"
        case "number", "range": return "1"
        case "tel": return "5555550100"
        case "url": return "https://example.com"
        case "date": return "2026-01-01"
        case "color": return "#336699"
        default: return "gulp"
        }
    }

    /// `pairs` as an `application/x-www-form-urlencoded` string.
    public static func encode(_ pairs: [(name: String, value: String)]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        func escape(_ text: String) -> String {
            (text.addingPercentEncoding(withAllowedCharacters: allowed) ?? text).replacingOccurrences(
                of: "%20", with: "+")
        }
        return pairs.map { escape($0.name) + "=" + escape($0.value) }.joined(separator: "&")
    }
}

/// `robots.txt` hints (CRL-005): every `Allow`/`Disallow` path (as URLs to try) and `Sitemap:` URLs.
public struct RobotsHints: Sendable, Hashable {
    /// Paths named in `Disallow` lines (for every user agent).
    public var disallowed: [String] = []
    /// Paths named in `Allow` lines.
    public var allowed: [String] = []
    /// Sitemap URLs.
    public var sitemaps: [String] = []

    /// Parse a robots.txt body.
    public init(_ text: String) {
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line =
                rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? ""
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty else { continue }
            switch key {
            case "disallow": disallowed.append(value)
            case "allow": allowed.append(value)
            case "sitemap": sitemaps.append(value)
            default: break
            }
        }
    }

    /// Whether `path` falls under a `Disallow` rule (prefix match; `*` and `$` wildcards; a longer
    /// `Allow` wins).
    public func disallows(_ path: String) -> Bool {
        func length(matching rules: [String]) -> Int {
            rules.filter { Self.matches($0, path) }.map(\.count).max() ?? -1
        }
        let deny = length(matching: disallowed)
        return deny >= 0 && deny > length(matching: allowed)
    }

    static func matches(_ rule: String, _ path: String) -> Bool {
        if !rule.contains("*") && !rule.hasSuffix("$") { return path.hasPrefix(rule) }
        var pattern =
            "^" + NSRegularExpression.escapedPattern(for: rule).replacingOccurrences(of: "\\*", with: ".*")
        if pattern.hasSuffix("\\$") { pattern = String(pattern.dropLast(2)) + "$" }
        return path.range(of: pattern, options: .regularExpression) != nil
    }

    /// Paths worth trying (wildcard-free `Allow`/`Disallow` values).
    public var hintPaths: [String] {
        (allowed + disallowed).filter { $0.hasPrefix("/") && !$0.contains("*") && !$0.contains("$") }
    }
}
