// GulpScanner — Check Recipes (F08 §3.3, SCN-060/061/064): user-authored checks that detect issues
// without writing code, inspired by Nuclei/BChecks. A recipe is declarative data (metadata + a
// `when` condition + matchers + a templated issue), so a non-programmer can add a check and it runs
// in the scan alongside the built-ins. Recipes are JSON here (dependency-free, Codable); a thin YAML
// front-end is a documented future layer. This file covers passive recipes (run on each response);
// active recipes (templated probes) reuse the same matcher model and are a follow-on.
//
// This is a deliberate step past Burp: its Bambdas are Java snippets and BChecks need its own DSL;
// a declarative JSON/YAML recipe is accessible and shareable, and participates in scan configs.

import Foundation
import GulpCore

/// A matcher over a response (SCN-061). All present conditions must hold (AND); `any` is an OR group.
public struct RecipeMatcher: Sendable, Hashable, Codable {
    /// The response status must be one of these.
    public var statusIn: [Int]?
    /// The body must contain this substring.
    public var bodyContains: String?
    /// The body must NOT contain this substring.
    public var bodyAbsent: String?
    /// The body must match this regex.
    public var bodyRegex: String?
    /// A header that must be present (name).
    public var headerPresent: String?
    /// A header that must be absent (name).
    public var headerAbsent: String?
    /// `header: value-substring` — the named header must contain the value.
    public var headerContains: [String: String]?
    /// An OR group: at least one of these sub-matchers must hold.
    public var any: [RecipeMatcher]?

    /// A matcher; every condition defaults to absent (no constraint).
    public init(
        statusIn: [Int]? = nil, bodyContains: String? = nil, bodyAbsent: String? = nil,
        bodyRegex: String? = nil,
        headerPresent: String? = nil, headerAbsent: String? = nil, headerContains: [String: String]? = nil,
        any: [RecipeMatcher]? = nil
    ) {
        self.statusIn = statusIn
        self.bodyContains = bodyContains
        self.bodyAbsent = bodyAbsent
        self.bodyRegex = bodyRegex
        self.headerPresent = headerPresent
        self.headerAbsent = headerAbsent
        self.headerContains = headerContains
        self.any = any
    }

    /// Whether this matcher holds for `message`.
    func matches(_ message: PassiveMessage) -> Bool {
        if let statusIn, !statusIn.contains(message.status) { return false }
        if let bodyContains, !message.body.contains(bodyContains) { return false }
        if let bodyAbsent, message.body.contains(bodyAbsent) { return false }
        if let bodyRegex,
            (try? NSRegularExpression(pattern: bodyRegex))?.firstMatch(
                in: message.body, range: NSRange(message.body.startIndex..., in: message.body)) == nil
        {
            return false
        }
        if let headerPresent, message.header(headerPresent) == nil { return false }
        if let headerAbsent, message.header(headerAbsent) != nil { return false }
        if let headerContains {
            for (name, value) in headerContains where message.header(name)?.contains(value) != true {
                return false
            }
        }
        if let any, !any.isEmpty, !any.contains(where: { $0.matches(message) }) { return false }
        return true
    }
}

/// A user-authored check (SCN-060/061).
public struct CheckRecipe: Sendable, Hashable, Codable, Identifiable {
    /// Stable id (`recipe.<slug>`); the issue's type id.
    public var id: String
    /// Display name.
    public var name: String
    /// Severity (info/low/medium/high).
    public var severity: IssueSeverity
    /// Confidence.
    public var confidence: IssueConfidence
    /// Only run on in-scope responses whose path contains this (empty: any).
    public var pathContains: String?
    /// Only run when the content-type contains this (e.g. `html`, `json`; empty: any).
    public var contentType: String?
    /// The passive matcher that fires the issue.
    public var match: RecipeMatcher
    /// Templated issue detail. `{{header:Name}}` is replaced with that response header's value.
    public var detail: String
    /// Optional background text for the issue.
    public var background: String?
    /// Optional remediation text for the issue.
    public var remediation: String?
    /// Optional references for the issue.
    public var references: String?

    /// A recipe; severity defaults to `.info` and confidence to `.firm`.
    public init(
        id: String, name: String, severity: IssueSeverity = .info, confidence: IssueConfidence = .firm,
        pathContains: String? = nil, contentType: String? = nil, match: RecipeMatcher, detail: String,
        background: String? = nil, remediation: String? = nil, references: String? = nil
    ) {
        self.id = id
        self.name = name
        self.severity = severity
        self.confidence = confidence
        self.pathContains = pathContains
        self.contentType = contentType
        self.match = match
        self.detail = detail
        self.background = background
        self.remediation = remediation
        self.references = references
    }

    /// Evaluate the recipe against a response; returns a finding when it matches.
    func evaluate(_ message: PassiveMessage) -> IssueFinding? {
        if let pathContains, !message.path.contains(pathContains) { return nil }
        if let contentType, !message.mime.contains(contentType) { return nil }
        guard match.matches(message) else { return nil }
        let detail = expand(self.detail, message)
        return IssueFinding(
            typeID: id, name: name, severity: severity, confidence: confidence, host: message.origin,
            path: message.path, insertionPoint: nil, variant: "", detail: detail,
            background: background ?? "", remediation: remediation ?? "", references: references ?? "",
            evidence: IssueEvidence(exchangeID: message.exchange.id))
    }

    /// Replace `{{header:Name}}` tokens with the response's header values.
    func expand(_ template: String, _ message: PassiveMessage) -> String {
        var result = template
        while let open = result.range(of: "{{header:") {
            guard let close = result[open.upperBound...].firstIndex(of: "}") else { break }
            // the token is `{{header:Name}}` — the closing `}}`; find the first `}` then skip two.
            let name = String(result[open.upperBound..<close])
            let value = message.header(name) ?? ""
            let endIndex = result.index(close, offsetBy: 2, limitedBy: result.endIndex) ?? result.endIndex
            result.replaceSubrange(open.lowerBound..<endIndex, with: value)
        }
        return result
    }
}

/// Loads and runs Check Recipes (SCN-064: they join the scan like built-in checks).
public enum CheckRecipes {
    /// Decode recipes from JSON data (one recipe object, or an array).
    public static func decode(_ data: Data) throws -> [CheckRecipe] {
        let decoder = JSONDecoder()
        if let array = try? decoder.decode([CheckRecipe].self, from: data) { return array }
        return [try decoder.decode(CheckRecipe.self, from: data)]
    }

    /// Run `recipes` against a response (first match per recipe id).
    public static func scan(_ recipes: [CheckRecipe], _ message: PassiveMessage) -> [IssueFinding] {
        recipes.compactMap { $0.evaluate(message) }
    }
}
