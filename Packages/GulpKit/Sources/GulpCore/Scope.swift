// GulpCore — target scope (F04 TGT-020…TGT-023; ADR-011). Scope is an ordered list of include and
// exclude rules evaluated **last-match-wins**: walk the enabled rules top to bottom; the last one
// that matches decides; no match means out of scope (an empty rule set puts nothing in scope).
//
// `ScopeService` compiles the rules once and answers `isInScope` without allocation-heavy work, so
// the UI, the store's `in_scope` column and ScopeGuard can call it per request. User regexes are
// validated against the classic catastrophic-backtracking shape (a quantified group that itself
// ends in a quantifier, e.g. `(a+)+`), and matching only ever sees the host and the path.

import Foundation

/// The request scheme (`ScopeRule.Scheme` is the rule's scheme filter, which adds `any`).
private typealias RequestScheme = Scheme

/// One include or exclude rule (TGT-020).
public struct ScopeRule: Sendable, Codable, Hashable, Identifiable {
    /// Include or exclude.
    public enum Kind: String, Sendable, Codable, Hashable, CaseIterable {
        case include, exclude
    }

    /// Which schemes the rule covers.
    public enum Scheme: String, Sendable, Codable, Hashable, CaseIterable {
        case any, http, https
    }

    /// Stable identity.
    public var id: UUID
    /// Include or exclude.
    public var kind: Kind
    /// Whether the rule takes part.
    public var enabled: Bool
    /// http, https or any.
    public var scheme: Scheme
    /// The host: an exact name (case-insensitive; `*.example.com` also matches subdomains) or, with
    /// `hostIsRegex`, a regex matched against the whole host.
    public var host: String
    /// Whether `host` is a regex.
    public var hostIsRegex: Bool
    /// Port: empty = any, `443`, or a range `8000-8100`.
    public var port: String
    /// A regex matched anywhere in the path and query (anchor with `^`); empty = any path.
    public var path: String

    /// A rule.
    public init(
        id: UUID = UUID(), kind: Kind = .include, enabled: Bool = true, scheme: Scheme = .any,
        host: String, hostIsRegex: Bool = false, port: String = "", path: String = ""
    ) {
        self.id = id
        self.kind = kind
        self.enabled = enabled
        self.scheme = scheme
        self.host = host
        self.hostIsRegex = hostIsRegex
        self.port = port
        self.path = path
    }

    /// "Add to scope" for a URL (TGT-021 simple mode): the exact host, the URL's scheme, its port
    /// only when it isn't the scheme's default, and its path as a prefix (a bare `/` covers the
    /// whole host). Nil for something that isn't an http(s) URL.
    public static func include(url: String, kind: Kind = .include) -> ScopeRule? {
        guard let target = HTTPTarget(url: url) else { return nil }
        var path = "/"
        if let schemeEnd = url.range(of: "://") {
            let rest = url[schemeEnd.upperBound...]
            if let slash = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) {
                path = String(rest[slash...].prefix { $0 != "?" && $0 != "#" })
            }
        }
        if path.isEmpty { path = "/" }
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        let prefix =
            path == "/"
            ? "" : "^" + ScopeRule.escape(path.hasSuffix("/") ? String(path.dropLast()) : path) + "(/|$|\\?)"
        return ScopeRule(
            kind: kind, scheme: target.scheme == .https ? .https : .http, host: target.host.lowercased(),
            port: standard ? "" : String(target.port), path: prefix)
    }

    /// `text` with regex metacharacters escaped.
    public static func escape(_ text: String) -> String {
        let special = Set("\\^$.|?*+()[]{}")
        return text.map { special.contains($0) ? "\\\($0)" : String($0) }.joined()
    }

    /// Why `pattern` can't be used as a scope regex (invalid, or shaped for catastrophic
    /// backtracking), or nil if it's fine.
    public static func problem(with pattern: String) -> String? {
        guard !pattern.isEmpty else { return nil }
        do {
            _ = try NSRegularExpression(pattern: pattern)
        } catch {
            return "Not a valid regular expression."
        }
        // A quantified group whose body ends in a quantifier: (a+)+, (\w*)*, (x+y?){2,}, …
        let nested = try? NSRegularExpression(pattern: #"\([^()]*[+*}]\)[+*{]"#)
        let whole = NSRange(pattern.startIndex..., in: pattern)
        if nested?.firstMatch(in: pattern, range: whole) != nil {
            return "Nested quantifiers like (a+)+ can take exponential time; rewrite the pattern."
        }
        return nil
    }
}

/// A compiled scope (TGT-022). Immutable; build a new one when the rules change.
public struct ScopeService: Sendable {
    /// The rules, in order.
    public let rules: [ScopeRule]
    private let compiled: [CompiledScopeRule]

    /// Compile `rules`. A rule whose regex is unusable (see `ScopeRule.problem(with:)`) never
    /// matches.
    public init(rules: [ScopeRule] = []) {
        self.rules = rules
        compiled = rules.map(CompiledScopeRule.init)
    }

    /// Whether a request to `target` for `path` (path and query) is in scope.
    public func isInScope(_ target: HTTPTarget, path: String) -> Bool {
        decidingRule(for: target, path: path)?.kind == .include
    }

    /// The rule that decides `target`/`path` — the last enabled rule that matches — or nil (out).
    public func decidingRule(for target: HTTPTarget, path: String) -> ScopeRule? {
        let host = target.host.lowercased()
        let checkedPath = String(path.prefix(8_192))  // bound the work a pathological path can cause
        for (index, rule) in compiled.enumerated().reversed()
        where rule.matches(scheme: target.scheme, host: host, port: target.port, path: checkedPath) {
            return rules[index]
        }
        return nil
    }

    /// A readable summary (TGT-025), e.g. "In scope: https://example.com /app. Excluded: /logout".
    public var summary: String {
        let active = rules.filter(\.enabled)
        guard !active.isEmpty else { return "Nothing is in scope." }
        func describe(_ rule: ScopeRule) -> String {
            let scheme = rule.scheme == .any ? "" : "\(rule.scheme.rawValue)://"
            let port = rule.port.isEmpty ? "" : ":\(rule.port)"
            let path = rule.path.isEmpty ? "" : " path ~ \(rule.path)"
            return "\(scheme)\(rule.hostIsRegex ? "/\(rule.host)/" : rule.host)\(port)\(path)"
        }
        let included = active.filter { $0.kind == .include }.map(describe)
        let excluded = active.filter { $0.kind == .exclude }.map(describe)
        var parts: [String] = []
        if !included.isEmpty { parts.append("In scope: " + included.joined(separator: ", ")) }
        if !excluded.isEmpty { parts.append("Excluded: " + excluded.joined(separator: ", ")) }
        return parts.joined(separator: ". ")
    }
}

/// A rule ready to match.
// NSRegularExpression is immutable and documented thread-safe for matching; nothing here mutates
// after init, so sharing it across tasks is safe.
private final class CompiledScopeRule: @unchecked Sendable {
    let rule: ScopeRule
    let host: NSRegularExpression?
    let path: NSRegularExpression?
    let ports: ClosedRange<Int>?
    let usable: Bool

    init(_ rule: ScopeRule) {
        self.rule = rule
        var usable = rule.enabled
        if rule.hostIsRegex {
            if ScopeRule.problem(with: rule.host) != nil { usable = false }
            host = try? NSRegularExpression(pattern: "^(?:\(rule.host))$", options: [.caseInsensitive])
        } else {
            host = nil
        }
        if rule.path.isEmpty {
            path = nil
        } else {
            if ScopeRule.problem(with: rule.path) != nil { usable = false }
            path = try? NSRegularExpression(pattern: rule.path)
        }
        let bounds = rule.port.split(separator: "-").compactMap {
            Int($0.trimmingCharacters(in: .whitespaces))
        }
        if rule.port.trimmingCharacters(in: .whitespaces).isEmpty {
            ports = nil
        } else if bounds.count == 1 {
            ports = bounds[0]...bounds[0]
        } else if bounds.count == 2, bounds[0] <= bounds[1] {
            ports = bounds[0]...bounds[1]
        } else {
            ports = nil
            usable = false  // an unparseable port never matches
        }
        self.usable = usable && (!rule.hostIsRegex || host != nil) && (rule.path.isEmpty || path != nil)
    }

    func matches(scheme: RequestScheme, host candidate: String, port: Int, path candidatePath: String) -> Bool
    {
        guard usable else { return false }
        switch rule.scheme {
        case .any: break
        case .http: guard scheme == .http else { return false }
        case .https: guard scheme == .https else { return false }
        }
        if let ports, !ports.contains(port) { return false }
        if let host {
            let range = NSRange(candidate.startIndex..., in: candidate)
            guard host.firstMatch(in: candidate, range: range) != nil else { return false }
        } else {
            let pattern = rule.host.lowercased()
            if pattern.hasPrefix("*.") {
                let base = pattern.dropFirst(2)
                guard candidate == base || candidate.hasSuffix("." + base) else { return false }
            } else {
                guard candidate == pattern else { return false }
            }
        }
        if let path {
            let range = NSRange(candidatePath.startIndex..., in: candidatePath)
            guard path.firstMatch(in: candidatePath, range: range) != nil else { return false }
        }
        return true
    }
}

/// Raised by ScopeGuard (TGT-023).
public struct OutOfScope: Error, Sendable, Equatable {
    /// The refused target.
    public var target: HTTPTarget
    /// The refused path.
    public var path: String
}

/// ScopeGuard (TGT-023): active tools call `require` before they send. Out of scope throws
/// `OutOfScope` unless the action carries an explicit override (the UI's "Send anyway?").
public actor ScopeGuard {
    private var service: ScopeService
    private var allowedHosts: Set<String> = []

    /// A guard for `service`.
    public init(_ service: ScopeService = ScopeService()) {
        self.service = service
    }

    /// Use new rules.
    public func set(_ service: ScopeService) {
        self.service = service
    }

    /// The current scope.
    public var current: ScopeService { service }

    /// Whether `target`/`path` is in scope (or its host was allowed with "don't ask again").
    public func permits(_ target: HTTPTarget, path: String) -> Bool {
        service.isInScope(target, path: path) || allowedHosts.contains(target.host.lowercased())
    }

    /// Throw `OutOfScope` for an out-of-scope target unless `override` (an explicit per-action
    /// choice) is set.
    public func require(_ target: HTTPTarget, path: String, override: Bool = false) throws {
        guard override || permits(target, path: path) else { throw OutOfScope(target: target, path: path) }
    }

    /// "Don't ask again for this host" (TGT-023): manual sends to it stop prompting.
    public func allowWithoutAsking(host: String) {
        allowedHosts.insert(host.lowercased())
    }
}
