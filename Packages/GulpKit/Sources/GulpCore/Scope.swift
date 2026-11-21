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

    enum CodingKeys: String, CodingKey {
        case id, kind, enabled, scheme, host, hostIsRegex, port, path
    }

    /// Decode a rule, filling in defaults for anything left out (hand-written scope files, TGT-025):
    /// a new id, include, enabled, any scheme, an exact host, any port, any path. Only `host` is
    /// required.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        kind = try c.decodeIfPresent(Kind.self, forKey: .kind) ?? .include
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        scheme = try c.decodeIfPresent(Scheme.self, forKey: .scheme) ?? .any
        host = try c.decode(String.self, forKey: .host)
        hostIsRegex = try c.decodeIfPresent(Bool.self, forKey: .hostIsRegex) ?? false
        port = try c.decodeIfPresent(String.self, forKey: .port) ?? ""
        path = try c.decodeIfPresent(String.self, forKey: .path) ?? ""
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

/// A scope file (TGT-025): `{"format": "gulp-scope", "version": 1, "rules": [...]}`.
public struct ScopeFile: Sendable, Codable, Hashable {
    /// Always `gulp-scope`.
    public var format = "gulp-scope"
    /// The file format version.
    public var version = 1
    /// The rules, in order.
    public var rules: [ScopeRule]

    /// A file holding `rules`.
    public init(rules: [ScopeRule]) {
        self.rules = rules
    }

    /// `rules` as pretty-printed JSON.
    public static func export(_ rules: [ScopeRule]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(ScopeFile(rules: rules))
    }

    /// The rules in `data`: a scope file or a bare array of rules. Throws a readable `GulpError`
    /// for anything else, or for a rule whose regex can't be used.
    public static func `import`(_ data: Data) throws -> [ScopeRule] {
        let decoder = JSONDecoder()
        let rules: [ScopeRule]
        if let file = try? decoder.decode(ScopeFile.self, from: data) {
            guard file.format == "gulp-scope" else {
                throw GulpError(message: "Not a Gulp scope file (format \"\(file.format)\").")
            }
            rules = file.rules
        } else if let bare = try? decoder.decode([ScopeRule].self, from: data) {
            rules = bare
        } else {
            throw GulpError(
                message: "Not a scope file: expected {\"rules\": [...]} with a host in every rule.")
        }
        for (index, rule) in rules.enumerated() {
            for pattern in [rule.hostIsRegex ? rule.host : "", rule.path] {
                if let problem = ScopeRule.problem(with: pattern) {
                    throw GulpError(message: "Rule \(index + 1): \(problem)")
                }
            }
        }
        return rules
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

    /// The path and query of an absolute URL, as `isInScope` takes it (`/` if it has none; the
    /// fragment dropped).
    public static func requestPath(ofURL url: String) -> String {
        guard let schemeEnd = url.range(of: "://") else { return "/" }
        let rest = url[schemeEnd.upperBound...]
        guard let start = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) else { return "/" }
        let tail = String(rest[start...].prefix { $0 != "#" })
        return tail.isEmpty ? "/" : (tail.hasPrefix("?") ? "/" + tail : tail)
    }

    /// The path and query of a raw request to `target`, as `isInScope` takes it (`/` if it has none).
    /// Every scope check of a request derives its path here.
    public static func requestPath(of request: RawRequest, target: HTTPTarget) -> String {
        let derived = DerivedFields(target: target, request: request, response: nil)
        return (derived.path ?? "/") + (derived.query.map { "?" + $0 } ?? "")
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

    /// A refusal of `target`/`path`.
    public init(target: HTTPTarget, path: String) {
        self.target = target
        self.path = path
    }
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

    /// Whether `target`/`path` is in scope by the rules. This is what active tools check; the
    /// "don't ask again" hosts don't widen it.
    public func permits(_ target: HTTPTarget, path: String) -> Bool {
        service.isInScope(target, path: path)
    }

    /// Whether a manual send (e.g. Repeater) to `target`/`path` goes without asking: in scope, or
    /// its host was allowed with "don't ask again".
    public func permitsManualSend(_ target: HTTPTarget, path: String) -> Bool {
        permits(target, path: path) || allowedHosts.contains(target.host.lowercased())
    }

    /// Throw `OutOfScope` for an out-of-scope target unless `override` (an explicit per-action
    /// choice) is set.
    public func require(_ target: HTTPTarget, path: String, override: Bool = false) throws {
        guard override || permits(target, path: path) else { throw OutOfScope(target: target, path: path) }
    }

    /// "Don't ask again for this host" (TGT-023): manual sends to it stop prompting
    /// (`permitsManualSend`). Active tools still check the rules only (`permits`, `require`).
    public func allowWithoutAsking(host: String) {
        allowedHosts.insert(host.lowercased())
    }
}
