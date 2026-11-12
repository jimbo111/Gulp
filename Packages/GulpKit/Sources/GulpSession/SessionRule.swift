// GulpSession — session handling rules (F15 SES-010/011). An ordered list of rules, each with a
// scope (which tools, which hosts/paths) and an ordered list of actions applied to every matching
// request: attach jar cookies, set/remove headers or params, add an identity's headers, follow a
// token captured earlier, run a macro, or sign the request. Rules run as the engine's request hook;
// a response hook marks the session stale when the validity check fails so the next request re-auths
// (that control flow lives in SessionEngine). GulpQL-based scope conditions are evaluated one layer
// up (the workspace), which narrows traffic before it reaches the hook; here scope is tool set plus
// host/path matching, which is self-contained and Linux-testable.

import Foundation
import GulpCore
import GulpHTTP

/// Which requests a rule applies to (SES-010).
public struct RuleScope: Sendable, Hashable, Codable {
    /// Tools the rule runs for (empty: every tool).
    public var tools: Set<ToolSource>
    /// Host glob (`*.example.com`, `example.com`, `*`); empty or `*` matches any host.
    public var hostGlob: String
    /// Path prefix the request target must start with (empty: any path).
    public var pathPrefix: String

    /// A scope.
    public init(tools: Set<ToolSource> = [], hostGlob: String = "*", pathPrefix: String = "") {
        self.tools = tools
        self.hostGlob = hostGlob
        self.pathPrefix = pathPrefix
    }

    /// Whether a request to `target`/`path` from `source` is in scope.
    public func matches(source: ToolSource, target: HTTPTarget, path: String) -> Bool {
        if !tools.isEmpty, !tools.contains(source) { return false }
        if !pathPrefix.isEmpty, !path.hasPrefix(pathPrefix) { return false }
        return Self.hostMatches(hostGlob, target.host)
    }

    static func hostMatches(_ glob: String, _ host: String) -> Bool {
        let glob = glob.lowercased()
        let host = host.lowercased()
        if glob.isEmpty || glob == "*" { return true }
        if glob.hasPrefix("*.") {
            return host == String(glob.dropFirst(2)) || host.hasSuffix(String(glob.dropFirst(1)))
        }
        return host == glob
    }
}

/// One action a rule takes on a matching request (SES-011).
public enum SessionAction: Sendable, Hashable, Codable {
    /// Attach the identity's jar cookies for this host/path.
    case useCookies
    /// Add the identity's static headers.
    case useIdentityHeaders
    /// Set (replace or add) a header.
    case setHeader(name: String, value: String)
    /// Remove a header.
    case removeHeader(name: String)
    /// Set or add a URL query parameter.
    case setParam(name: String, value: String)
    /// Substitute a captured variable into a header or param by name (SES-013 token following).
    case followToken(variable: String, into: TokenTarget)
    /// Check the session's validity on the response and re-auth with the identity's login macro when
    /// it fails (SES-012); the retry is handled by the engine.
    case checkValidity(ValidityCheck)
    /// Run a macro and keep its captured variables and cookies (SES-011).
    case runMacro(UUID)
    /// Sign the request (runs last; SES-016…018).
    case sign(SigningScheme)

    /// Where a followed token is written.
    public enum TokenTarget: Sendable, Hashable, Codable {
        /// A request header.
        case header(String)
        /// A URL query parameter.
        case param(String)
    }
}

/// A session rule (SES-010).
public struct SessionRule: Sendable, Hashable, Codable, Identifiable {
    /// Stable id.
    public var id: UUID
    /// Display name.
    public var name: String
    /// Enabled.
    public var enabled: Bool
    /// What it applies to.
    public var scope: RuleScope
    /// The identity whose cookies/headers/login it uses (nil: the active identity).
    public var identity: UUID?
    /// Ordered actions.
    public var actions: [SessionAction]

    /// A rule.
    public init(
        id: UUID = UUID(), name: String, enabled: Bool = true, scope: RuleScope = RuleScope(),
        identity: UUID? = nil, actions: [SessionAction] = []
    ) {
        self.id = id
        self.name = name
        self.enabled = enabled
        self.scope = scope
        self.identity = identity
        self.actions = actions
    }
}

/// Applies a rule's non-signing, non-macro actions to a request (the parts that need no network).
/// Returns the rewritten request and a log of what changed (SES-015).
public enum RuleApplication {
    /// Apply `actions` to `request` going to `target`, using `identity`'s cookies/headers/variables.
    public static func apply(
        _ actions: [SessionAction], to request: RawRequest, target: HTTPTarget, identity: Identity,
        now: Date = Date()
    ) -> (request: RawRequest, log: [String]) {
        var request = request
        var log: [String] = []
        let path = request.bytes[request.parsed.target].string()
        for action in actions {
            switch action {
            case .useCookies:
                if let cookie = identity.cookies.header(
                    host: target.host, path: path, scheme: target.scheme, now: now)
                {
                    request = request.settingHeader("Cookie", to: cookie)
                    log.append("attached cookies")
                }
            case .useIdentityHeaders:
                for (name, value) in identity.headers.sorted(by: { $0.key < $1.key }) {
                    request = request.settingHeader(
                        name, to: VariableExpansion.expand(value, identity.allVariables))
                }
                if !identity.headers.isEmpty {
                    log.append("added \(identity.headers.count) identity header(s)")
                }
            case .setHeader(let name, let value):
                request = request.settingHeader(
                    name, to: VariableExpansion.expand(value, identity.allVariables))
                log.append("set \(name)")
            case .removeHeader(let name):
                request = request.removingHeader(name)
                log.append("removed \(name)")
            case .setParam(let name, let value):
                request = request.settingQueryParameter(
                    name, to: VariableExpansion.expand(value, identity.allVariables))
                log.append("set param \(name)")
            case .followToken(let variable, let into):
                guard let value = identity.allVariables[variable] else {
                    log.append("token \(variable) not captured yet")
                    continue
                }
                switch into {
                case .header(let name): request = request.settingHeader(name, to: value)
                case .param(let name): request = request.settingQueryParameter(name, to: value)
                }
                log.append("followed \(variable)")
            case .checkValidity, .runMacro, .sign:
                break  // handled by the engine (need the network / the final bytes)
            }
        }
        return (request, log)
    }
}
