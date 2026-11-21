// GulpWorkspace — the session layer wired into the engine (F15 M12a). `SessionState` holds the
// project's identities, rules, macros and the active identity's cookie jar plus per-origin DPoP
// nonces and access token. Three engine hooks use it:
//
//   SessionRequestHook   (registered first)  — for in-scope rules: ensure the session is valid
//                                               (single-flight login-macro re-auth), attach cookies,
//                                               set/remove headers and params, follow tokens.
//   SessionResponseHook  (response side)      — store Set-Cookie into the jar, remember a DPoP-Nonce,
//                                               and mark the session stale when the validity check fails.
//   SessionSignerHook    (registered last)    — sign in-scope requests after every other hook and the
//                                               Content-Length fixer, so the signature covers the sent
//                                               bytes (SES-016…018).
//
// Config (identities/rules/macros) persists as a SettingsGroup; the active identity's cookies and the
// captured variables are live state. Its secrets (signing keys, identity credentials, macro steps)
// are kept in the environment's secret store, not the project file (SessionSecrets.swift); the
// state here always holds them resolved.

import Foundation
import GulpCore
import GulpHTTP
import GulpSession

/// Persistent session configuration (SES-001…SES-023), stored with the project.
public struct SessionSettings: SettingsGroup, Hashable {
    /// Storage key.
    public static let key = "sessions"
    /// No identities, rules or macros.
    public static let defaultValue = SessionSettings()

    /// Identities (the active one is `activeIdentity`, else the first).
    public var identities: [Identity]
    /// Ordered session rules.
    public var rules: [SessionRule]
    /// Macros by id.
    public var macros: [Macro]
    /// The active identity's id.
    public var activeIdentity: UUID?
    /// Identities and macros whose credentials or steps are in the secret store and not loaded
    /// here: id (`uuidString`) → secret name (SessionSecrets.swift).
    var credentialRefs: [String: String] = [:]

    /// Session settings.
    public init(
        identities: [Identity] = [], rules: [SessionRule] = [], macros: [Macro] = [],
        activeIdentity: UUID? = nil
    ) {
        self.identities = identities
        self.rules = rules
        self.macros = macros
        self.activeIdentity = activeIdentity
    }

    private enum CodingKeys: String, CodingKey {
        case identities, rules, macros, activeIdentity, credentialRefs
    }

    /// Decode, accepting settings saved before credentials moved to the secret store.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        identities = try container.decode([Identity].self, forKey: .identities)
        rules = try container.decode([SessionRule].self, forKey: .rules)
        macros = try container.decode([Macro].self, forKey: .macros)
        activeIdentity = try container.decodeIfPresent(UUID.self, forKey: .activeIdentity)
        credentialRefs = try container.decodeIfPresent([String: String].self, forKey: .credentialRefs) ?? [:]
    }
}

/// Live session state shared by the hooks (SES-010…SES-018).
public actor SessionState {
    private var identities: [UUID: Identity]
    private var identityOrder: [UUID]
    private var rules: [SessionRule]
    private var macros: [UUID: Macro]
    private var activeID: UUID?
    /// Per-origin latest DPoP-Nonce (RFC 9449).
    private var dpopNonces: [String: String] = [:]
    /// Origins whose session is known stale (need re-auth before the next in-scope send).
    private var stale: Set<UUID> = []
    /// One in-flight re-auth per identity (single-flight, SES edge case).
    private var reauthTasks: [UUID: Task<Void, Never>] = [:]
    /// Sends a macro's request (set by the service once the engine exists).
    private var sender: MacroSender?
    private let log: @Sendable (String) -> Void

    /// Build from settings.
    public init(_ settings: SessionSettings, log: @escaping @Sendable (String) -> Void = { _ in }) {
        identities = Dictionary(uniqueKeysWithValues: settings.identities.map { ($0.id, $0) })
        identityOrder = settings.identities.map(\.id)
        rules = settings.rules
        macros = Dictionary(uniqueKeysWithValues: settings.macros.map { ($0.id, $0) })
        activeID = settings.activeIdentity ?? settings.identities.first?.id
        self.log = log
    }

    /// Replace the config (after an edit).
    public func update(_ settings: SessionSettings) {
        let previous = identities
        identities = Dictionary(uniqueKeysWithValues: settings.identities.map { ($0.id, $0) })
        // Keep live captured variables and cookies across a config edit.
        for id in identities.keys {
            if let old = previous[id] {
                identities[id]?.captured = old.captured
                identities[id]?.cookies = old.cookies
            }
        }
        identityOrder = settings.identities.map(\.id)
        rules = settings.rules
        macros = Dictionary(uniqueKeysWithValues: settings.macros.map { ($0.id, $0) })
        activeID = settings.activeIdentity ?? identityOrder.first
    }

    func setSender(_ sender: @escaping MacroSender) { self.sender = sender }

    func identity(_ id: UUID?) -> Identity? {
        if let id { return identities[id] }
        if let activeID { return identities[activeID] }
        return identityOrder.first.flatMap { identities[$0] }
    }

    func activeIdentityID() -> UUID? { activeID ?? identityOrder.first }

    /// Set the active identity (SES-002, "as user-B").
    public func setActive(_ id: UUID?) { activeID = id }

    /// A snapshot of an identity's cookies (for the CLI/UI and tests).
    public func cookies(of id: UUID? = nil) -> CookieJar { identity(id)?.cookies ?? CookieJar() }

    /// The rules that apply to a send, newest-config order.
    func matchingRules(source: ToolSource, target: HTTPTarget, path: String) -> [SessionRule] {
        rules.filter { $0.enabled && $0.scope.matches(source: source, target: target, path: path) }
    }

    /// Prepare an in-scope request: re-auth if stale, then apply the rules' non-network actions.
    func prepare(_ request: RawRequest, target: HTTPTarget, source: ToolSource) async -> RawRequest {
        let path = request.bytes[request.parsed.target].string()
        let applicable = matchingRules(source: source, target: target, path: path)
        guard !applicable.isEmpty else { return request }
        var request = request
        for rule in applicable {
            let identityID = rule.identity ?? activeID
            // Validity + macro re-auth (single-flight) before applying this rule's cookies.
            if rule.actions.contains(where: {
                if case .checkValidity = $0 { return true } else { return false }
            }),
                let id = identityID, stale.contains(id)
            {
                await reauthenticate(identity: id)
            }
            guard let identity = identity(identityID) else { continue }
            let (rewritten, entries) = RuleApplication.apply(
                rule.actions, to: request, target: target, identity: identity)
            request = rewritten
            // Run macro actions (SES-011) that aren't the login macro.
            for action in rule.actions {
                if case .runMacro(let macroID) = action { await runMacro(macroID, identity: identityID) }
            }
            if !entries.isEmpty { log("session rule \(rule.name): \(entries.joined(separator: ", "))") }
        }
        return request
    }

    /// The signing scheme and context for an in-scope request, if a rule asks for signing.
    func signing(source: ToolSource, target: HTTPTarget, path: String, origin: String) -> (
        SigningScheme, SigningContext
    )? {
        for rule in matchingRules(source: source, target: target, path: path) {
            for action in rule.actions {
                if case .sign(let scheme) = action {
                    let identity = identity(rule.identity ?? activeID)
                    let token = identity?.allVariables["access_token"]
                    return (scheme, SigningContext(accessToken: token, dpopNonce: dpopNonces[origin]))
                }
            }
        }
        return nil
    }

    /// Record a response: store cookies, remember a DPoP-Nonce, mark stale on validity failure.
    func observe(response: RawResponse, target: HTTPTarget, source: ToolSource, requestPath: String) {
        // A DPoP-Nonce is per origin, not per identity (SES-016), so capture it even with no identity.
        if let nonce = response.headerValue("dpop-nonce")?.string() {
            dpopNonces[Issue.origin(target)] = nonce
        }
        let identityID = activeID ?? identityOrder.first
        guard let identityID else { return }
        let setCookies = response.headerValues("set-cookie").map { $0.string() }
        if !setCookies.isEmpty {
            identities[identityID]?.cookies.store(setCookies: setCookies, from: target.host)
        }
        for rule in matchingRules(source: source, target: target, path: requestPath) {
            for action in rule.actions {
                if case .checkValidity(let check) = action, !check.isEmpty, !check.isValid(response) {
                    stale.insert(rule.identity ?? identityID)
                    log("session: \(target.host) looks logged out; will re-auth")
                }
            }
        }
    }

    /// Single-flight re-auth: run the identity's login macro once; concurrent callers await it.
    func reauthenticate(identity id: UUID) async {
        if let task = reauthTasks[id] { await task.value; return }
        guard let identity = identities[id], let macroID = identity.loginMacro, let macro = macros[macroID],
            let sender
        else {
            stale.remove(id)
            return
        }
        let task = Task { [sender] in
            let runner = MacroRunner(send: sender)
            let result = await runner.run(macro, variables: identity.variables, cookies: identity.cookies)
            await self.applyMacroResult(result, to: id)
        }
        reauthTasks[id] = task
        await task.value
        reauthTasks[id] = nil
        stale.remove(id)
    }

    func runMacro(_ macroID: UUID, identity id: UUID?) async {
        guard let macro = macros[macroID], let sender, let id = id ?? activeID, let identity = identities[id]
        else { return }
        let runner = MacroRunner(send: sender)
        let result = await runner.run(macro, variables: identity.allVariables, cookies: identity.cookies)
        applyMacroResult(result, to: id)
    }

    func applyMacroResult(_ result: MacroResult, to id: UUID) {
        identities[id]?.cookies = result.cookies
        for (name, value) in result.variables { identities[id]?.captured[name] = value }
        log("macro: \(result.log.last ?? "done")")
    }

    /// Force the session stale (tests/CLI).
    public func markStale(_ id: UUID? = nil) {
        if let target = id ?? activeID { stale.insert(target) }
    }
}
