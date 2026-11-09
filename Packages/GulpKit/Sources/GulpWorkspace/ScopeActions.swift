// GulpWorkspace — scope for a project (F04 TGT-020…TGT-023): the rules live in the project file;
// changing them updates ScopeGuard and recomputes every row's `in_scope`.

import Foundation
import GulpCore
import GulpStore

extension ProjectSession {
    /// The current scope.
    public func scope() async -> ScopeService { await scopeGuard.current }

    /// Replace the scope rules (stored, applied to ScopeGuard and to every row's `in_scope`).
    public func setScope(_ rules: [ScopeRule]) async throws {
        let service = try await store.setScope(rules)
        await scopeGuard.set(service)
        await applyProxyScope()
    }

    /// "Add to scope" (TGT-021): an include rule for `url`'s host and path prefix, appended so it
    /// wins over earlier rules (last match wins). Returns the rule, or nil for a non-URL.
    @discardableResult
    public func addToScope(url: String) async throws -> ScopeRule? {
        guard let rule = ScopeRule.include(url: url) else { return nil }
        try await setScope(await scope().rules + [rule])
        return rule
    }

    /// "Remove from scope": an exclude rule for `url`, appended (it overrides earlier includes).
    @discardableResult
    public func excludeFromScope(url: String) async throws -> ScopeRule? {
        guard let rule = ScopeRule.include(url: url, kind: .exclude) else { return nil }
        try await setScope(await scope().rules + [rule])
        return rule
    }

    /// What a manual send (e.g. Repeater) should do for `target`/`path` (TGT-023). Until the project
    /// has an enabled scope rule, manual sends never ask (nothing is configured to protect yet); the
    /// active tools' ScopeGuard still refuses everything then.
    public func scopeDecision(for target: HTTPTarget, path: String) async -> ScopeDecision {
        let scopeGuard = self.scopeGuard
        guard await scopeGuard.current.rules.contains(where: \.enabled) else { return .send }
        return await scopeGuard.permits(target, path: path) ? .send : .confirm
    }

    /// What sending the raw `request` to `target` should do (TGT-023).
    public func scopeDecision(for target: HTTPTarget, request: [UInt8]) async -> ScopeDecision {
        await scopeDecision(for: target, path: Self.pathAndQuery(of: request, target: target))
    }

    /// What sending Repeater tab `id` should do (TGT-023): its target and the path in its draft.
    public func scopeDecision(forRepeaterTab id: Int64) async -> ScopeDecision {
        guard let tab = await repeater.tab(id) else { return .send }
        return await scopeDecision(for: tab.target, request: tab.draft)
    }

    /// What "Send group" should do (TGT-023): confirm if any member is out of scope.
    public func scopeDecision(forRepeaterGroup id: Int64) async -> ScopeDecision {
        for tab in await repeater.members(of: id)
        where await scopeDecision(for: tab.target, path: Self.pathAndQuery(of: tab.draft, target: tab.target))
            == .confirm
        {
            return .confirm
        }
        return .send
    }

    /// "Send anyway, and don't ask again for this host" (TGT-023), for the rest of the session.
    public func allowOutOfScopeSends(to host: String) async {
        await scopeGuard.allowWithoutAsking(host: host)
    }

    /// Export the scope as JSON (TGT-025).
    public func exportScope() async throws -> Data {
        try ScopeFile.export(await scope().rules)
    }

    /// Replace the scope with the rules in a scope file (TGT-025). Returns how many rules it had.
    @discardableResult
    public func importScope(_ data: Data) async throws -> Int {
        let rules = try ScopeFile.import(data)
        try await setScope(rules)
        return rules.count
    }

    /// The path and query of a raw request (`/` if it has none).
    static func pathAndQuery(of request: [UInt8], target: HTTPTarget) -> String {
        let derived = DerivedFields(target: target, request: RawRequest(Bytes(request)), response: nil)
        return (derived.path ?? "/") + (derived.query.map { "?" + $0 } ?? "")
    }
}

/// What a manual send does about scope (TGT-023).
public enum ScopeDecision: Sendable, Equatable {
    /// In scope (or allowed without asking): send.
    case send
    /// Out of scope: ask "Target is out of scope. Send anyway?" first.
    case confirm
}
