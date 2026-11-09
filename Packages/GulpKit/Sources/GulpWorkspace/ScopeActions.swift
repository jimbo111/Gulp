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

    /// What a manual send (e.g. Repeater) should do for `target`/`path` (TGT-023).
    public func scopeDecision(for target: HTTPTarget, path: String) async -> ScopeDecision {
        await scopeGuard.permits(target, path: path) ? .send : .confirm
    }
}

/// What a manual send does about scope (TGT-023).
public enum ScopeDecision: Sendable, Equatable {
    /// In scope (or allowed without asking): send.
    case send
    /// Out of scope: ask "Target is out of scope. Send anyway?" first.
    case confirm
}
