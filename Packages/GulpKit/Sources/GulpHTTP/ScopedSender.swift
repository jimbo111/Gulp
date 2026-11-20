// GulpHTTP — the only way an *active* tool sends (CLAUDE.md "Scope safety"). A `ScopedSender` is built
// with an explicit `SendScope`, so the scope decision is made once, up front, and every send checks it:
// an out-of-scope target throws GulpCore's `OutOfScope` (the same error ScopeGuard raises) before a
// byte leaves the machine. Active CLI probes use `.pinned` (the operator's `--target` is the
// authorization, and nothing else may be hit); project-backed tools use `.guarded(ScopeGuard)`; a deliberate per-action override is `.overridden(reason:)` and says why.
// Scripts/rules-check.sh bans constructing a bare `NIOHTTPEngine()` in gulp-cli outside this type.

import GulpCore

/// What a `ScopedSender` may send to (CLAUDE.md "Scope safety").
public enum SendScope: Sendable {
    /// Only the one target the operator named (scheme, host and port must match exactly).
    case pinned(HTTPTarget)
    /// The project scope.
    case guarded(ScopeGuard)
    /// The user explicitly overrode scope for this action; `reason` says why.
    case overridden(reason: String)
}

/// An HTTP engine that refuses out-of-scope sends (CLAUDE.md "Scope safety").
public struct ScopedSender: Sendable {
    /// The scope every send is checked against.
    public let scope: SendScope
    private let engine: NIOHTTPEngine

    /// A sender limited to `scope`.
    public init(scope: SendScope, engine: NIOHTTPEngine = NIOHTTPEngine()) {
        self.scope = scope
        self.engine = engine
    }

    /// Whether `target`/`path` may be sent to.
    public func permits(_ target: HTTPTarget, path: String) async -> Bool {
        switch scope {
        case .pinned(let pinned):
            return pinned.scheme == target.scheme && pinned.host.lowercased() == target.host.lowercased()
                && pinned.port == target.port
        case .guarded(let scopeGuard):
            return await scopeGuard.permits(target, path: path)
        case .overridden:
            return true
        }
    }

    /// Send raw HTTP/1 bytes, if in scope (otherwise throw before sending).
    public func send(_ request: RawRequest, to target: HTTPTarget, options: SendOptions)
        async throws(OutOfScope)
        -> ExchangeResult
    {
        let path = Self.path(of: request)
        guard await permits(target, path: path) else { throw OutOfScope(target: target, path: path) }
        return await engine.send(request, to: target, options: options)
    }

    /// Open a WebSocket session, if in scope (otherwise throw before sending the upgrade).
    public func openWebSocket(_ upgrade: RawRequest, to target: HTTPTarget, options: SendOptions) async throws
        -> WebSocketSession
    {
        let path = Self.path(of: upgrade)
        guard await permits(target, path: path) else { throw OutOfScope(target: target, path: path) }
        return try await engine.openWebSocket(upgrade, to: target, options: options)
    }

    /// The underlying engine, released only once `target` is checked in scope — for library helpers
    /// that take an engine and talk to that one target (a WebSocket probe, a fuzz run, a batch of
    /// sends from a non-throwing closure). Check here, at the single place the target is chosen.
    public func engine(checkedFor target: HTTPTarget, path: String = "/") async throws(OutOfScope)
        -> NIOHTTPEngine
    {
        guard await permits(target, path: path) else { throw OutOfScope(target: target, path: path) }
        return engine
    }

    /// Release the engine's connections.
    public func shutdown() async { await engine.shutdown() }

    /// The request-target's path (without the query) — what scope rules match on.
    static func path(of request: RawRequest) -> String {
        let target = request.bytes[request.parsed.target].string()
        let path = target.split(separator: "?", maxSplits: 1).first.map(String.init) ?? "/"
        return path.isEmpty ? "/" : path
    }
}
