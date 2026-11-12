// GulpSession — session handling (F15): a per-project cookie jar (CookieJar), identities
// (Identity), macros that replay to establish or refresh session state (Macro/MacroRunner),
// the session-validity check (ValidityCheck), ordered session rules (SessionRule) run as engine
// hooks, and request signing (RequestSigner: DPoP, HTTP Message Signatures, AWS SigV4). The types
// are value types or engine-agnostic so the core is tested on Linux; GulpWorkspace persists them
// and registers the hooks on the engine.

/// Module marker (kept for diagnostics; the real types are the files in this module).
public enum GulpSession {
    /// The module's name.
    public static let moduleName = "GulpSession"
}
