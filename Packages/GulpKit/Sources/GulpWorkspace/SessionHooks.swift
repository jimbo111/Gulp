// GulpWorkspace — the engine hooks that apply the session layer (F15). All three carry the shared
// SessionState; they are registered on the engine by ProjectSession. The request hook runs first
// (so cookies/headers are set before Transform Tags and match & replace), the signer hook last (so
// it signs the final bytes), and the response hook records cookies/nonces and marks staleness.

import Foundation
import GulpCore
import GulpHTTP
import GulpSession

/// Applies session rules to an outgoing request (SES-010/011); runs for every tool (the rule scope
/// decides what matches).
public struct SessionRequestHook: RequestHook {
    /// Hook family (toggled per send via `SendOptions.applyHooks`).
    public let kind = HookSet.sessions
    let state: SessionState

    /// A hook over `state`.
    public init(state: SessionState) { self.state = state }

    /// Applies the session rules that match this request's source and target.
    public func willSend(_ req: inout OutgoingRequest, context: HookContext) async throws {
        req.request = await state.prepare(req.request, target: req.target, source: context.source)
    }
}

/// Signs an outgoing request (SES-016…018). Registered LAST so it reads the final bytes; it fixes
/// Content-Length itself before signing (the engine's later fix is then a no-op).
public struct SessionSignerHook: RequestHook {
    /// Shares the sessions family so it toggles with the rest of the session layer.
    public let kind = HookSet.sessions
    let state: SessionState

    /// A signer over `state`.
    public init(state: SessionState) { self.state = state }

    /// Signs the final request bytes when a signing scheme matches its source and target.
    public func willSend(_ req: inout OutgoingRequest, context: HookContext) async throws {
        let path = req.request.bytes[req.request.parsed.target].string()
        guard
            let (scheme, signingContext) = await state.signing(
                source: context.source, target: req.target, path: path, origin: Issue.origin(req.target))
        else { return }
        let finalized = req.request.updatingContentLength()
        req.request = try RequestSigner.sign(
            finalized, to: req.target, scheme: scheme, context: signingContext)
    }
}

/// Records cookies, DPoP nonces and session staleness from responses (SES-001/012).
public struct SessionResponseHook: ResponseHook {
    /// Hook family.
    public let kind = HookSet.sessions
    let state: SessionState

    /// A hook over `state`.
    public init(state: SessionState) { self.state = state }

    /// Feeds the response to the session state, which records cookies and nonces and marks staleness.
    public func didReceive(
        _ response: inout RawResponse, for request: OutgoingRequest, context: HookContext
    ) async throws {
        let path = request.request.bytes[request.request.parsed.target].string()
        await state.observe(
            response: response, target: request.target, source: context.source, requestPath: path)
    }
}
