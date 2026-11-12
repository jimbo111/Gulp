// GulpWorkspace — ProjectSession's session-layer control surface (F15 M12a): set the macro sender,
// read/write the identities/rules/macros config, switch the active identity, run and test macros.

import Foundation
import GulpCore
import GulpHTTP
import GulpSession

extension ProjectSession {
    /// Give the session state a macro sender that uses the engine (recorded as `session` traffic),
    /// so re-authentication and macro actions replay through the real pipeline (SES-023).
    public func startSession() async {
        let engine = http
        let sender: MacroSender = { request, target in
            var options = SendOptions(recordAs: .session)
            // The session layer's own macros don't re-enter the session hooks (no nested re-auth).
            options.applyHooks = []
            options.timeouts.total = .seconds(30)
            let result = await engine.send(request, to: target, options: options)
            return (result.exchange.response, result.exchange.id, result.error?.code)
        }
        await sessionState.setSender(sender)
    }

    /// The stored session configuration (SES-001…SES-023).
    public func sessionSettings() -> SessionSettings { settings.get(SessionSettings.self) }

    /// Store and apply a new session configuration.
    public func setSessionSettings(_ value: SessionSettings) async throws {
        try await settings.set(value, scope: .project)
        await sessionState.update(value)
    }

    /// Switch the active identity ("as user-B", SES-002).
    public func setActiveIdentity(_ id: UUID?) async {
        await sessionState.setActive(id)
        var stored = sessionSettings()
        stored.activeIdentity = id
        try? await setSessionSettings(stored)
    }

    /// Run a macro against the engine and return the result (SES-022 test-run).
    public func runMacro(_ macro: Macro, identity: Identity? = nil) async -> MacroResult {
        let engine = http
        let sender: MacroSender = { request, target in
            var options = SendOptions(recordAs: .session)
            options.applyHooks = []
            options.timeouts.total = .seconds(30)
            let result = await engine.send(request, to: target, options: options)
            return (result.exchange.response, result.exchange.id, result.error?.code)
        }
        let runner = MacroRunner(send: sender)
        let base = identity ?? Identity.unauthenticated
        return await runner.run(macro, variables: base.allVariables, cookies: base.cookies)
    }
}
