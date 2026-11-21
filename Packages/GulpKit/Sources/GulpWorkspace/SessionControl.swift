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

    /// Store and apply a new session configuration. Signing keys go to the environment's secret store
    /// and the project keeps only references (CLAUDE.md "No secrets in the repo"); keys the new
    /// configuration no longer uses are deleted from the store.
    public func setSessionSettings(_ value: SessionSettings) async throws {
        let secrets = environment.secretStore
        let previousRefs = sessionSettings().signingSecretRefs
        let persisted = try value.externalizingSigningSecrets(into: secrets)
        try await settings.set(persisted, scope: .project)
        for ref in previousRefs.subtracting(persisted.signingSecretRefs) {
            do {
                try secrets.delete(ref)
            } catch {
                await events.publish(
                    .log(
                        LogEntry(
                            level: .warning, message: "Couldn't delete \(ref): \(error)",
                            module: "gulp.session")))
            }
        }
        await sessionState.update(persisted.resolvingSigningSecrets(from: secrets).settings)
    }

    /// A project saved before keys moved out of the project file still carries them inline: move them
    /// to the secret store and rewrite the project with references (once, on open).
    func moveInlineSigningSecrets() async {
        let stored = sessionSettings()
        guard stored.hasInlineSigningSecrets else { return }
        do {
            try await setSessionSettings(stored)
            await events.publish(
                .log(
                    LogEntry(
                        level: .info, message: "Moved this project's signing keys out of the project file.",
                        module: "gulp.session")))
        } catch {
            await events.publish(
                .log(
                    LogEntry(
                        level: .warning,
                        message: "Couldn't move signing keys out of the project file: \(error)",
                        module: "gulp.session")))
        }
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
