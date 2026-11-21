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

    /// The stored session configuration (SES-001…SES-023), with identity credentials and macro steps
    /// loaded from the secret store. Signing keys stay references (`.stored(ref:)`); passing the
    /// value back to `setSessionSettings` keeps them.
    public func sessionSettings() -> SessionSettings {
        settings.get(SessionSettings.self).resolvingCredentials(from: environment.secretStore).settings
    }

    /// Store and apply a new session configuration. Its secrets (signing keys, identity credentials,
    /// macro steps) go to the environment's secret store and the project keeps only references
    /// (CLAUDE.md "No secrets in the repo"); secrets the new configuration no longer uses are deleted
    /// from the store.
    public func setSessionSettings(_ value: SessionSettings) async throws {
        let secrets = environment.secretStore
        let previousRefs = settings.get(SessionSettings.self).secretRefs
        let persisted = try value.externalizingSecrets(into: secrets)
        try await settings.set(persisted, scope: .project)
        await deleteSecrets(previousRefs.subtracting(persisted.secretRefs))
        await sessionState.update(persisted.resolvingSecrets(from: secrets).settings)
    }

    /// Remove `refs` from the secret store (a failure is logged; the secret is merely left behind).
    func deleteSecrets(_ refs: Set<String>) async {
        for ref in refs {
            do {
                try environment.secretStore.delete(ref)
            } catch {
                await events.publish(
                    .log(
                        LogEntry(
                            level: .warning, message: "Couldn't delete \(ref): \(error)",
                            module: "gulp.session")))
            }
        }
    }

    /// A project saved before secrets moved out of the project file still carries them inline: move
    /// them to the secret store and rewrite the project with references (once, on open).
    func moveInlineSecrets() async {
        let stored = settings.get(SessionSettings.self)
        guard stored.hasInlineSecrets else { return }
        do {
            try await setSessionSettings(stored)
            await events.publish(
                .log(
                    LogEntry(
                        level: .info,
                        message: "Moved this project's session secrets out of the project file.",
                        module: "gulp.session")))
        } catch {
            await events.publish(
                .log(
                    LogEntry(
                        level: .warning,
                        message: "Couldn't move session secrets out of the project file: \(error)",
                        module: "gulp.session")))
        }
    }

    /// Switch the active identity ("as user-B", SES-002). The stored secrets are kept as they are.
    public func setActiveIdentity(_ id: UUID?) async {
        await sessionState.setActive(id)
        var stored = settings.get(SessionSettings.self)
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

extension LayeredSettings {
    /// Give this project its own copies of the secrets its session settings reference. A project
    /// made with "Use settings from…" (PRJ-005) or by Save As (PRJ-002) starts with the source's
    /// references; editing them here would otherwise delete the source's secrets.
    func copySessionSecrets(in secrets: any SecretStore) async throws {
        let stored = get(SessionSettings.self)
        guard !stored.secretRefs.isEmpty else { return }
        try await set(try stored.copyingSecrets(in: secrets), scope: .project)
    }
}
