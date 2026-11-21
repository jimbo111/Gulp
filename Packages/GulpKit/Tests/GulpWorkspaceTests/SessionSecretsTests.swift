// Session secrets never reach the project file (CLAUDE.md "No secrets in the repo", F15): signing
// keys (SES-016…018), identity credentials (SES-002) and macro steps (SES-020) live in the
// environment's secret store, the project stores references, and the session layer still uses the
// real values. Projects never share a secret (PRJ-002 Save As, PRJ-005 "Use settings from…").

import Foundation
import GulpCore
import GulpSession
import GulpStore
import Testing

@testable import GulpWorkspace

@Suite("Session secrets live in the secret store, not the project file")
struct SessionSecretsTests {
    static let awsSecret = "wJalrXUtnFEMI-K7MDENG-TOPSECRET-bPxRfiCY"
    static let target = HTTPTarget(scheme: .https, host: "api.example", port: 443)

    static func signingRule() -> SessionRule {
        SessionRule(
            name: "sign", scope: RuleScope(hostGlob: "api.example"),
            actions: [
                .sign(
                    .sigV4(
                        secret: .aws(accessKey: "AKIDEXAMPLE", secretKey: awsSecret, sessionToken: nil),
                        region: "us-east-1", service: "execute-api"))
            ])
    }

    /// The scheme the live session layer would sign with.
    static func liveScheme(_ session: ProjectSession) async -> SigningScheme? {
        await session.sessionState.signing(
            source: .repeater, target: target, path: "/", origin: "https://api.example")?
            .0
    }

    /// The session settings exactly as written in the project file.
    static func storedSettings(at url: URL) async throws -> SessionSettings {
        let store = try ProjectStore.open(at: url)
        let data = try await store.settingsJSON(SessionSettings.key)
        try await store.close()
        return try JSONDecoder().decode(SessionSettings.self, from: try #require(data))
    }

    @Test("SES-018: the project file holds a reference; the key is a 0600 file in the secret store")
    func keyLeavesTheProjectFile() async throws {
        let environment = isolatedEnvironment()
        let url = projectURL(environment, "secrets")
        let session = try await ProjectSession.open(at: url, environment: environment)
        try await session.setSessionSettings(SessionSettings(rules: [Self.signingRule()]))

        // The live session still signs with the real key.
        #expect(
            await Self.liveScheme(session)?.secret
                == .aws(accessKey: "AKIDEXAMPLE", secretKey: Self.awsSecret, sessionToken: nil))
        // What the rest of the app reads back is the reference.
        let readBack = await session.sessionSettings()
        guard case .stored(let ref) = readBack.rules[0].actions.compactMap(\.signingScheme).first?.secret
        else {
            Issue.record("the stored settings still carry the key inline")
            return
        }
        try await session.close()

        // Not in the settings row, and not anywhere in the file's bytes.
        let stored = try await Self.storedSettings(at: url)
        #expect(stored.signingSecretRefs == [ref])
        let fileBytes = try Data(contentsOf: url)
        #expect(fileBytes.range(of: Data(Self.awsSecret.utf8)) == nil)

        // In the secret store, readable only by the owner.
        let file = environment.supportDirectory.appendingPathComponent("secrets/\(ref)")
        let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
        #expect(
            try environment.secretStore.read(ref).map { String(decoding: $0, as: UTF8.self) }?.contains(
                Self.awsSecret) == true)
    }

    @Test("SES-018: reopening resolves the key; removing the rule deletes it from the store")
    func reopenResolvesAndRemovalDeletes() async throws {
        let environment = isolatedEnvironment()
        let url = projectURL(environment, "reopen")
        let first = try await ProjectSession.open(at: url, environment: environment)
        try await first.setSessionSettings(SessionSettings(rules: [Self.signingRule()]))
        try await first.close()

        let reopened = try await ProjectSession.open(at: url, environment: environment)
        #expect(await Self.liveScheme(reopened)?.secret.isInline == true)
        let refs = await reopened.sessionSettings().signingSecretRefs
        let ref = try #require(refs.first)
        // Re-saving unchanged settings (e.g. switching identity) keeps the same reference and key.
        await reopened.setActiveIdentity(nil)
        #expect(await reopened.sessionSettings().signingSecretRefs == [ref])
        #expect(try environment.secretStore.read(ref) != nil)

        try await reopened.setSessionSettings(SessionSettings())
        #expect(try environment.secretStore.read(ref) == nil)
        try await reopened.close()
    }

    @Test("SES-018: a project saved with inline keys is migrated on open")
    func inlineKeysAreMigrated() async throws {
        let environment = isolatedEnvironment()
        let url = projectURL(environment, "legacy")
        let legacy = try await ProjectSession.open(at: url, environment: environment)
        // Write the settings the way older builds did: key material inline.
        try await legacy.settings.set(SessionSettings(rules: [Self.signingRule()]), scope: .project)
        try await legacy.close()

        let migrated = try await ProjectSession.open(at: url, environment: environment)
        #expect(await Self.liveScheme(migrated)?.secret.isInline == true)
        try await migrated.close()
        let stored = try await Self.storedSettings(at: url)
        #expect(!stored.hasInlineSigningSecrets)
        #expect(stored.signingSecretRefs.count == 1)
    }

    @Test("SES-018: a key missing from this machine's store fails signing with a clear error")
    func missingKeyFailsClearly() async throws {
        let environment = isolatedEnvironment()
        let url = projectURL(environment, "moved")
        let first = try await ProjectSession.open(at: url, environment: environment)
        try await first.setSessionSettings(SessionSettings(rules: [Self.signingRule()]))
        let firstRefs = await first.sessionSettings().signingSecretRefs
        let ref = try #require(firstRefs.first)
        try await first.close()
        try environment.secretStore.delete(ref)  // e.g. the project was copied to another Mac

        let session = try await ProjectSession.open(at: url, environment: environment)
        let scheme = try #require(await Self.liveScheme(session))
        #expect(scheme.secret == .stored(ref: ref))
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: api.example\r\n\r\n"))
        #expect(throws: SigningError.self) {
            _ = try RequestSigner.sign(request, to: Self.target, scheme: scheme)
        }
        try await session.close()
    }

    static let bearer = "Bearer IDENTITY-TOKEN-0f3c"
    static let password = "MACRO-PASSWORD-77a1"
    static let cookie = "COOKIE-SECRET-91bd"
    static let captured = "CAPTURED-CSRF-5e20"
    /// The plaintext an identity and its login macro would otherwise put in the project file.
    static let credentialPlaintext = [bearer, password, cookie, captured]

    /// An identity with every kind of credential and a login macro whose body carries a password.
    static func identityConfig() -> SessionSettings {
        let step = MacroStep(
            request: Array(
                "POST /login HTTP/1.1\r\nHost: api.example\r\n\r\nuser=admin&password=\(password)".utf8),
            target: target)
        let macro = Macro(name: "login", steps: [step])
        var identity = Identity(
            name: "admin", variables: ["password": password], headers: ["Authorization": bearer],
            loginMacro: macro.id, captured: ["csrf": captured])
        identity.cookies.store(setCookies: ["session=\(cookie); Path=/"], from: "api.example")
        return SessionSettings(
            identities: [identity], rules: [signingRule()], macros: [macro], activeIdentity: identity.id)
    }

    /// Whether any of `secrets` appears in the project file's bytes.
    static func fileContains(_ url: URL, _ secrets: [String]) throws -> Bool {
        let bytes = try Data(contentsOf: url)
        return secrets.contains { bytes.range(of: Data($0.utf8)) != nil }
    }

    @Test("SES-002: identity credentials and macro steps live in the secret store, not the project file")
    func identityCredentialsLeaveTheProjectFile() async throws {
        let environment = isolatedEnvironment()
        let url = projectURL(environment, "identities")
        let config = Self.identityConfig()
        let session = try await ProjectSession.open(at: url, environment: environment)
        try await session.setSessionSettings(config)
        // The app and the session layer still see the credentials.
        let readBack = await session.sessionSettings()
        #expect(readBack.identities == config.identities && readBack.macros == config.macros)
        #expect(await session.sessionState.identity(nil)?.headers == config.identities[0].headers)
        try await session.close()

        #expect(try !Self.fileContains(url, Self.credentialPlaintext))
        let stored = try await Self.storedSettings(at: url)
        #expect(stored.identities[0].variables.isEmpty && stored.macros[0].steps.isEmpty)
        let refs = stored.secretRefs
        #expect(refs.count == 3)  // identity, macro, signing key
        for ref in refs {
            let file = environment.supportDirectory.appendingPathComponent("secrets/\(ref)")
            let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int
            #expect(mode == 0o600)
        }

        let reopened = try await ProjectSession.open(at: url, environment: environment)
        let resolved = await reopened.sessionSettings()
        #expect(resolved.identities == config.identities && resolved.macros == config.macros)
        // Switching identity doesn't rewrite the secrets; removing everything deletes them.
        await reopened.setActiveIdentity(nil)
        #expect(await reopened.settings.get(SessionSettings.self).secretRefs == refs)
        try await reopened.setSessionSettings(SessionSettings())
        for ref in refs { #expect(try environment.secretStore.read(ref) == nil) }
        try await reopened.close()
    }

    @Test("SES-002: a project saved with inline identity credentials is migrated on open")
    func inlineCredentialsAreMigrated() async throws {
        let environment = isolatedEnvironment()
        let url = projectURL(environment, "legacy-identities")
        let config = Self.identityConfig()
        let legacy = try await ProjectSession.open(at: url, environment: environment)
        try await legacy.settings.set(config, scope: .project)  // the way older builds wrote it
        try await legacy.close()
        #expect(try Self.fileContains(url, Self.credentialPlaintext))

        let migrated = try await ProjectSession.open(at: url, environment: environment)
        #expect(await migrated.sessionSettings().identities == config.identities)
        try await migrated.close()
        let stored = try await Self.storedSettings(at: url)
        #expect(!stored.hasInlineSecrets && stored.secretRefs.count == 3)
    }

    @Test("PRJ-005: a project made with another's settings gets its own copies of the secrets")
    func settingsFromAnotherProjectCopySecrets() async throws {
        let environment = isolatedEnvironment()
        let source = projectURL(environment, "source")
        let config = Self.identityConfig()
        let first = try await ProjectSession.open(at: source, environment: environment)
        try await first.setSessionSettings(config)
        let sourceRefs = await first.settings.get(SessionSettings.self).secretRefs
        try await first.close()

        let copy = try await ProjectSession.open(
            at: projectURL(environment, "copy"), environment: environment, settingsFrom: .project(source))
        #expect(await copy.settings.get(SessionSettings.self).secretRefs.isDisjoint(with: sourceRefs))
        #expect(await copy.sessionSettings().identities == config.identities)
        #expect(await Self.liveScheme(copy)?.secret.isInline == true)
        try await copy.setSessionSettings(SessionSettings())  // the copy drops everything…
        try await copy.close()
        // …the source keeps its own.
        for ref in sourceRefs { #expect(try environment.secretStore.read(ref) != nil) }

        let reopened = try await ProjectSession.open(at: source, environment: environment)
        #expect(await reopened.sessionSettings().identities == config.identities)
        #expect(await Self.liveScheme(reopened)?.secret.isInline == true)
        try await reopened.close()
    }

    @Test(
        "PRJ-002: Save As gives the new file its own secrets; a discarded temporary project deletes its own")
    func saveAsCopiesSecrets() async throws {
        let environment = isolatedEnvironment()
        let original = projectURL(environment, "original")
        let session = try await ProjectSession.open(at: original, environment: environment)
        try await session.setSessionSettings(Self.identityConfig())
        let originalRefs = await session.settings.get(SessionSettings.self).secretRefs
        try await session.saveAs(projectURL(environment, "saved-as"))
        let savedRefs = await session.settings.get(SessionSettings.self).secretRefs
        #expect(savedRefs.count == 3 && savedRefs.isDisjoint(with: originalRefs))
        try await session.setSessionSettings(SessionSettings())
        try await session.close()
        for ref in originalRefs { #expect(try environment.secretStore.read(ref) != nil) }

        let temporary = try await ProjectSession.openTemporary(environment: environment)
        try await temporary.setSessionSettings(Self.identityConfig())
        let temporaryRefs = await temporary.settings.get(SessionSettings.self).secretRefs
        try await temporary.close()
        for ref in temporaryRefs { #expect(try environment.secretStore.read(ref) == nil) }
    }

    @Test("BCN-004: the OAST token lives in the environment's secret store, shared by later runs")
    func oastTokenUsesTheSecretStore() async throws {
        let environment = isolatedEnvironment()
        let server = "https://oast.example:8443"
        let name = OASTSettings.tokenSecretName(server)
        let session = try await open(environment, "oast-token")
        try await session.configureOAST(OASTSettings(serverURL: server), token: "TOKEN-123")
        #expect(try environment.secretStore.read(name) == Data("TOKEN-123".utf8))
        try await session.close()
        #expect(
            try Data(contentsOf: projectURL(environment, "oast-token")).range(of: Data("TOKEN-123".utf8))
                == nil)

        // The next run on this machine (another project, another CLI process) finds it.
        let next = try await open(environment, "oast-token-next")
        #expect(try await next.storedOASTToken(server) == "TOKEN-123")
        try await next.configureOAST(OASTSettings(serverURL: server), token: "")  // empty clears it
        #expect(try environment.secretStore.read(name) == nil)
        try await next.close()
    }

    @Test func fileStoreRejectsNamesThatEscapeItsDirectory() throws {
        let store = FileSecretStore(
            directory: FileManager.default.temporaryDirectory.appendingPathComponent("s"))
        #expect(throws: SecretStoreError.self) { try store.write(Data(), name: "../escape") }
        #expect(throws: SecretStoreError.self) { try store.write(Data(), name: ".hidden") }
    }
}

extension SessionAction {
    /// The signing scheme, if this is a `.sign` action.
    fileprivate var signingScheme: SigningScheme? {
        if case .sign(let scheme) = self { return scheme }
        return nil
    }
}
