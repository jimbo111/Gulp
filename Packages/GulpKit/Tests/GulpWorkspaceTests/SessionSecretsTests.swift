// Signing keys never reach the project file (CLAUDE.md "No secrets in the repo", F15 SES-016…018):
// the project stores `.stored(ref:)`, the key lives in the environment's secret store, and the
// session layer still signs with the real key.

import Foundation
import GulpCore
import GulpSession
import GulpStore
import Testing

@testable import GulpWorkspace

@Suite("Session signing keys live in the secret store, not the project file")
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
