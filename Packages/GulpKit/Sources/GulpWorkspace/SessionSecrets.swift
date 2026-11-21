// GulpWorkspace — session secrets never reach the project file (CLAUDE.md "No secrets in the repo").
// Before SessionSettings is persisted, its secrets move into the SecretStore:
//
//   - each inline `SigningSecret` in a rule is stored and replaced by `.stored(ref:)`;
//   - each identity's credentials (variables, headers, cookies, captured values) and each macro's
//     steps (a login request carries the password) are stored as one secret, the persisted identity
//     or macro is left empty, and `credentialRefs` names the secret.
//
// Content that is loaded gets a new secret; a reference that could not be loaded on this machine is
// kept as it is. Before the session layer uses the settings, every reference is resolved back, so
// the engine works with the real values while the `.gulp` file only ever holds references. A
// project never shares a secret with another (Save As and "Use settings from…" copy them).

import Foundation
import GulpSession

/// The secret part of an identity, stored as one secret.
struct IdentityCredentials: Codable, Hashable {
    var variables: [String: String] = [:]
    var headers: [String: String] = [:]
    var cookies = CookieJar()
    var captured: [String: String] = [:]

    var isEmpty: Bool { self == IdentityCredentials() }
}

extension Identity {
    /// The identity's credentials (everything but its name and login macro).
    var credentials: IdentityCredentials {
        get {
            IdentityCredentials(variables: variables, headers: headers, cookies: cookies, captured: captured)
        }
        set {
            variables = newValue.variables
            headers = newValue.headers
            cookies = newValue.cookies
            captured = newValue.captured
        }
    }
}

extension SessionSettings {
    /// Every secret the settings reference.
    var secretRefs: Set<String> { signingSecretRefs.union(credentialRefs.values) }

    /// Whether any secret is still inline (a project saved before secrets moved out).
    var hasInlineSecrets: Bool {
        hasInlineSigningSecrets || identities.contains { !$0.credentials.isEmpty }
            || macros.contains { !$0.steps.isEmpty }
    }

    /// A copy safe to persist: inline secrets are written to `store` and replaced by references.
    func externalizingSecrets(into store: any SecretStore) throws -> SessionSettings {
        var copy = try externalizingSigningSecrets(into: store)
        var refs: [String: String] = [:]
        for index in copy.identities.indices {
            let key = copy.identities[index].id.uuidString
            let credentials = copy.identities[index].credentials
            guard !credentials.isEmpty else {
                refs[key] = credentialRefs[key]  // not loaded on this machine: keep the reference
                continue
            }
            refs[key] = try Self.write(credentials, kind: "identity", to: store)
            copy.identities[index].credentials = IdentityCredentials()
        }
        for index in copy.macros.indices {
            let key = copy.macros[index].id.uuidString
            guard !copy.macros[index].steps.isEmpty else {
                refs[key] = credentialRefs[key]
                continue
            }
            refs[key] = try Self.write(copy.macros[index].steps, kind: "macro", to: store)
            copy.macros[index].steps = []
        }
        copy.credentialRefs = refs
        return copy
    }

    /// A copy with identity credentials and macro steps loaded from `store` (what the app edits;
    /// signing keys stay references). Unloadable ones stay empty and referenced, and are listed in
    /// `missing`.
    func resolvingCredentials(from store: any SecretStore) -> (settings: SessionSettings, missing: [String]) {
        var copy = self
        var missing: [String] = []
        for index in identities.indices {
            let key = identities[index].id.uuidString
            guard let ref = credentialRefs[key] else { continue }
            guard let credentials = Self.read(IdentityCredentials.self, ref, from: store) else {
                missing.append(ref)
                continue
            }
            copy.identities[index].credentials = credentials
            copy.credentialRefs[key] = nil
        }
        for index in macros.indices {
            let key = macros[index].id.uuidString
            guard let ref = credentialRefs[key] else { continue }
            guard let steps = Self.read([MacroStep].self, ref, from: store) else {
                missing.append(ref)
                continue
            }
            copy.macros[index].steps = steps
            copy.credentialRefs[key] = nil
        }
        return (copy, missing)
    }

    /// A copy for the session layer: every reference resolved from `store`, signing keys included.
    func resolvingSecrets(from store: any SecretStore) -> (settings: SessionSettings, missing: [String]) {
        let (loaded, missingCredentials) = resolvingCredentials(from: store)
        let (resolved, missingKeys) = loaded.resolvingSigningSecrets(from: store)
        return (resolved, missingCredentials + missingKeys)
    }

    /// The same settings referencing fresh copies of their secrets, for a project that took these
    /// settings from another one (so deleting its secrets never deletes the other's).
    func copyingSecrets(in store: any SecretStore) throws -> SessionSettings {
        try resolvingSecrets(from: store).settings.externalizingSecrets(into: store)
    }

    private static func write(_ value: some Encodable, kind: String, to store: any SecretStore) throws
        -> String
    {
        let ref = "\(kind)-\(UUID().uuidString.lowercased())"
        try store.write(try JSONEncoder().encode(value), name: ref)
        return ref
    }

    private static func read<T: Decodable>(_ type: T.Type, _ ref: String, from store: any SecretStore) -> T? {
        guard let data = try? store.read(ref) else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    // MARK: signing keys

    /// Every `.stored` reference the rules hold.
    var signingSecretRefs: Set<String> {
        var refs: Set<String> = []
        forEachSigningSecret { secret in
            if case .stored(let ref) = secret { refs.insert(ref) }
        }
        return refs
    }

    /// Whether any rule still carries key material inline.
    var hasInlineSigningSecrets: Bool {
        var found = false
        forEachSigningSecret { secret in
            if secret.isInline { found = true }
        }
        return found
    }

    /// A copy whose inline signing keys are written to `store` and replaced by references.
    func externalizingSigningSecrets(into store: any SecretStore) throws -> SessionSettings {
        var copy = self
        var failure: (any Error)?
        copy.mapSigningSecrets { secret in
            guard secret.isInline, failure == nil else { return secret }
            do {
                return .stored(ref: try Self.write(secret, kind: "signing", to: store))
            } catch {
                failure = error
                return secret
            }
        }
        if let failure { throw failure }
        return copy
    }

    /// A copy with signing-key references resolved from `store`. Unresolvable ones stay `.stored`
    /// (signing with them then fails with a clear error) and are listed in `missing`.
    func resolvingSigningSecrets(from store: any SecretStore) -> (
        settings: SessionSettings, missing: [String]
    ) {
        var copy = self
        var missing: [String] = []
        copy.mapSigningSecrets { secret in
            guard case .stored(let ref) = secret else { return secret }
            guard let resolved = Self.read(SigningSecret.self, ref, from: store), resolved.isInline else {
                missing.append(ref)
                return secret
            }
            return resolved
        }
        return (copy, missing)
    }

    /// Replace the secret of every signing action, in order, with `body`'s result.
    private mutating func mapSigningSecrets(_ body: (SigningSecret) -> SigningSecret) {
        for r in rules.indices {
            for a in rules[r].actions.indices {
                guard case .sign(let scheme) = rules[r].actions[a] else { continue }
                rules[r].actions[a] = .sign(scheme.replacingSecret(body(scheme.secret)))
            }
        }
    }

    /// Visit the secret of every signing action, in order.
    private func forEachSigningSecret(_ body: (SigningSecret) -> Void) {
        var copy = self
        copy.mapSigningSecrets { secret in
            body(secret)
            return secret
        }
    }
}
