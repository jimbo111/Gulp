// GulpWorkspace — signing keys in session rules never reach the project file. Before SessionSettings
// is persisted, each inline `SigningSecret` is moved into the SecretStore and replaced by
// `.stored(ref:)`; before the session layer uses the settings, each reference is resolved back. The
// engine therefore signs with the real key while the `.gulp` file only ever holds references.

import Foundation
import GulpSession

extension SessionSettings {
    /// Every `.stored` reference the rules hold.
    var signingSecretRefs: Set<String> {
        var refs: Set<String> = []
        forEachSigningSecret { secret in
            if case .stored(let ref) = secret { refs.insert(ref) }
        }
        return refs
    }

    /// Whether any rule still carries key material inline (a project saved before secrets moved out).
    var hasInlineSigningSecrets: Bool {
        var found = false
        forEachSigningSecret { secret in
            if secret.isInline { found = true }
        }
        return found
    }

    /// A copy safe to persist: inline secrets are written to `store` and replaced by references.
    func externalizingSigningSecrets(into store: any SecretStore) throws -> SessionSettings {
        var copy = self
        var failure: (any Error)?
        copy.mapSigningSecrets { secret in
            guard secret.isInline, failure == nil else { return secret }
            let ref = "signing-\(UUID().uuidString.lowercased())"
            do {
                try store.write(try JSONEncoder().encode(secret), name: ref)
                return .stored(ref: ref)
            } catch {
                failure = error
                return secret
            }
        }
        if let failure { throw failure }
        return copy
    }

    /// A copy for the session layer: references resolved from `store`. Unresolvable ones stay
    /// `.stored` (signing with them then fails with a clear error) and are listed in `missing`.
    func resolvingSigningSecrets(from store: any SecretStore) -> (
        settings: SessionSettings, missing: [String]
    ) {
        var copy = self
        var missing: [String] = []
        copy.mapSigningSecrets { secret in
            guard case .stored(let ref) = secret else { return secret }
            guard let data = try? store.read(ref),
                let resolved = try? JSONDecoder().decode(SigningSecret.self, from: data), resolved.isInline
            else {
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
