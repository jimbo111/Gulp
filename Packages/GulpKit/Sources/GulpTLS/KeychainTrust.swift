// GulpTLS — trusting the Gulp CA on this Mac (F24 MAC-001, MAC-002; F02 §3 trust badge).
//
// Concept: a certificate in the login keychain is not trusted by itself. Trust is a separate
// "trust settings" record; setting it for a root shows the system's authorization dialog, so the
// user explicitly consents. Removing trust deletes that record (and the certificate).

#if os(macOS)
import Foundation
import Security

/// Install, remove and check trust for the Gulp CA in the user's login keychain.
public enum KeychainTrust {
    /// Add the CA to the login keychain and trust it for SSL (MAC-001). Shows the system's
    /// authorization prompt; blocks until the user answers, so call it off the main thread.
    public static func install(_ authority: CertificateAuthority) throws {
        let certificate = try secCertificate(authority.certificateDER())
        let status = SecItemAdd(itemQuery(certificate) as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw TLSError.storage("adding the CA to the login keychain failed (\(status))")
        }
        let settings: [[String: Any]] = [
            [
                kSecTrustSettingsPolicy as String: SecPolicyCreateSSL(true, nil),
                kSecTrustSettingsResult as String: NSNumber(value: SecTrustSettingsResult.trustRoot.rawValue),
            ]
        ]
        let trust = SecTrustSettingsSetTrustSettings(certificate, .user, settings as CFArray)
        guard trust == errSecSuccess else {
            throw TLSError.storage("the trust setting was not changed (\(trust))")
        }
    }

    /// Remove the CA's trust setting and the certificate from the login keychain (MAC-002).
    public static func remove(_ authority: CertificateAuthority) throws {
        let certificate = try secCertificate(authority.certificateDER())
        let trust = SecTrustSettingsRemoveTrustSettings(certificate, .user)
        guard trust == errSecSuccess || trust == errSecItemNotFound else {
            throw TLSError.storage("removing the trust setting failed (\(trust))")
        }
        let status = SecItemDelete(itemQuery(certificate) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TLSError.storage("removing the CA from the login keychain failed (\(status))")
        }
    }

    /// Whether this Mac trusts certificates the CA issues: evaluate a freshly minted test leaf
    /// with the SSL policy, as a browser would (F02 §4 "Trust check").
    public static func isTrusted(_ authority: CertificateAuthority) throws -> Bool {
        let host = "gulp-trust-check.invalid"
        let leaf = try authority.mintLeaf(for: .dns(host), key: SigningKey.generate(.p256))
        let chain = [try secCertificate(leaf.der), try secCertificate(authority.certificateDER())]
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(
            chain as CFArray, SecPolicyCreateSSL(true, host as CFString), &trust)
        guard status == errSecSuccess, let trust else { return false }
        return SecTrustEvaluateWithError(trust, nil)
    }

    private static func itemQuery(_ certificate: SecCertificate) -> [String: Any] {
        [kSecClass as String: kSecClassCertificate, kSecValueRef as String: certificate]
    }

    private static func secCertificate(_ der: [UInt8]) throws -> SecCertificate {
        guard let certificate = SecCertificateCreateWithData(nil, Data(der) as CFData) else {
            throw TLSError.invalidInput("certificate")
        }
        return certificate
    }
}
#endif
