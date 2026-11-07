// GulpTLS — the Gulp CA (F02 TLS-001, TLS-003, TLS-006, TLS-007, TLS-010, TLS-012): generate,
// import and export the CA, and mint exact-host leaf certificates signed by it.
//
// Concept: a leaf is only trusted if (1) it chains to a root the client trusts — our CA, which the
// user installs — and (2) its subjectAltName matches the host the client asked for. Browsers ignore
// the CN for name matching since 2017; it is set for readability only.

import Crypto
import Foundation
import SwiftASN1
import X509
import _CryptoExtras

/// Key algorithm of the CA (TLS-001: RSA-2048 by default for compatibility, ECDSA P-256 optional).
public enum CAKeyType: String, Sendable, Codable, CaseIterable {
    /// RSA 2048-bit.
    case rsa2048
    /// ECDSA on P-256.
    case p256
}

/// Errors from the CA, minting and CA storage.
public enum TLSError: Error, Sendable, Equatable, CustomStringConvertible {
    /// A PEM/DER input could not be parsed.
    case invalidInput(String)
    /// The private key does not belong to the certificate.
    case keyMismatch
    /// Reading or writing CA storage failed.
    case storage(String)

    /// Human-readable text.
    public var description: String {
        switch self {
        case .invalidInput(let what): "Invalid input: \(what)"
        case .keyMismatch: "The private key does not match the certificate"
        case .storage(let what): "CA storage: \(what)"
        }
    }
}

/// A private key with the PEM text it was created from (for storage and for NIOSSL).
public struct SigningKey: Sendable {
    /// The key as swift-certificates uses it.
    public let key: Certificate.PrivateKey
    /// PEM encoding (PKCS#8 for P-256, PKCS#1 or PKCS#8 for RSA).
    public let pem: String
    /// Which algorithm.
    public let type: CAKeyType
    /// DER of the public key (SubjectPublicKeyInfo), used for key identifiers and comparisons.
    public let publicKeyDER: [UInt8]

    /// A new random key.
    public static func generate(_ type: CAKeyType) throws -> SigningKey {
        switch type {
        case .p256:
            let key = P256.Signing.PrivateKey()
            return SigningKey(
                key: Certificate.PrivateKey(key), pem: key.pemRepresentation, type: .p256,
                publicKeyDER: [UInt8](key.publicKey.derRepresentation))
        case .rsa2048:
            let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
            return SigningKey(
                key: Certificate.PrivateKey(key), pem: key.pemRepresentation, type: .rsa2048,
                publicKeyDER: [UInt8](key.publicKey.derRepresentation))
        }
    }

    /// Parse a PEM private key (P-256 or RSA).
    public init(pem: String) throws {
        if let key = try? P256.Signing.PrivateKey(pemRepresentation: pem) {
            self.init(
                key: Certificate.PrivateKey(key), pem: pem, type: .p256,
                publicKeyDER: [UInt8](key.publicKey.derRepresentation))
        } else if let key = try? _RSA.Signing.PrivateKey(pemRepresentation: pem) {
            self.init(
                key: Certificate.PrivateKey(key), pem: pem, type: .rsa2048,
                publicKeyDER: [UInt8](key.publicKey.derRepresentation))
        } else {
            throw TLSError.invalidInput("private key is not a PEM P-256 or RSA key")
        }
    }

    private init(key: Certificate.PrivateKey, pem: String, type: CAKeyType, publicKeyDER: [UInt8]) {
        self.key = key
        self.pem = pem
        self.type = type
        self.publicKeyDER = publicKeyDER
    }

    /// RFC 5280 §4.2.1.2-style key identifier: SHA-1 of the public key encoding.
    var keyIdentifier: [UInt8] { [UInt8](Insecure.SHA1.hash(data: publicKeyDER)) }

    var signatureAlgorithm: Certificate.SignatureAlgorithm {
        type == .p256 ? .ecdsaWithSHA256 : .sha256WithRSAEncryption
    }
}

/// A leaf certificate minted for one host.
public struct MintedLeaf: Sendable {
    /// Who it was minted for.
    public let subject: CertificateSubject
    /// The certificate.
    public let certificate: Certificate
    /// Its DER encoding.
    public let der: [UInt8]
    /// The leaf's private key (shared across leaves by default, TLS-004).
    public let key: SigningKey

    /// A leaf from its parts (the minter builds these; tests can present any certificate).
    public init(subject: CertificateSubject, certificate: Certificate, der: [UInt8], key: SigningKey) {
        self.subject = subject
        self.certificate = certificate
        self.der = der
        self.key = key
    }
}

/// The Gulp certificate authority.
public struct CertificateAuthority: Sendable {
    /// The CA certificate.
    public let certificate: Certificate
    /// The CA private key.
    public let key: SigningKey
    /// Key identifier written into leaves' authorityKeyIdentifier.
    let keyIdentifier: [UInt8]?

    /// CA validity (TLS-001).
    public static let validityYears = 10
    /// Leaf validity in days after `notBefore + 1 day` (TLS-003: ≈397 days, under Apple's 398).
    public static let leafValidityDays = 396

    /// Generate a new CA (TLS-001).
    public static func generate(
        keyType: CAKeyType = .rsa2048, now: Date = Date()
    ) throws -> CertificateAuthority {
        let key = try SigningKey.generate(keyType)
        let suffix = randomBytes(3).map { String(format: "%02X", $0) }.joined()
        let name = try DistinguishedName {
            CommonName("Gulp CA \(suffix)")
            OrganizationName("Gulp")
        }
        let identifier = key.keyIdentifier
        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
            Critical(KeyUsage(keyCertSign: true, cRLSign: true))
            SubjectKeyIdentifier(keyIdentifier: ArraySlice(identifier))
        }
        let notAfter = Calendar(identifier: .gregorian).date(byAdding: .year, value: validityYears, to: now)
        let certificate = try Certificate(
            version: .v3, serialNumber: randomSerial(), publicKey: key.key.publicKey,
            notValidBefore: now.addingTimeInterval(-86_400),
            notValidAfter: notAfter ?? now.addingTimeInterval(Double(validityYears) * 365 * 86_400),
            issuer: name, subject: name, signatureAlgorithm: key.signatureAlgorithm,
            extensions: extensions, issuerPrivateKey: key.key)
        return CertificateAuthority(certificate: certificate, key: key, keyIdentifier: identifier)
    }

    /// Import a CA from a PEM certificate and PEM private key (TLS-007).
    public init(certificatePEM: String, privateKeyPEM: String) throws {
        let certificate: Certificate
        do {
            certificate = try Certificate(pemEncoded: certificatePEM)
        } catch {
            throw TLSError.invalidInput("CA certificate is not a PEM certificate")
        }
        let key = try SigningKey(pem: privateKeyPEM)
        guard certificate.publicKey == key.key.publicKey else { throw TLSError.keyMismatch }
        var identifier: [UInt8]?
        for ext in certificate.extensions where ext.oid == .X509ExtensionID.subjectKeyIdentifier {
            identifier = (try? SubjectKeyIdentifier(ext)).map { [UInt8]($0.keyIdentifier) }
        }
        self.init(certificate: certificate, key: key, keyIdentifier: identifier)
    }

    private init(certificate: Certificate, key: SigningKey, keyIdentifier: [UInt8]?) {
        self.certificate = certificate
        self.key = key
        self.keyIdentifier = keyIdentifier
    }

    /// The CA certificate as PEM (TLS-006).
    public func certificatePEM() throws -> String {
        try certificate.serializeAsPEM().pemString
    }

    /// The CA certificate as DER (TLS-006).
    public func certificateDER() throws -> [UInt8] {
        try Self.der(certificate)
    }

    /// SHA-256 fingerprint of the CA certificate, lowercase hex.
    public func sha256Fingerprint() throws -> String {
        try Self.fingerprint(certificateDER())
    }

    /// Mint an exact-host leaf (TLS-003, TLS-010, TLS-012). `key` is the leaf key pair.
    public func mintLeaf(
        for subject: CertificateSubject, key leafKey: SigningKey, now: Date = Date()
    ) throws -> MintedLeaf {
        let name: DistinguishedName
        let commonName = subject.description
        if commonName.utf8.count <= 64 {  // the X.520 upper bound for CN
            name = try DistinguishedName { CommonName(commonName) }
        } else {
            name = DistinguishedName()
        }
        let altName: GeneralName
        switch subject {
        case .dns(let host): altName = .dnsName(host)
        case .ip(let bytes, _): altName = .ipAddress(ASN1OctetString(contentBytes: ArraySlice(bytes)))
        }
        let usage =
            leafKey.type == .rsa2048
            ? KeyUsage(digitalSignature: true, keyEncipherment: true) : KeyUsage(digitalSignature: true)
        let authorityKey = keyIdentifier
        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.notCertificateAuthority)
            Critical(usage)
            try ExtendedKeyUsage([.serverAuth])
            SubjectAlternativeNames([altName])
            SubjectKeyIdentifier(keyIdentifier: ArraySlice(leafKey.keyIdentifier))
            if let authorityKey {
                AuthorityKeyIdentifier(keyIdentifier: ArraySlice(authorityKey))
            }
        }
        let certificate = try Certificate(
            version: .v3, serialNumber: Self.randomSerial(), publicKey: leafKey.key.publicKey,
            notValidBefore: now.addingTimeInterval(-86_400),
            notValidAfter: now.addingTimeInterval(Double(Self.leafValidityDays) * 86_400),
            issuer: self.certificate.subject, subject: name, signatureAlgorithm: key.signatureAlgorithm,
            extensions: extensions, issuerPrivateKey: key.key)
        let der = try Self.der(certificate)
        return MintedLeaf(subject: subject, certificate: certificate, der: der, key: leafKey)
    }

    // MARK: helpers

    static func der(_ certificate: Certificate) throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return serializer.serializedBytes
    }

    /// Lowercase hex SHA-256 of `bytes`.
    public static func fingerprint(_ bytes: [UInt8]) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    static func randomBytes(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }
    }

    /// A random 16-byte positive serial (TLS-003); the top bit is cleared so DER keeps it positive.
    static func randomSerial() -> Certificate.SerialNumber {
        var bytes = randomBytes(16)
        bytes[0] = (bytes[0] & 0x7F) | 0x40
        return Certificate.SerialNumber(bytes: bytes)
    }
}
