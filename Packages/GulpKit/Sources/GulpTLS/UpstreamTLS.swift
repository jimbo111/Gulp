// GulpTLS — the client side of TLS to real servers (F02 TLS-008, TLS-009). A testing tool must talk
// to self-signed staging servers, so validation is OFF by default — but the chain and the result
// validation *would* have given are still captured, so the History can show a warning badge.
//
// Concept: NIOSSL's custom verification callback replaces BoringSSL's verification entirely and
// hands us the presented chain. Turning verification off with `.none` instead would skip the
// callback, and we would never see the chain.

import Foundation
import GulpCore
import NIOSSL
import SwiftASN1
import X509

/// A TLS protocol version for upstream connections.
public enum TLSProtocolVersion: String, Sendable, Codable, Hashable, CaseIterable, Comparable {
    /// TLS 1.0.
    case tls1_0 = "TLSv1.0"
    /// TLS 1.1.
    case tls1_1 = "TLSv1.1"
    /// TLS 1.2.
    case tls1_2 = "TLSv1.2"
    /// TLS 1.3.
    case tls1_3 = "TLSv1.3"

    var nio: TLSVersion {
        switch self {
        case .tls1_0: .tlsv1
        case .tls1_1: .tlsv11
        case .tls1_2: .tlsv12
        case .tls1_3: .tlsv13
        }
    }

    /// The version NIOSSL negotiated, by name.
    public init?(_ version: TLSVersion) {
        switch version {
        case .tlsv1: self = .tls1_0
        case .tlsv11: self = .tls1_1
        case .tlsv12: self = .tls1_2
        case .tlsv13: self = .tls1_3
        default: return nil
        }
    }

    /// Ordered oldest to newest.
    public static func < (lhs: Self, rhs: Self) -> Bool {
        allCases.firstIndex(of: lhs)! < allCases.firstIndex(of: rhs)!
    }
}

/// Upstream TLS settings (TLS-008, TLS-009). Part of the connection-pool key: connections made with
/// different settings are never shared.
public struct UpstreamTLSSettings: Sendable, Codable, Hashable {
    /// Lowest version offered (default TLS 1.2).
    public var minimumVersion: TLSProtocolVersion = .tls1_2
    /// Highest version offered (default TLS 1.3).
    public var maximumVersion: TLSProtocolVersion = .tls1_3
    /// OpenSSL-style cipher list for TLS ≤ 1.2; nil keeps the library default.
    public var cipherSuites: String?
    /// ALPN protocols offered, in preference order. Empty (the default) derives them from the
    /// request's HTTP version preference (`h2, http/1.1` for auto).
    public var alpn: [String] = []
    /// Fail the handshake when the server's certificate does not validate (off by default).
    public var validateCertificates = false

    /// Default settings.
    public init() {}
}

/// What one upstream handshake produced.
public struct UpstreamHandshake: Sendable {
    /// The certificates the server presented, leaf first (DER).
    public var chain: [[UInt8]] = []
    /// What validation said (whether or not it was enforced).
    public var validation: TLSValidation = .notChecked
}

/// Upstream TLS helpers: client contexts, chain capture and validation.
public enum UpstreamTLS {
    /// A client context for `settings`. The verification callback passed to the handler decides
    /// trust; the context only fixes versions, ciphers and ALPN.
    public static func makeContext(_ settings: UpstreamTLSSettings) throws -> NIOSSLContext {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.minimumTLSVersion = min(settings.minimumVersion, settings.maximumVersion).nio
        configuration.maximumTLSVersion = max(settings.minimumVersion, settings.maximumVersion).nio
        if let ciphers = settings.cipherSuites, !ciphers.isEmpty { configuration.cipherSuites = ciphers }
        configuration.applicationProtocols = settings.alpn
        // Must not be `.none`, or the custom callback never runs (and we see no chain).
        configuration.certificateVerification = .noHostnameVerification
        return try NIOSSLContext(configuration: configuration)
    }

    /// The SNI to send for `host`: nil for IP literals (SNI carries names only, RFC 6066 §3).
    public static func serverName(for host: String) -> String? {
        if case .ip = CertificateSubject(host: host) { return nil }
        return host
    }

    /// Lowercase hex SHA-256 of each certificate (leaf first), as recorded in `TLSInfo`.
    public static func fingerprints(_ chain: [[UInt8]]) -> [String] {
        chain.map(CertificateAuthority.fingerprint)
    }

    /// Validate a presented chain (leaf first, DER) for `host` against `roots`.
    /// Reasons: `selfSigned`, `expired`, `notYetValid`, `untrusted` (no path to a root, or the name
    /// doesn't match), `unparsable`.
    public static func validate(
        chain: [[UInt8]], host: String, roots: CertificateStore? = nil, now: Date = Date()
    ) async -> TLSValidation {
        let certificates = chain.compactMap { try? Certificate(derEncoded: $0) }
        guard let leaf = certificates.first, certificates.count == chain.count else {
            return .failed("unparsable")
        }
        if now > leaf.notValidAfter { return .failed("expired") }
        if now < leaf.notValidBefore { return .failed("notYetValid") }
        let roots = roots ?? SystemRoots.store
        // An IP-literal target is checked against the leaf's IP SANs, a name against its DNS SANs.
        var ip: String?
        if case .ip(_, let text) = CertificateSubject(host: host) { ip = text }
        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy(validationTime: now)
            ServerIdentityPolicy(serverHostname: serverName(for: host), serverIP: ip)
        }
        let result = await verifier.validate(
            leafCertificate: leaf, intermediates: CertificateStore(Array(certificates.dropFirst())))
        switch result {
        case .validCertificate:
            return .ok
        case .couldNotValidate:
            let selfSigned = certificates.count == 1 && leaf.issuer == leaf.subject
            return .failed(selfSigned ? "selfSigned" : "untrusted")
        }
    }
}

/// The platform's trusted roots, read once from the system PEM bundle (Linux distributions and
/// macOS both ship one; macOS keeps `/etc/ssl/cert.pem` in sync with its system roots).
enum SystemRoots {
    static let bundlePaths = [
        "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem",
    ]

    static let store: CertificateStore = {
        for path in bundlePaths {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8),
                let documents = try? PEMDocument.parseMultiple(pemString: text)
            else { continue }
            let certificates = documents.compactMap { try? Certificate(pemDocument: $0) }
            if !certificates.isEmpty { return CertificateStore(certificates) }
        }
        return CertificateStore()
    }()
}
