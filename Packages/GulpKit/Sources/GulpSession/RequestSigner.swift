// GulpSession — request signing as a session action (F15 SES-016…SES-018). A `RequestSigner` runs
// as the engine's LAST request hook, so it reads the final bytes (after Transform Tags, match &
// replace, extensions and the Content-Length fixer) and signs exactly what is sent. Three schemes:
//
//   DPoP (RFC 9449)            — a fresh proof JWT per request: htm/htu/iat/jti, ath for the access
//                                token, and the server nonce when one was demanded; set as `DPoP`.
//   HTTP Message Signatures    — RFC 9421 over chosen covered components (@method, @target-uri,
//   (RFC 9421)                   @authority, content-digest, headers); adds Signature-Input and
//                                Signature (and Content-Digest when covered).
//   AWS SigV4                  — canonical request → string to sign → derived key; adds Authorization,
//                                X-Amz-Date and X-Amz-Content-Sha256 (session token when present).
//
// Signing never caches a signature (it re-signs on every send and retry) and reads the key material
// the workspace loads from the Keychain. The JOSE/crypto primitives are GulpCodec's (shared with the
// JWT Workbench). Nothing here weakens verification; it produces valid signatures so a tester can
// exercise APIs that require them.

import Crypto
import Foundation
import GulpCodec
import GulpCore
import GulpHTTP

/// Private key material for a signing scheme (serialized; the real secrets live in the Keychain).
public enum SigningSecret: Sendable, Hashable, Codable {
    /// An EC private key (raw bytes) on a curve — DPoP and RFC 9421 (ES256/384/512).
    case ec(curve: ECCurve, privateRaw: [UInt8])
    /// An RSA private key as PEM — RFC 9421 (RSA-PSS / RS256).
    case rsaPEM(String)
    /// A shared secret — RFC 9421 HMAC (hmac-sha256).
    case hmac([UInt8])
    /// AWS credentials — SigV4.
    case aws(accessKey: String, secretKey: String, sessionToken: String?)

    func jwtKey() -> JWTKey? {
        switch self {
        case .ec(let curve, let raw): return .ecPrivate(curve, raw)
        case .rsaPEM(let pem): return JWTKey.pem(pem)
        case .hmac(let bytes): return .secret(bytes)
        case .aws: return nil
        }
    }
}

/// How to sign a request (SES-016…018).
public enum SigningScheme: Sendable, Hashable, Codable {
    /// DPoP proof (RFC 9449). `alg` is the JWS algorithm (ES256 by default); the key is the EC key.
    case dpop(secret: SigningSecret, algorithm: String = "ES256")
    /// HTTP Message Signatures (RFC 9421). Covered components, algorithm label, key id, and the key.
    case httpMessageSignature(
        secret: SigningSecret, algorithm: String, keyID: String,
        components: [String] = ["@method", "@target-uri", "content-digest"])
    /// AWS SigV4 for `service` in `region`.
    case sigV4(secret: SigningSecret, region: String, service: String)
}

/// Extra per-request inputs the signer may need (the access token for DPoP `ath`, the latest
/// `DPoP-Nonce` for the origin). The engine fills these from the identity/response state.
public struct SigningContext: Sendable {
    /// The OAuth access token (for DPoP `ath`), if any.
    public var accessToken: String?
    /// The latest `DPoP-Nonce` the server sent for this origin, if any.
    public var dpopNonce: String?
    /// The clock (injected for deterministic tests).
    public var now: Date

    /// A context.
    public init(accessToken: String? = nil, dpopNonce: String? = nil, now: Date = Date()) {
        self.accessToken = accessToken
        self.dpopNonce = dpopNonce
        self.now = now
    }
}

/// Produces a signed copy of a request.
public enum RequestSigner {
    /// Sign `request` to `target` with `scheme`. Throws if the key material is wrong for the scheme.
    public static func sign(
        _ request: RawRequest, to target: HTTPTarget, scheme: SigningScheme,
        context: SigningContext = SigningContext()
    ) throws -> RawRequest {
        switch scheme {
        case .dpop(let secret, let algorithm):
            return try signDPoP(
                request, target: target, secret: secret, algorithm: algorithm, context: context)
        case .httpMessageSignature(let secret, let algorithm, let keyID, let components):
            return try signMessage(
                request, target: target, secret: secret, algorithm: algorithm, keyID: keyID,
                components: components,
                context: context)
        case .sigV4(let secret, let region, let service):
            return try signSigV4(
                request, target: target, secret: secret, region: region, service: service, context: context)
        }
    }

    // MARK: helpers

    static func method(_ request: RawRequest) -> String {
        request.bytes[request.parsed.method].string().uppercased()
    }

    static func targetString(_ request: RawRequest) -> String {
        request.bytes[request.parsed.target].string()
    }

    static func bodyBytes(_ request: RawRequest) -> [UInt8] {
        Array(request.bytes.rawBytes[request.parsed.body])
    }

    static func authority(_ request: RawRequest, target: HTTPTarget) -> String {
        request.headerValue("host")?.string()
            ?? {
                let def = target.scheme == .https ? 443 : 80
                return target.port == def ? target.host : "\(target.host):\(target.port)"
            }()
    }

    static func targetURI(_ request: RawRequest, target: HTTPTarget) -> String {
        "\(target.scheme.rawValue)://\(authority(request, target: target))\(targetString(request))"
    }

    static func base64(_ bytes: [UInt8]) -> String { Data(bytes).base64EncodedString() }

    static func base64url(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    static func sha256(_ bytes: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: bytes)) }

    static func hmacSHA256(_ key: [UInt8], _ message: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

    // MARK: DPoP (RFC 9449)

    static func signDPoP(
        _ request: RawRequest, target: HTTPTarget, secret: SigningSecret, algorithm: String,
        context: SigningContext
    ) throws -> RawRequest {
        guard let key = secret.jwtKey() else { throw SigningError.wrongKey("DPoP needs an EC/RSA key") }
        let header: [String: Any] = [
            "typ": "dpop+jwt", "alg": algorithm, "jwk": try key.publicJWK(),
        ]
        var claims: [String: Any] = [
            "htm": method(request),
            "htu": targetURI(request, target: target).components(separatedBy: "?").first
                ?? targetURI(request, target: target),
            "iat": Int(context.now.timeIntervalSince1970),
            "jti": base64url((0..<16).map { _ in UInt8.random(in: 0...255) }),
        ]
        if let token = context.accessToken { claims["ath"] = base64url(sha256(Array(token.utf8))) }
        if let nonce = context.dpopNonce { claims["nonce"] = nonce }
        let proof = try buildJWS(header: header, claims: claims, algorithm: algorithm, key: key)
        return request.settingHeader("DPoP", to: proof)
    }

    static func buildJWS(header: [String: Any], claims: [String: Any], algorithm: String, key: JWTKey) throws
        -> String
    {
        let headerJSON = try JSONSerialization.data(withJSONObject: header, options: [.sortedKeys])
        let claimsJSON = try JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys])
        let headerSegment = base64url(Array(headerJSON))
        let claimsSegment = base64url(Array(claimsJSON))
        let token = try JWT(headerSegment: headerSegment, payloadSegment: claimsSegment, signatureSegment: "")
            .signed(algorithm, key: key)
        return token.compact
    }

    // MARK: HTTP Message Signatures (RFC 9421)

    static func signMessage(
        _ request: RawRequest, target: HTTPTarget, secret: SigningSecret, algorithm: String, keyID: String,
        components: [String], context: SigningContext
    ) throws -> RawRequest {
        var request = request
        var components = components
        // Content-Digest is added (and covered) when requested and there is a body (RFC 9421 §2.1 + RFC 9530).
        if components.contains("content-digest") {
            let digest = "sha-256=:" + base64(sha256(bodyBytes(request))) + ":"
            request = request.settingHeader("Content-Digest", to: digest)
        }
        // The signature base (RFC 9421 §2.5): one line per component, then @signature-params.
        var lines: [String] = []
        for component in components {
            let value = try componentValue(component, request: request, target: target)
            lines.append("\"\(component.lowercased())\": \(value)")
        }
        let created = Int(context.now.timeIntervalSince1970)
        let coverage = components.map { "\"\($0.lowercased())\"" }.joined(separator: " ")
        let params = "(\(coverage));created=\(created);keyid=\"\(keyID)\";alg=\"\(algorithm)\""
        lines.append("\"@signature-params\": \(params)")
        let base = lines.joined(separator: "\n")
        let signature = try messageSignature(Array(base.utf8), algorithm: algorithm, secret: secret)
        let signatureB64 = base64(signature)
        return
            request
            .settingHeader("Signature-Input", to: "sig1=\(params)")
            .settingHeader("Signature", to: "sig1=:\(signatureB64):")
    }

    static func componentValue(_ component: String, request: RawRequest, target: HTTPTarget) throws -> String
    {
        switch component.lowercased() {
        case "@method": return method(request)
        case "@target-uri": return targetURI(request, target: target)
        case "@authority": return authority(request, target: target).lowercased()
        case "@path": return RawRequest.splitQuery(targetString(request)).path
        case "@query":
            let query = RawRequest.splitQuery(targetString(request)).query
            return query.isEmpty ? "?" : "?\(query)"
        default:
            guard let value = request.headerValue(component)?.string() else {
                throw SigningError.missingComponent(component)
            }
            return value.trimmingCharacters(in: .whitespaces)
        }
    }

    static func messageSignature(_ base: [UInt8], algorithm: String, secret: SigningSecret) throws -> [UInt8]
    {
        switch algorithm.lowercased() {
        case "hmac-sha256":
            guard case .hmac(let key) = secret else {
                throw SigningError.wrongKey("hmac-sha256 needs a shared secret")
            }
            return hmacSHA256(key, base)
        case "ecdsa-p256-sha256":
            guard case .ec(let curve, let raw) = secret, curve == .p256 else {
                throw SigningError.wrongKey("ecdsa-p256-sha256 needs a P-256 key")
            }
            return Array(
                try P256.Signing.PrivateKey(rawRepresentation: raw).signature(for: base).rawRepresentation)
        case "ed25519":
            throw SigningError.wrongKey("ed25519 message signatures aren't supported yet")
        default:
            throw SigningError.wrongKey(
                "message-signature algorithm \(algorithm) isn't supported (use hmac-sha256 or ecdsa-p256-sha256)"
            )
        }
    }

    // MARK: AWS SigV4

    static func signSigV4(
        _ request: RawRequest, target: HTTPTarget, secret: SigningSecret, region: String, service: String,
        context: SigningContext
    ) throws -> RawRequest {
        guard case .aws(let accessKey, let secretKey, let sessionToken) = secret else {
            throw SigningError.wrongKey("SigV4 needs AWS credentials")
        }
        var request = request
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        let amzDate = formatter.string(from: context.now)
        let dateStamp = String(amzDate.prefix(8))
        let payloadHash = hex(sha256(bodyBytes(request)))

        request = request.settingHeader("X-Amz-Date", to: amzDate)
        request = request.settingHeader("X-Amz-Content-Sha256", to: payloadHash)
        if let sessionToken { request = request.settingHeader("X-Amz-Security-Token", to: sessionToken) }
        let host = authority(request, target: target)
        request = request.settingHeader("Host", to: host)

        // Signed headers: host, x-amz-date, x-amz-content-sha256 and the security token when present.
        var signed: [(String, String)] = [
            ("host", host), ("x-amz-content-sha256", payloadHash), ("x-amz-date", amzDate),
        ]
        if let sessionToken { signed.append(("x-amz-security-token", sessionToken)) }
        signed.sort { $0.0 < $1.0 }
        let signedHeaders = signed.map(\.0).joined(separator: ";")
        let canonicalHeaders = signed.map { "\($0.0):\($0.1.trimmingCharacters(in: .whitespaces))\n" }
            .joined()

        let (path, query) = RawRequest.splitQuery(targetString(request))
        let canonicalRequest = [
            method(request), canonicalURIPath(path), canonicalQuery(query), canonicalHeaders, signedHeaders,
            payloadHash,
        ].joined(separator: "\n")

        let scope = "\(dateStamp)/\(region)/\(service)/aws4_request"
        let stringToSign = [
            "AWS4-HMAC-SHA256", amzDate, scope, hex(sha256(Array(canonicalRequest.utf8))),
        ].joined(separator: "\n")

        let kDate = hmacSHA256(Array("AWS4\(secretKey)".utf8), Array(dateStamp.utf8))
        let kRegion = hmacSHA256(kDate, Array(region.utf8))
        let kService = hmacSHA256(kRegion, Array(service.utf8))
        let kSigning = hmacSHA256(kService, Array("aws4_request".utf8))
        let signature = hex(hmacSHA256(kSigning, Array(stringToSign.utf8)))

        let authorization =
            "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(scope), SignedHeaders=\(signedHeaders), Signature=\(signature)"
        return request.settingHeader("Authorization", to: authorization)
    }

    static func canonicalURIPath(_ path: String) -> String {
        let p = path.isEmpty ? "/" : path
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~/")
        return p.addingPercentEncoding(withAllowedCharacters: allowed) ?? p
    }

    static func canonicalQuery(_ query: String) -> String {
        guard !query.isEmpty else { return "" }
        func encode(_ text: String) -> String {
            var allowed = CharacterSet.alphanumerics
            allowed.insert(charactersIn: "-._~")
            return text.addingPercentEncoding(withAllowedCharacters: allowed) ?? text
        }
        let pairs = query.split(separator: "&").map { pair -> (String, String) in
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            return (encode(parts[0]), parts.count > 1 ? encode(parts[1]) : "")
        }
        .sorted { $0.0 != $1.0 ? $0.0 < $1.0 : $0.1 < $1.1 }
        return pairs.map { "\($0.0)=\($0.1)" }.joined(separator: "&")
    }
}

/// Why signing failed.
public enum SigningError: Error, Sendable, CustomStringConvertible {
    /// The key material doesn't fit the scheme.
    case wrongKey(String)
    /// A covered component isn't present in the request.
    case missingComponent(String)

    public var description: String {
        switch self {
        case .wrongKey(let message): return message
        case .missingComponent(let component): return "the request has no \(component) to sign"
        }
    }
}
