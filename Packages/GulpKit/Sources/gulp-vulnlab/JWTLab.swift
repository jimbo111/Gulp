// gulp-vulnlab — the JWT lab (doc 06 §3 "Auth", F12 acceptance 5): `/api/me` trusts tokens it
// shouldn't, `/safe/api/me` doesn't. Deliberately written against swift-crypto directly, not Gulp's
// JWT code, so the M7 DoD tests Gulp against an independent verifier.
//
//   GET /api/login?user=alice           → an RS256 token (kid "vulnlab-rsa", 1 h)
//   GET /api/login?user=alice&alg=HS256 → an HS256 token signed with a weak secret from
//                                         Wordlists/jwt-secrets.txt
//   GET /api/key.pem, /.well-known/jwks.json → the RSA public key
//   GET /api/me       (vulnerable) accepts: alg "none" (any case) unsigned; HS256 verified with the
//                     RSA public key PEM as the secret (RS→HS confusion) or the weak secret; a `kid`
//                     that traverses to /dev/null (empty HMAC key); RS256 with the real key.
//   GET /safe/api/me  accepts only RS256 signed with the real key, unexpired.

import Crypto
import Foundation
import _CryptoExtras

enum JWTLab {
    /// The weak HMAC secret (it is in Wordlists/jwt-secrets.txt).
    static let weakSecret = "secret123"

    /// Generated on first use (static lets initialise once, thread-safely); tokens don't survive a
    /// restart, which is fine for a lab.
    static let key: _RSA.Signing.PrivateKey = {
        guard let key = try? _RSA.Signing.PrivateKey(keySize: .bits2048) else {
            fatalError("RSA key generation failed")
        }
        return key
    }()

    static var publicPEM: String { key.publicKey.pemRepresentation + "\n" }

    static func b64url(_ bytes: some DataProtocol) -> String {
        Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    static func unb64url(_ text: Substring) -> Data? {
        var value = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while value.count % 4 != 0 { value += "=" }
        return Data(base64Encoded: value)
    }

    static func login(user: String, alg: String) -> VulnReply {
        let now = Int(Date().timeIntervalSince1970)
        let claims = #"{"exp":\#(now + 3600),"iat":\#(now),"role":"user","sub":"\#(user)"}"#
        let header =
            alg == "HS256"
            ? #"{"alg":"HS256","typ":"JWT"}"# : #"{"alg":"RS256","kid":"vulnlab-rsa","typ":"JWT"}"#
        let input = b64url(Data(header.utf8)) + "." + b64url(Data(claims.utf8))
        let signature: Data
        if alg == "HS256" {
            signature = Data(
                HMAC<SHA256>.authenticationCode(
                    for: Data(input.utf8), using: SymmetricKey(data: Data(weakSecret.utf8))))
        } else {
            guard
                let rsa = try? key.signature(
                    for: SHA256.hash(data: Data(input.utf8)), padding: .insecurePKCS1v1_5)
            else {
                return VulnLab.json(500, #"{"error":"signing failed"}"#)
            }
            signature = rsa.rawRepresentation
        }
        return VulnLab.json(200, #"{"token":"\#(input).\#(b64url(signature))"}"#)
    }

    static func jwks() -> VulnReply {
        guard let primitives = try? key.publicKey.getKeyPrimitives() else { return VulnLab.json(500, "{}") }
        let jwk =
            #"{"alg":"RS256","e":"\#(b64url(primitives.publicExponent))","kid":"vulnlab-rsa","kty":"RSA","n":"\#(b64url(primitives.modulus))","use":"sig"}"#
        return VulnLab.json(200, #"{"keys":[\#(jwk)]}"#)
    }

    /// `/api/me` (`safe: false`) or `/safe/api/me` (`safe: true`).
    static func me(_ authorization: String?, safe: Bool) -> VulnReply {
        guard let authorization, authorization.lowercased().hasPrefix("bearer ") else {
            return VulnLab.json(401, #"{"error":"missing bearer token"}"#)
        }
        let token = authorization.dropFirst(7).trimmingCharacters(in: .whitespaces)
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let headerData = unb64url(parts[0]), let claimsData = unb64url(parts[1]),
            let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
            let claims = try? JSONSerialization.jsonObject(with: claimsData) as? [String: Any]
        else { return VulnLab.json(401, #"{"error":"malformed token"}"#) }
        if let exp = (claims["exp"] as? NSNumber)?.doubleValue, exp < Date().timeIntervalSince1970 {
            return VulnLab.json(401, #"{"error":"token expired"}"#)
        }
        let alg = header["alg"] as? String ?? ""
        let input = Data("\(parts[0]).\(parts[1])".utf8)
        let signature = unb64url(parts[2]) ?? Data()
        var accepted = false
        if alg == "RS256" {
            accepted = key.publicKey.isValidSignature(
                _RSA.Signing.RSASignature(rawRepresentation: signature), for: SHA256.hash(data: input),
                padding: .insecurePKCS1v1_5)
        } else if !safe {
            if alg.lowercased() == "none" {
                accepted = true  // VULNERABLE: unsigned tokens
            } else if alg == "HS256" {
                var secrets: [Data] = [Data(publicPEM.utf8), Data(weakSecret.utf8)]  // VULNERABLE: key confusion, weak secret
                if let kid = header["kid"] as? String, kid.contains("../") {
                    // VULNERABLE: kid is a path; "../…/dev/null" reads an empty key.
                    secrets = kid.hasSuffix("dev/null") ? [Data()] : []
                }
                accepted = secrets.contains { secret in
                    let mac = Data(
                        HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: secret)))
                    return mac == signature
                }
            }
        }
        guard accepted else { return VulnLab.json(401, #"{"error":"invalid token"}"#) }
        let user = claims["sub"] as? String ?? "?"
        let role = claims["role"] as? String ?? "user"
        return VulnLab.json(200, #"{"role":"\#(role)","user":"\#(user)"}"#)
    }
}
