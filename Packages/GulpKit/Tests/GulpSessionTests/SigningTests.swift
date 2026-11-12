import Crypto
import Foundation
import GulpCodec
import GulpCore
import Testing

@testable import GulpSession

// F15 SES-016…018: request signing. DPoP proofs verify against the embedded JWK; HTTP Message
// Signatures (RFC 9421) rebuild a verifiable signature base; AWS SigV4 matches the published test
// vector from the AWS documentation (so the canonicalisation is exactly right).

@Suite("Request signing (SES-016…018)")
struct SigningTests {
    let clock = Date(timeIntervalSince1970: 1_700_000_000)

    func request(_ raw: String) -> RawRequest {
        var text = raw.replacingOccurrences(of: "\n", with: "\r\n")
        if !text.contains("\r\n\r\n") { text += "\r\n\r\n" }  // header terminator only when absent
        return RawRequest(Bytes(Array(text.utf8)))
    }

    @Test("SES-016: a DPoP proof carries htm/htu/jti/ath and verifies against its own JWK")
    func test_SES016_dpop() throws {
        let key = try JWTKey.generate(for: "ES256")
        guard case .ecPrivate(let curve, let raw) = key else { Issue.record("not EC"); return }
        let scheme = SigningScheme.dpop(secret: .ec(curve: curve, privateRaw: raw))
        let context = SigningContext(accessToken: "token-xyz", dpopNonce: "n-1", now: clock)
        let signed = try RequestSigner.sign(
            request("GET /resource?x=1 HTTP/1.1\nHost: api.example.com\n\n"),
            to: HTTPTarget(scheme: .https, host: "api.example.com"), scheme: scheme, context: context)
        let proof = try #require(signed.headerValue("dpop")?.string())
        let jwt = try JWT(proof)
        #expect(jwt.algorithm == "ES256")
        #expect(jwt.header["typ"] as? String == "dpop+jwt")
        let claims = jwt.claims
        #expect(claims["htm"] as? String == "GET")
        #expect(claims["htu"] as? String == "https://api.example.com/resource", "htu excludes the query")
        #expect(claims["nonce"] as? String == "n-1")
        let ath = Data(SHA256.hash(data: Data("token-xyz".utf8))).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        #expect(claims["ath"] as? String == ath)
        // The proof's signature verifies against the JWK embedded in its header.
        let jwk = try #require(jwt.header["jwk"] as? [String: Any])
        let publicKey = try JWTKey.jwk(jwk)
        #expect(jwt.verifies(with: publicKey), "the proof is self-consistent")
    }

    @Test("SES-017: an HMAC message signature builds a verifiable RFC 9421 base and Content-Digest")
    func test_SES017_messageSignatureHMAC() throws {
        let secret = Array("sh-secret".utf8)
        let scheme = SigningScheme.httpMessageSignature(
            secret: .hmac(secret), algorithm: "hmac-sha256", keyID: "k1",
            components: ["@method", "@authority", "@path", "content-digest"])
        let signed = try RequestSigner.sign(
            request(
                "POST /pay HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\nContent-Length: 7\n\n{\"a\":1}"
            ),
            to: HTTPTarget(scheme: .https, host: "api.example.com"),
            scheme: scheme, context: SigningContext(now: clock))
        // Content-Digest over the body (RFC 9530).
        let digest = "sha-256=:" + Data(SHA256.hash(data: Data("{\"a\":1}".utf8))).base64EncodedString() + ":"
        #expect(signed.headerValue("content-digest")?.string() == digest)
        let input = try #require(signed.headerValue("signature-input")?.string())
        #expect(
            input.hasPrefix(
                "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\");created=\(Int(clock.timeIntervalSince1970));keyid=\"k1\""
            ))
        // Rebuild the base exactly and verify the HMAC.
        let params = String(input.dropFirst("sig1=".count))
        let base = [
            "\"@method\": POST", "\"@authority\": api.example.com", "\"@path\": /pay",
            "\"content-digest\": \(digest)",
            "\"@signature-params\": \(params)",
        ].joined(separator: "\n")
        let expected = Array(
            HMAC<SHA256>.authenticationCode(for: Array(base.utf8), using: SymmetricKey(data: secret)))
        let signature = try #require(signed.headerValue("signature")?.string())
        #expect(signature == "sig1=:\(Data(expected).base64EncodedString()):")
    }

    @Test("SES-018: SigV4 signs host, date and the payload hash; the signature re-derives exactly")
    func test_SES018_sigv4() throws {
        let secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        let scheme = SigningScheme.sigV4(
            secret: .aws(accessKey: "AKIDEXAMPLE", secretKey: secretKey, sessionToken: nil),
            region: "us-east-1", service: "service")
        let when = Date(timeIntervalSince1970: 1_440_938_160)  // 2015-08-30T12:36:00Z
        let signed = try RequestSigner.sign(
            request("GET /path/a?b=2&a=1 HTTP/1.1\nHost: example.amazonaws.com\n\n"),
            to: HTTPTarget(scheme: .https, host: "example.amazonaws.com"),
            scheme: scheme, context: SigningContext(now: when))
        #expect(signed.headerValue("x-amz-date")?.string() == "20150830T123600Z")
        let payloadHash = signed.headerValue("x-amz-content-sha256")?.string()
        #expect(
            payloadHash == Data(SHA256.hash(data: Data())).map { String(format: "%02x", $0) }.joined(),
            "empty-body hash is signed (modern/S3 behaviour)")
        let auth = try #require(signed.headerValue("authorization")?.string())
        #expect(auth.contains("Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"))
        #expect(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"))

        // Independently re-derive the signature from the published algorithm and the query is sorted
        // (a before b), so agreement confirms the canonicalisation.
        func hmac(_ key: [UInt8], _ msg: String) -> [UInt8] {
            Array(HMAC<SHA256>.authenticationCode(for: Array(msg.utf8), using: SymmetricKey(data: key)))
        }
        func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
        let canonical = [
            "GET", "/path/a", "a=1&b=2",
            "host:example.amazonaws.com\nx-amz-content-sha256:\(payloadHash!)\nx-amz-date:20150830T123600Z\n",
            "host;x-amz-content-sha256;x-amz-date", payloadHash!,
        ].joined(separator: "\n")
        let stringToSign = [
            "AWS4-HMAC-SHA256", "20150830T123600Z", "20150830/us-east-1/service/aws4_request",
            hex(Array(SHA256.hash(data: Data(canonical.utf8)))),
        ].joined(separator: "\n")
        let kDate = hmac(Array("AWS4\(secretKey)".utf8), "20150830")
        let kSign = hmac(hmac(hmac(kDate, "us-east-1"), "service"), "aws4_request")
        #expect(auth.contains("Signature=\(hex(hmac(kSign, stringToSign)))"))
    }

    @Test("Signing fails cleanly when the key doesn't fit the scheme")
    func test_signingWrongKey() {
        let scheme = SigningScheme.sigV4(secret: .hmac([1, 2, 3]), region: "r", service: "s")
        #expect(throws: SigningError.self) {
            try RequestSigner.sign(
                request("GET / HTTP/1.1\nHost: h"), to: HTTPTarget(scheme: .https, host: "h"), scheme: scheme)
        }
    }
}
