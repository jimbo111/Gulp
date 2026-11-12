// gulp-vulnlab — request-signing fixtures (F15 SES-016…018, the M12a DoD): three endpoints that
// accept a request only when it carries a valid signature, each verified by an INDEPENDENT
// implementation (swift-crypto directly, not Gulp's RequestSigner), so a 200 proves real interop:
//
//   /signed/dpop      requires a DPoP proof (RFC 9449) whose JWS verifies against its own JWK and
//                     whose htm/htu match the request; on the first call it demands a nonce (401 with
//                     DPoP-Nonce) so the retry path is exercised.
//   /signed/http-sig  requires an RFC 9421 signature over @method/@target-uri/content-digest with the
//                     shared HMAC key `http-sig-secret`.
//   /signed/sigv4     requires an AWS SigV4 Authorization built from the fixed demo credentials.
//
// The safe twins aren't needed here; the "without the signing action" case in the DoD is just the
// same request sent with no signature, which these endpoints answer 401.

import Crypto
import Foundation
import GulpCore

enum SignedLab {
    static let hmacKey = Array("http-sig-secret".utf8)
    static let awsAccessKey = "GULPACCESSKEY"
    static let awsSecretKey = "gulp/secret/key/EXAMPLEEXAMPLEEXAMPLE"
    static let awsRegion = "us-east-1"
    static let awsService = "execute-api"

    static func text(_ body: String, status: Int = 200, headers: [String] = []) -> VulnReply {
        VulnReply(bytes: VulnLab.response(status, body: Array(body.utf8), headers: headers))
    }

    static func respond(_ request: RawRequest, path: String) -> VulnReply? {
        switch path {
        case "/signed/dpop": return dpop(request)
        case "/signed/http-sig": return httpSig(request)
        case "/signed/sigv4": return sigv4(request)
        default: return nil
        }
    }

    static func method(_ request: RawRequest) -> String {
        request.bytes[request.parsed.method].string().uppercased()
    }
    static func target(_ request: RawRequest) -> String { request.bytes[request.parsed.target].string() }
    static func body(_ request: RawRequest) -> [UInt8] { Array(request.bytes.rawBytes[request.parsed.body]) }
    static func host(_ request: RawRequest) -> String {
        request.headerValue("host")?.string() ?? "127.0.0.1:8088"
    }

    static func b64urlDecode(_ text: String) -> Data? {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }

    // MARK: DPoP (RFC 9449) — independent verification

    static func dpop(_ request: RawRequest) -> VulnReply {
        guard let proof = request.headerValue("dpop")?.string() else {
            return text("missing DPoP proof", status: 401)
        }
        let segments = proof.split(separator: ".").map(String.init)
        guard segments.count == 3,
            let headerData = b64urlDecode(segments[0]), let claimsData = b64urlDecode(segments[1]),
            let signature = b64urlDecode(segments[2]),
            let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
            let claims = try? JSONSerialization.jsonObject(with: claimsData) as? [String: Any]
        else { return text("malformed DPoP proof", status: 401) }
        // Require a nonce once, so the client has to read DPoP-Nonce and retry (RFC 9449 §8).
        if claims["nonce"] == nil {
            return text("use_dpop_nonce", status: 401, headers: ["DPoP-Nonce: gulp-nonce-1"])
        }
        guard header["typ"] as? String == "dpop+jwt", (header["alg"] as? String)?.hasPrefix("ES") == true,
            let jwk = header["jwk"] as? [String: Any], let x = jwk["x"] as? String,
            let y = jwk["y"] as? String,
            let xData = b64urlDecode(x), let yData = b64urlDecode(y)
        else { return text("bad DPoP header", status: 401) }
        // Verify the ES256 signature over header.claims against the embedded P-256 JWK.
        let signingInput = Array("\(segments[0]).\(segments[1])".utf8)
        guard let key = try? P256.Signing.PublicKey(rawRepresentation: xData + yData),
            let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
            key.isValidSignature(ecdsa, for: SHA256.hash(data: Data(signingInput)))
        else { return text("DPoP signature invalid", status: 401) }
        guard claims["htm"] as? String == method(request) else {
            return text("DPoP htm mismatch", status: 401)
        }
        let expectedHTU =
            "http://\(host(request))\(target(request).split(separator: "?").first.map(String.init) ?? "")"
        guard claims["htu"] as? String == expectedHTU else {
            return text("DPoP htu mismatch (\(claims["htu"] ?? "nil") vs \(expectedHTU))", status: 401)
        }
        return text("dpop ok: authenticated with a valid proof")
    }

    // MARK: HTTP Message Signatures (RFC 9421) — independent verification

    static func httpSig(_ request: RawRequest) -> VulnReply {
        guard let input = request.headerValue("signature-input")?.string(),
            let signature = request.headerValue("signature")?.string()
        else { return text("missing Signature-Input/Signature", status: 401) }
        // Parse `sig1=(...);created=..;keyid=..;alg=..`.
        guard let eq = input.firstIndex(of: "="), let paren = input.firstIndex(of: "(") else {
            return text("malformed Signature-Input", status: 401)
        }
        let label = String(input[..<eq])
        let params = String(input[input.index(after: eq)...])
        guard let close = params.firstIndex(of: ")") else { return text("malformed coverage", status: 401) }
        let covered = params[params.index(after: params.startIndex)..<close]
            .split(separator: " ").map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\"")) }
        // Rebuild the base from the covered components.
        var lines: [String] = []
        for component in covered {
            let value: String
            switch component {
            case "@method": value = method(request)
            case "@target-uri": value = "http://\(host(request))\(target(request))"
            case "@authority": value = host(request).lowercased()
            case "@path": value = String(target(request).split(separator: "?").first ?? "")
            default:
                guard let v = request.headerValue(component)?.string() else {
                    return text("covered header \(component) missing", status: 401)
                }
                value = v.trimmingCharacters(in: .whitespaces)
            }
            lines.append("\"\(component)\": \(value)")
        }
        lines.append("\"@signature-params\": \(params)")
        let base = lines.joined(separator: "\n")
        let expected = Array(
            HMAC<SHA256>.authenticationCode(for: Array(base.utf8), using: SymmetricKey(data: hmacKey)))
        // The Signature value is `label=:base64:`.
        let wanted = "\(label)=:" + Data(expected).base64EncodedString() + ":"
        guard signature == wanted else { return text("signature mismatch", status: 401) }
        // Content-Digest, when covered, must match the body.
        if covered.contains("content-digest"), let digest = request.headerValue("content-digest")?.string() {
            let actual =
                "sha-256=:" + Data(SHA256.hash(data: Data(body(request)))).base64EncodedString() + ":"
            guard digest == actual else { return text("content-digest mismatch", status: 401) }
        }
        return text("http-sig ok: RFC 9421 signature verified")
    }

    // MARK: AWS SigV4 — independent verification

    static func sigv4(_ request: RawRequest) -> VulnReply {
        guard let auth = request.headerValue("authorization")?.string(), auth.hasPrefix("AWS4-HMAC-SHA256"),
            let amzDate = request.headerValue("x-amz-date")?.string(),
            let payloadHash = request.headerValue("x-amz-content-sha256")?.string()
        else { return text("missing SigV4 headers", status: 401) }
        // Parse Credential, SignedHeaders and Signature.
        func field(_ name: String) -> String? {
            guard let range = auth.range(of: "\(name)=") else { return nil }
            let rest = auth[range.upperBound...]
            return String(rest.prefix { $0 != "," })
        }
        guard let credential = field("Credential"), let signedHeaders = field("SignedHeaders"),
            let provided = field("Signature"), credential.hasPrefix(awsAccessKey + "/")
        else { return text("malformed Authorization", status: 401) }
        let dateStamp = String(amzDate.prefix(8))
        // Canonical headers in the order SignedHeaders lists.
        var canonicalHeaders = ""
        for name in signedHeaders.split(separator: ";") {
            let value: String
            switch name {
            case "host": value = host(request)
            case "x-amz-date": value = amzDate
            case "x-amz-content-sha256": value = payloadHash
            default:
                value = request.headerValue(String(name))?.string().trimmingCharacters(in: .whitespaces) ?? ""
            }
            canonicalHeaders += "\(name):\(value)\n"
        }
        let parts = target(request).split(separator: "?", maxSplits: 1).map(String.init)
        let path = parts.first ?? "/"
        let query = parts.count > 1 ? canonicalQuery(parts[1]) : ""
        let canonicalRequest = [
            method(request), path, query, canonicalHeaders, signedHeaders, payloadHash,
        ].joined(separator: "\n")
        let scope = "\(dateStamp)/\(awsRegion)/\(awsService)/aws4_request"
        let stringToSign = [
            "AWS4-HMAC-SHA256", amzDate, scope, hex(Array(SHA256.hash(data: Data(canonicalRequest.utf8)))),
        ].joined(separator: "\n")
        let kDate = hmac(Array("AWS4\(awsSecretKey)".utf8), Array(dateStamp.utf8))
        let kSigning = hmac(
            hmac(hmac(kDate, Array(awsRegion.utf8)), Array(awsService.utf8)), Array("aws4_request".utf8))
        let expected = hex(hmac(kSigning, Array(stringToSign.utf8)))
        guard provided == expected else { return text("sigv4 signature mismatch", status: 401) }
        return text("sigv4 ok: AWS SigV4 signature verified")
    }

    static func canonicalQuery(_ query: String) -> String {
        func encode(_ text: String) -> String {
            var allowed = CharacterSet.alphanumerics
            allowed.insert(charactersIn: "-._~")
            return text.addingPercentEncoding(withAllowedCharacters: allowed) ?? text
        }
        var pairs: [(String, String)] = []
        for pair in query.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1).map(String.init)
            pairs.append((encode(kv[0]), kv.count > 1 ? encode(kv[1]) : ""))
        }
        pairs.sort { $0.0 != $1.0 ? $0.0 < $1.0 : $0.1 < $1.1 }
        return pairs.map { "\($0.0)=\($0.1)" }.joined(separator: "&")
    }

    static func hmac(_ key: [UInt8], _ message: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
}
