// GulpHTTP — platform authentication (F03 HTTP-012): per-host credentials that answer a `401`
// challenge automatically. The engine sends the request; on a `401` whose `WWW-Authenticate` offers
// Digest or Basic, it sends it once more with the matching `Authorization` header (both exchanges
// are recorded). Digest follows RFC 7616 (MD5, MD5-sess, SHA-256, SHA-256-sess; qop=auth; the
// nonce count is kept per server nonce). NTLMv2 needs MD4 (not in swift-crypto) and connection
// affinity across three messages; it is not implemented yet (docs/PROGRESS.md carry-over).

import Crypto
import Foundation
import GulpCore

/// A username and password for one host (HTTP-012).
public struct PlatformCredential: Sendable, Codable, Hashable {
    /// The host it applies to (case-insensitive; `*.example.com` matches subdomains).
    public var host: String
    /// Username.
    public var username: String
    /// Password.
    public var password: String

    /// A credential.
    public init(host: String, username: String, password: String) {
        self.host = host
        self.username = username
        self.password = password
    }

    func matches(_ candidate: String) -> Bool {
        let pattern = host.lowercased()
        let name = candidate.lowercased()
        if pattern.hasPrefix("*.") { return name.hasSuffix(pattern.dropFirst(1)) }
        return name == pattern
    }
}

/// One authentication challenge from a `WWW-Authenticate` header.
public struct AuthChallenge: Sendable, Equatable {
    /// The scheme, lowercased (`basic`, `digest`, …).
    public var scheme: String
    /// Its parameters (names lowercased, values unquoted).
    public var parameters: [String: String]

    /// Every challenge in `response`'s `WWW-Authenticate` headers.
    public static func all(in response: RawResponse) -> [AuthChallenge] {
        response.parsed.headers
            .filter { response.bytes[$0.name].string().lowercased() == "www-authenticate" }
            .flatMap { parse(response.bytes[$0.value].string()) }
    }

    /// Parse a header value (several challenges may share one header, RFC 9110 §11.6.1).
    public static func parse(_ value: String) -> [AuthChallenge] {
        var challenges: [AuthChallenge] = []
        var chars = Substring(value)
        func skipSpaces() {
            while chars.first == " " || chars.first == "\t" || chars.first == "," { chars.removeFirst() }
        }
        func token() -> String {
            let end = chars.firstIndex { " \t,=".contains($0) } ?? chars.endIndex
            defer { chars = chars[end...] }
            return String(chars[..<end])
        }
        while true {
            skipSpaces()
            guard !chars.isEmpty else { break }
            var challenge = AuthChallenge(scheme: token().lowercased(), parameters: [:])
            // Parameters until the next `token SP` that starts a new challenge.
            while true {
                skipSpaces()
                let save = chars
                let name = token()
                guard !name.isEmpty else { break }
                while chars.first == " " { chars.removeFirst() }
                guard chars.first == "=" else {
                    chars = save  // a bare token: the next challenge's scheme (or a token68)
                    break
                }
                chars.removeFirst()
                while chars.first == " " { chars.removeFirst() }
                var parameter = ""
                if chars.first == "\"" {
                    chars.removeFirst()
                    while let c = chars.first, c != "\"" {
                        chars.removeFirst()
                        if c == "\\", let escaped = chars.first {
                            parameter.append(escaped)
                            chars.removeFirst()
                        } else {
                            parameter.append(c)
                        }
                    }
                    if !chars.isEmpty { chars.removeFirst() }
                } else {
                    parameter = token()
                    while chars.first == "=" {  // token68 padding, e.g. `Negotiate abc==`
                        parameter.append("=")
                        chars.removeFirst()
                    }
                }
                challenge.parameters[name.lowercased()] = parameter
            }
            challenges.append(challenge)
        }
        return challenges
    }
}

/// Computes `Authorization` headers.
public enum PlatformAuthorization {
    /// `Basic base64(user:password)`.
    public static func basic(_ credential: PlatformCredential) -> String {
        "Basic " + Data("\(credential.username):\(credential.password)".utf8).base64EncodedString()
    }

    /// The RFC 7616 Digest answer to `challenge` for `method` and `uri`, or nil for an algorithm or
    /// qop this can't do.
    public static func digest(
        _ challenge: AuthChallenge, credential: PlatformCredential, method: String, uri: String,
        nonceCount: Int, cnonce: String
    ) -> String? {
        let p = challenge.parameters
        guard let realm = p["realm"], let nonce = p["nonce"] else { return nil }
        let algorithm = p["algorithm"] ?? "MD5"
        let hash: (String) -> String
        switch algorithm.uppercased() {
        case "MD5", "MD5-SESS": hash = { Insecure.MD5.hash(data: Data($0.utf8)).hex }
        case "SHA-256", "SHA-256-SESS": hash = { SHA256.hash(data: Data($0.utf8)).hex }
        default: return nil
        }
        let offered = (p["qop"] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let qop: String? = offered.isEmpty ? nil : (offered.contains("auth") ? "auth" : nil)
        if !offered.isEmpty && qop == nil { return nil }  // only auth-int offered: not supported
        var ha1 = hash("\(credential.username):\(realm):\(credential.password)")
        if algorithm.uppercased().hasSuffix("-SESS") { ha1 = hash("\(ha1):\(nonce):\(cnonce)") }
        let ha2 = hash("\(method):\(uri)")
        let nc = String(format: "%08x", nonceCount)
        let response =
            qop.map { hash("\(ha1):\(nonce):\(nc):\(cnonce):\($0):\(ha2)") } ?? hash("\(ha1):\(nonce):\(ha2)")
        var fields = [
            "username=\"\(credential.username)\"", "realm=\"\(realm)\"", "nonce=\"\(nonce)\"",
            "uri=\"\(uri)\"",
            "algorithm=\(algorithm)", "response=\"\(response)\"",
        ]
        if let qop { fields += ["qop=\(qop)", "nc=\(nc)", "cnonce=\"\(cnonce)\""] }
        if let opaque = p["opaque"] { fields.append("opaque=\"\(opaque)\"") }
        return "Digest " + fields.joined(separator: ", ")
    }
}

/// The engine's platform-authentication credentials (HTTP-012).
public actor PlatformAuth {
    private var credentials: [PlatformCredential] = []
    private var nonceCounts: [String: Int] = [:]

    /// No credentials.
    public init() {}

    /// Replace the credentials (first matching host wins).
    public func set(_ credentials: [PlatformCredential]) {
        self.credentials = credentials
    }

    /// The `Authorization` value answering `response` (a 401) to `request` at `target`, or nil when
    /// there is no credential for the host or no challenge it can answer. Digest is preferred.
    func answer(_ response: RawResponse, to request: RawRequest, target: HTTPTarget) -> String? {
        guard response.parsed.statusCode == 401,
            let credential = credentials.first(where: { $0.matches(target.host) })
        else { return nil }
        let challenges = AuthChallenge.all(in: response)
        if let digest = challenges.first(where: { $0.scheme == "digest" }) {
            let nonce = digest.parameters["nonce"] ?? ""
            let count = (nonceCounts[nonce] ?? 0) + 1
            nonceCounts[nonce] = count
            let cnonce = (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
            return PlatformAuthorization.digest(
                digest, credential: credential, method: request.bytes[request.parsed.method].string(),
                uri: request.bytes[request.parsed.target].string(), nonceCount: count, cnonce: cnonce)
        }
        if challenges.contains(where: { $0.scheme == "basic" }) {
            return PlatformAuthorization.basic(credential)
        }
        return nil
    }
}

extension Digest {
    fileprivate var hex: String { map { String(format: "%02x", $0) }.joined() }
}

extension RawRequest {
    /// The request with header `name` set to `value`: the first field of that name has its value
    /// replaced (others are removed); without one, a field is added at the end of the header block.
    public func settingHeader(_ name: String, to value: String) -> RawRequest {
        let lower = name.lowercased()
        let fields = parsed.headers.filter { bytes[$0.name].string().lowercased() == lower }
        guard let first = fields.first else {
            let (end, terminator) = HTTP1.headerBlockEnd(bytes.rawBytes)
            guard terminator != 0 else { return self }
            let ending = terminator == 4 ? "\r\n" : "\n"
            let insertAt = end - (terminator == 4 ? 2 : 1)
            return replacing(insertAt..<insertAt, with: Bytes("\(name): \(value)\(ending)"))
        }
        var result = self
        for field in fields.dropFirst().reversed() {
            var end = field.line.upperBound
            let all = result.bytes.rawBytes
            if end < all.count, all[end] == 0x0D { end += 1 }
            if end < all.count, all[end] == 0x0A { end += 1 }
            result = result.replacing(field.line.lowerBound..<end, with: Bytes())
        }
        return result.replacing(first.value, with: Bytes(value))
    }
}
