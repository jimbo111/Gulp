// GulpOAST — the OAST client (F10 BCN-001, BCN-002, BCN-005). Gulp speaks the interactsh protocol
// to every OAST server: public or self-hosted interactsh servers and Gulp's own dev Beacon, which
// implements the same API. The wire format follows the interactsh source (2026):
//
// - register: POST /register {"public-key", "secret-key", "correlation-id"}; the public key is the
//   base64 of a PEM block labelled "RSA PUBLIC KEY" holding a PKIX (SubjectPublicKeyInfo) RSA-2048
//   key. The correlation id is 20 characters of the xid alphabet (0-9, a-v).
// - payload hosts are `<correlation-id><13-char zbase32 nonce>.<domain>`; the 33-character prefix is
//   the "unique id" an interaction reports, so every payload is unique (BCN-001).
// - poll: GET /poll?id=<correlation-id>&secret=<secret> → {"data": [...], "extra": [...],
//   "aes_key": ...}. `aes_key` is the session's AES-256 key, RSA-OAEP(SHA-256)-encrypted to our
//   key; each `data` item is base64(IV ‖ AES-256-CTR(interaction JSON)). `extra` items are plain JSON.
// - deregister: POST /deregister {"correlation-id", "secret-key"}.
// An `Authorization` header carries the server's token when it requires one.

import Crypto
import Foundation
import GulpCore
import _CryptoExtras

/// A correlation payload (BCN-001).
public struct OASTPayload: Sendable, Hashable, Codable {
    /// The unique id (33 lowercase characters): the correlation key stored with its context.
    public var id: String
    /// The hostname to inject (`<id>.<domain>`).
    public var host: String

    /// `http://<host>/`.
    public var httpURL: String { "http://\(host)/" }
    /// `https://<host>/`.
    public var httpsURL: String { "https://\(host)/" }
    /// An email address on the payload host.
    public var email: String { "gulp@\(host)" }
}

/// One interaction the server saw (BCN-002).
public struct OASTInteraction: Sendable, Hashable, Codable {
    /// `dns`, `http`, `https`, `smtp`…
    public var proto: String
    /// The 33-character unique id (lowercased): which payload.
    public var uniqueID: String
    /// The full subdomain that reached the server.
    public var fullID: String
    /// DNS query type (`A`, `AAAA`…), when DNS.
    public var queryType: String?
    /// The raw request (HTTP) or query (DNS) text.
    public var rawRequest: String
    /// The server's raw response.
    public var rawResponse: String
    /// Who interacted.
    public var remoteAddress: String
    /// When (server clock).
    public var timestamp: Date

    /// An interaction.
    public init(
        proto: String, uniqueID: String, fullID: String, queryType: String? = nil, rawRequest: String = "",
        rawResponse: String = "", remoteAddress: String = "", timestamp: Date = Date()
    ) {
        self.proto = proto
        self.uniqueID = uniqueID.lowercased()
        self.fullID = fullID
        self.queryType = queryType
        self.rawRequest = rawRequest
        self.rawResponse = rawResponse
        self.remoteAddress = remoteAddress
        self.timestamp = timestamp
    }

    /// Decode interactsh's JSON form.
    public init?(json: [String: Any]) {
        guard let proto = json["protocol"] as? String, let unique = json["unique-id"] as? String else {
            return nil
        }
        self.init(
            proto: proto, uniqueID: unique, fullID: json["full-id"] as? String ?? unique,
            queryType: (json["q-type"] as? String).flatMap { $0.isEmpty ? nil : $0 },
            rawRequest: json["raw-request"] as? String ?? "",
            rawResponse: json["raw-response"] as? String ?? "",
            remoteAddress: json["remote-address"] as? String ?? "",
            timestamp: (json["timestamp"] as? String).flatMap(Interactsh.parseDate) ?? Date())
    }

    /// interactsh's JSON form (what a server stores and encrypts).
    public var json: [String: Any] {
        var object: [String: Any] = [
            "protocol": proto, "unique-id": uniqueID, "full-id": fullID, "raw-request": rawRequest,
            "raw-response": rawResponse, "remote-address": remoteAddress,
            "timestamp": Interactsh.formatDate(timestamp),
        ]
        if let queryType { object["q-type"] = queryType }
        return object
    }
}

/// An OAST failure (registration, polling or decryption).
public struct OASTError: Error, Sendable, Hashable, CustomStringConvertible {
    /// What went wrong.
    public var message: String

    /// An error.
    public init(_ message: String) { self.message = message }

    /// A readable form of the error: its message.
    public var description: String { message }
}

/// How the client reaches the server (the workspace passes one built on the engine, unrecorded).
public protocol OASTTransport: Sendable {
    /// Send a request; returns the status and body.
    func send(method: String, url: String, body: [UInt8]?, headers: [String: String]) async throws -> (
        status: Int, body: [UInt8]
    )
}

/// Protocol constants and crypto shared by the client and test servers.
public enum Interactsh {
    /// Correlation id length.
    public static let correlationIDLength = 20
    /// Nonce length.
    public static let nonceLength = 13
    /// The xid alphabet (correlation ids).
    public static let xidAlphabet = Array("0123456789abcdefghijklmnopqrstuv")
    /// The zbase32 alphabet (nonces).
    public static let zbase32Alphabet = Array("ybndrfg8ejkmcpqxot1uwisza345h769")

    /// A random string from `alphabet`.
    public static func random(_ count: Int, from alphabet: [Character]) -> String {
        var generator = SystemRandomNumberGenerator()
        return String((0..<count).map { _ in alphabet[Int(generator.next() % UInt64(alphabet.count))] })
    }

    /// Whether `text` is a 33-character unique id (xid prefix + zbase32 nonce).
    public static func isUniqueID(_ text: some StringProtocol) -> Bool {
        let chars = Array(text.lowercased())
        guard chars.count == correlationIDLength + nonceLength else { return false }
        return chars.prefix(correlationIDLength).allSatisfy(xidAlphabet.contains)
            && chars.suffix(nonceLength).allSatisfy(zbase32Alphabet.contains)
    }

    /// The first unique id in a hostname or text (interactsh slides a 33-character window over each
    /// label), lowercased; nil if none.
    public static func uniqueID(in text: String) -> String? {
        for label in text.lowercased().split(whereSeparator: { ".\n\t\"'/: ".contains($0) }) {
            let chars = Array(label)
            let width = correlationIDLength + nonceLength
            guard chars.count >= width else { continue }
            for start in 0...(chars.count - width) {
                let window = String(chars[start..<start + width])
                if isUniqueID(window) { return window }
            }
        }
        return nil
    }

    /// Base64 of a PEM "RSA PUBLIC KEY" block holding the PKIX DER of `key` (interactsh's format).
    public static func encodePublicKey(_ key: _RSA.Encryption.PublicKey) -> String {
        let body = key.derRepresentation.base64EncodedString(options: [
            .lineLength64Characters, .endLineWithLineFeed,
        ])
        let pem = "-----BEGIN RSA PUBLIC KEY-----\n\(body)\n-----END RSA PUBLIC KEY-----\n"
        return Data(pem.utf8).base64EncodedString()
    }

    /// The key in `encodePublicKey`'s format.
    public static func decodePublicKey(_ text: String) throws -> _RSA.Encryption.PublicKey {
        guard let pemData = Data(base64Encoded: text) else { throw OASTError("public key isn't base64") }
        let pem = String(decoding: pemData, as: UTF8.self)
        let body = pem.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
        guard let der = Data(base64Encoded: body) else { throw OASTError("public key PEM is malformed") }
        return try _RSA.Encryption.PublicKey(derRepresentation: der)
    }

    /// Decrypt one poll item: unwrap the AES key with `privateKey`, then AES-256-CTR with the IV in
    /// the first 16 bytes.
    public static func decrypt(_ item: String, aesKey: String, privateKey: _RSA.Encryption.PrivateKey) throws
        -> [UInt8]
    {
        guard let wrapped = Data(base64Encoded: aesKey) else { throw OASTError("aes_key isn't base64") }
        let key = try privateKey.decrypt(wrapped, padding: .PKCS1_OAEP_SHA256)
        return try decrypt(item, key: SymmetricKey(data: key))
    }

    /// AES-256-CTR decrypt of `base64(IV ‖ ciphertext)`.
    public static func decrypt(_ item: String, key: SymmetricKey) throws -> [UInt8] {
        guard let data = Data(base64Encoded: item), data.count >= 16 else {
            throw OASTError("interaction isn't base64")
        }
        let nonce = try AES._CTR.Nonce(nonceBytes: data.prefix(16))
        return Array(try AES._CTR.decrypt(data.dropFirst(16), using: key, nonce: nonce))
    }

    /// AES-256-CTR encrypt to `base64(IV ‖ ciphertext)` (the server side).
    public static func encrypt(_ message: [UInt8], key: SymmetricKey) throws -> String {
        var iv = [UInt8](repeating: 0, count: 16)
        var generator = SystemRandomNumberGenerator()
        for index in iv.indices { iv[index] = UInt8.random(in: 0...255, using: &generator) }
        let ciphertext = try AES._CTR.encrypt(message, using: key, nonce: AES._CTR.Nonce(nonceBytes: iv))
        return (Data(iv) + ciphertext).base64EncodedString()
    }

    /// RSA-OAEP(SHA-256) of `key` to `publicKey`, base64 (the server side).
    public static func wrap(_ key: SymmetricKey, for publicKey: _RSA.Encryption.PublicKey) throws -> String {
        let raw = key.withUnsafeBytes { Data($0) }
        return try publicKey.encrypt(raw, padding: .PKCS1_OAEP_SHA256).base64EncodedString()
    }

    static func parseDate(_ text: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: text) { return date }
        // Go's RFC 3339 with nanoseconds: drop digits past milliseconds.
        if let dot = text.firstIndex(of: "."),
            let zone = text[dot...].firstIndex(where: { $0 == "Z" || $0 == "+" || $0 == "-" })
        {
            let trimmed =
                String(text[..<dot]) + "." + text[text.index(after: dot)..<zone].prefix(3) + text[zone...]
            if let date = formatter.date(from: trimmed) { return date }
        }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: text)
    }

    static func formatDate(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}

/// A registered interactsh session (BCN-002, BCN-005).
public actor InteractshClient {
    /// The server, e.g. `https://oast.example.com` or the dev Beacon `http://127.0.0.1:8090`.
    public let serverURL: String
    /// The domain payload hosts live under (default: the server's host).
    public let domain: String
    private let token: String?
    private let transport: any OASTTransport
    private let privateKey: _RSA.Encryption.PrivateKey
    /// The session's correlation id.
    public let correlationID: String
    private let secretKey: String
    /// Whether `register` succeeded (and `deregister` hasn't run).
    public private(set) var registered = false

    /// A client (generates a fresh RSA-2048 key and correlation id; call `register` next).
    public init(serverURL: String, domain: String? = nil, token: String? = nil, transport: any OASTTransport)
        throws
    {
        var server = serverURL
        while server.hasSuffix("/") { server.removeLast() }
        self.serverURL = server
        let host =
            server.split(separator: "/").dropFirst().first.map {
                String($0.split(separator: ":").first ?? $0)
            } ?? ""
        self.domain = (domain?.isEmpty == false ? domain! : host).lowercased()
        self.token = token
        self.transport = transport
        privateKey = try _RSA.Encryption.PrivateKey(keySize: .bits2048)
        correlationID = Interactsh.random(Interactsh.correlationIDLength, from: Interactsh.xidAlphabet)
        secretKey = UUID().uuidString.lowercased()
    }

    private var headers: [String: String] {
        var headers = ["Content-Type": "application/json"]
        if let token, !token.isEmpty { headers["Authorization"] = token }
        return headers
    }

    /// Register with the server.
    public func register() async throws {
        let body: [String: String] = [
            "public-key": Interactsh.encodePublicKey(privateKey.publicKey), "secret-key": secretKey,
            "correlation-id": correlationID,
        ]
        let (status, data) = try await transport.send(
            method: "POST", url: serverURL + "/register",
            body: Array(try JSONSerialization.data(withJSONObject: body)),
            headers: headers)
        let object = (try? JSONSerialization.jsonObject(with: Data(data))) as? [String: Any]
        guard status == 200, object?["message"] as? String == "registration successful" else {
            if status == 401 { throw OASTError("the server needs a token (401)") }
            throw OASTError(
                "registration failed (HTTP \(status)): \(object?["error"] as? String ?? String(decoding: data.prefix(200), as: UTF8.self))"
            )
        }
        registered = true
    }

    /// A new payload (unique per call).
    public func newPayload() -> OASTPayload {
        let id = correlationID + Interactsh.random(Interactsh.nonceLength, from: Interactsh.zbase32Alphabet)
        return OASTPayload(id: id, host: "\(id).\(domain)")
    }

    /// Interactions since the last poll.
    public func poll() async throws -> [OASTInteraction] {
        guard registered else { throw OASTError("not registered") }
        let (status, data) = try await transport.send(
            method: "GET", url: "\(serverURL)/poll?id=\(correlationID)&secret=\(secretKey)", body: nil,
            headers: headers)
        guard status == 200 else {
            if status == 401 { throw OASTError("the server needs a token (401)") }
            throw OASTError(
                "poll failed (HTTP \(status)): \(String(decoding: data.prefix(200), as: UTF8.self))")
        }
        guard let object = (try? JSONSerialization.jsonObject(with: Data(data))) as? [String: Any] else {
            throw OASTError("poll returned something other than JSON")
        }
        var interactions: [OASTInteraction] = []
        let aesKey = object["aes_key"] as? String ?? ""
        for item in object["data"] as? [String] ?? [] {
            let plain = try Interactsh.decrypt(item, aesKey: aesKey, privateKey: privateKey)
            if let json = (try? JSONSerialization.jsonObject(with: Data(plain))) as? [String: Any],
                let interaction = OASTInteraction(json: json)
            {
                interactions.append(interaction)
            }
        }
        for item in (object["extra"] as? [String] ?? []) + (object["tlddata"] as? [String] ?? []) {
            if let json = (try? JSONSerialization.jsonObject(with: Data(item.utf8))) as? [String: Any],
                let interaction = OASTInteraction(json: json)
            {
                interactions.append(interaction)
            }
        }
        return interactions
    }

    /// End the session on the server.
    public func deregister() async throws {
        guard registered else { return }
        let body = ["correlation-id": correlationID, "secret-key": secretKey]
        _ = try await transport.send(
            method: "POST", url: serverURL + "/deregister",
            body: Array(try JSONSerialization.data(withJSONObject: body)),
            headers: headers)
        registered = false
    }
}
