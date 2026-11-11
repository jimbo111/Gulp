// BeaconKit — the dev Beacon's in-memory store and the interactsh server protocol (F10 BCN-021 in
// dev mode, BCN-024). Clients register an RSA public key under a 20-character correlation id; every
// DNS/HTTP interaction whose name carries `<correlation id><13-char nonce>` is encrypted for that
// client (AES-256-CTR, the session key RSA-OAEP-SHA256-wrapped) and handed out once by `poll`.
// This mirrors the interactsh server, so Gulp's one client works with both.

import Crypto
import Foundation
import _CryptoExtras

/// One recorded interaction.
public struct BeaconInteraction: Sendable, Hashable {
    /// `dns`, `http` or `https`.
    public var proto: String
    /// The 33-character unique id (lowercased).
    public var uniqueID: String
    /// The name up to and including the label that carried the id.
    public var fullID: String
    /// DNS query type.
    public var queryType: String?
    /// The raw request or query text.
    public var rawRequest: String
    /// The source address.
    public var remoteAddress: String
    /// When.
    public var timestamp: Date

    /// An interaction.
    public init(
        proto: String, uniqueID: String, fullID: String, queryType: String? = nil, rawRequest: String,
        remoteAddress: String, timestamp: Date = Date()
    ) {
        self.proto = proto
        self.uniqueID = uniqueID.lowercased()
        self.fullID = fullID
        self.queryType = queryType
        self.rawRequest = rawRequest
        self.remoteAddress = remoteAddress
        self.timestamp = timestamp
    }

    /// interactsh's JSON form.
    public var json: [String: Any] {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var object: [String: Any] = [
            "protocol": proto, "unique-id": uniqueID, "full-id": fullID, "raw-request": rawRequest,
            "raw-response": "", "remote-address": remoteAddress,
            "timestamp": formatter.string(from: timestamp),
        ]
        if let queryType { object["q-type"] = queryType }
        return object
    }
}

/// A protocol reply: HTTP status and a JSON body.
public struct BeaconReply: Sendable {
    /// HTTP status.
    public var status: Int
    /// JSON body.
    public var body: [UInt8]

    static func json(_ object: Any, _ status: Int = 200) -> BeaconReply {
        BeaconReply(
            status: status, body: Array((try? JSONSerialization.data(withJSONObject: object)) ?? Data()))
    }

    static func error(_ message: String, _ status: Int = 400) -> BeaconReply {
        json(["error": message], status)
    }
}

/// Correlation-id helpers (the interactsh alphabets).
public enum BeaconIDs {
    /// Correlation id length.
    public static let correlationLength = 20
    /// Nonce length.
    public static let nonceLength = 13
    static let xid = Set("0123456789abcdefghijklmnopqrstuv")
    static let zbase32 = Set("ybndrfg8ejkmcpqxot1uwisza345h769")

    /// Whether `text` is a valid correlation id.
    public static func isCorrelationID(_ text: String) -> Bool {
        text.count == correlationLength && text.allSatisfy(xid.contains)
    }

    /// The first unique id in a name's labels (33-character window; case-insensitive), with the full
    /// id (the name up to and including that label). Nil if none.
    public static func find(in name: String) -> (unique: String, full: String)? {
        let labels = name.lowercased().split(separator: ".", omittingEmptySubsequences: false).map(
            String.init)
        let width = correlationLength + nonceLength
        for (index, label) in labels.enumerated() {
            let chars = Array(label)
            guard chars.count >= width else { continue }
            for start in 0...(chars.count - width) {
                let window = chars[start..<start + width]
                if window.prefix(correlationLength).allSatisfy(xid.contains),
                    window.suffix(nonceLength).allSatisfy(zbase32.contains)
                {
                    return (String(window), labels[...index].joined(separator: "."))
                }
            }
        }
        return nil
    }
}

/// The dev Beacon's state.
public actor BeaconStore {
    struct Session {
        var secret: String
        var key: [UInt8]
        var wrappedKey: String
        var pending: [String] = []
    }

    private var sessions: [String: Session] = [:]
    /// The shared token clients must send in `Authorization` (nil: none required).
    public let token: String?
    /// Interactions recorded (for the log and tests).
    public private(set) var recorded = 0

    /// A store; with `token`, every API call needs it.
    public init(token: String? = nil) {
        self.token = token
    }

    /// Whether `authorization` satisfies the token.
    public func authorized(_ authorization: String?) -> Bool {
        guard let token, !token.isEmpty else { return true }
        return authorization == token
    }

    /// `POST /register`.
    public func register(_ body: [UInt8]) -> BeaconReply {
        guard let object = (try? JSONSerialization.jsonObject(with: Data(body))) as? [String: Any] else {
            return .error("could not decode json body")
        }
        guard let id = object["correlation-id"] as? String, BeaconIDs.isCorrelationID(id) else {
            return .error("invalid correlation-id")
        }
        guard let secret = object["secret-key"] as? String, !secret.isEmpty else {
            return .error("no secret specified for register")
        }
        guard sessions[id] == nil else { return .error("correlation-id provided already exists") }
        do {
            let publicKey = try BeaconCrypto.decodePublicKey(object["public-key"] as? String ?? "")
            let key = SymmetricKey(size: .bits256)
            let wrapped = try BeaconCrypto.wrap(key, for: publicKey)
            sessions[id] = Session(
                secret: secret, key: key.withUnsafeBytes { Array($0) }, wrappedKey: wrapped)
            return .json(["message": "registration successful"])
        } catch {
            return .error("could not set id and public key: \(error)")
        }
    }

    /// `POST /deregister`.
    public func deregister(_ body: [UInt8]) -> BeaconReply {
        guard let object = (try? JSONSerialization.jsonObject(with: Data(body))) as? [String: Any],
            let id = object["correlation-id"] as? String, let secret = object["secret-key"] as? String
        else { return .error("could not decode json body") }
        guard sessions[id]?.secret == secret else { return .error("could not remove id") }
        sessions[id] = nil
        return .json(["message": "deregistration successful"])
    }

    /// `GET /poll?id=…&secret=…`.
    public func poll(id: String?, secret: String?) -> BeaconReply {
        guard let id, !id.isEmpty else { return .error("no id specified for poll") }
        guard let secret, !secret.isEmpty else { return .error("no secret specified for poll") }
        guard var session = sessions[id], session.secret == secret else {
            return .error("could not get interactions: could not get correlation-id from cache")
        }
        let data = session.pending
        session.pending = []
        sessions[id] = session
        return .json(["data": data, "extra": [String](), "aes_key": session.wrappedKey])
    }

    /// Record an interaction for its registered session (dropped when nobody registered it).
    /// Returns whether a session took it.
    @discardableResult
    public func record(_ interaction: BeaconInteraction) -> Bool {
        let id = String(interaction.uniqueID.prefix(BeaconIDs.correlationLength))
        guard var session = sessions[id],
            let json = try? JSONSerialization.data(withJSONObject: interaction.json),
            let item = try? BeaconCrypto.encrypt(Array(json), key: SymmetricKey(data: session.key))
        else { return false }
        session.pending.append(item)
        sessions[id] = session
        recorded += 1
        return true
    }
}

/// The server side of interactsh's crypto.
public enum BeaconCrypto {
    /// The client's key from base64(PEM "RSA PUBLIC KEY" with PKIX DER).
    public static func decodePublicKey(_ text: String) throws -> _RSA.Encryption.PublicKey {
        guard let pemData = Data(base64Encoded: text) else { throw BeaconError("public key isn't base64") }
        let body = String(decoding: pemData, as: UTF8.self).split(separator: "\n").filter {
            !$0.hasPrefix("-----")
        }
        .joined()
        guard let der = Data(base64Encoded: body) else { throw BeaconError("public key PEM is malformed") }
        return try _RSA.Encryption.PublicKey(derRepresentation: der)
    }

    /// RSA-OAEP(SHA-256) of the session key, base64.
    public static func wrap(_ key: SymmetricKey, for publicKey: _RSA.Encryption.PublicKey) throws -> String {
        try publicKey.encrypt(key.withUnsafeBytes { Data($0) }, padding: .PKCS1_OAEP_SHA256)
            .base64EncodedString()
    }

    /// base64(IV ‖ AES-256-CTR(message)).
    public static func encrypt(_ message: [UInt8], key: SymmetricKey) throws -> String {
        var generator = SystemRandomNumberGenerator()
        let iv = (0..<16).map { _ in UInt8.random(in: 0...255, using: &generator) }
        let ciphertext = try AES._CTR.encrypt(message, using: key, nonce: AES._CTR.Nonce(nonceBytes: iv))
        return (Data(iv) + ciphertext).base64EncodedString()
    }
}

/// A Beacon error.
public struct BeaconError: Error, Sendable, CustomStringConvertible {
    /// The message.
    public var description: String

    init(_ description: String) { self.description = description }
}
