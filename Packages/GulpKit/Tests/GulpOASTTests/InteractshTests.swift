import Crypto
import Foundation
import GulpCore
import NIOConcurrencyHelpers
import Testing
import _CryptoExtras

@testable import GulpOAST

// F10 BCN-001, BCN-002, BCN-005: the interactsh protocol against an in-memory server built from the
// same primitives a real server uses (RSA-OAEP-SHA256 key wrap, AES-256-CTR with a 16-byte IV).

/// A minimal interactsh server as an `OASTTransport`.
final class FakeInteractsh: OASTTransport, Sendable {
    struct Session: Sendable {
        var secret: String
        var key: [UInt8]
        var wrapped: String
        var pending: [String] = []
    }

    let sessions = NIOLockedValueBox<[String: Session]>([:])
    let token: String?

    init(token: String? = nil) { self.token = token }

    /// Record an interaction for whatever unique id `host` carries (what the DNS/HTTP listener does).
    func interact(host: String, proto: String = "http", raw: String = "GET / HTTP/1.1") {
        guard let unique = Interactsh.uniqueID(in: host) else { return }
        let correlation = String(unique.prefix(Interactsh.correlationIDLength))
        let interaction = OASTInteraction(
            proto: proto, uniqueID: unique,
            fullID: host.split(separator: ".").first.map(String.init) ?? unique,
            queryType: proto == "dns" ? "A" : nil, rawRequest: raw, remoteAddress: "10.0.0.7")
        sessions.withLockedValue { sessions in
            guard var session = sessions[correlation],
                let json = try? JSONSerialization.data(withJSONObject: interaction.json),
                let item = try? Interactsh.encrypt(Array(json) + [0x0A], key: SymmetricKey(data: session.key))
            else { return }
            session.pending.append(item)
            sessions[correlation] = session
        }
    }

    func send(method: String, url: String, body: [UInt8]?, headers: [String: String]) async throws -> (
        status: Int, body: [UInt8]
    ) {
        if let token, headers["Authorization"] != token { return (401, []) }
        let path = url.split(separator: "/", maxSplits: 3).dropFirst(2).first.map { "/" + $0 } ?? "/"
        let object =
            body.flatMap { try? JSONSerialization.jsonObject(with: Data($0)) as? [String: String] } ?? [:]
        func json(_ value: Any, _ status: Int = 200) -> (Int, [UInt8]) {
            (status, Array((try? JSONSerialization.data(withJSONObject: value)) ?? Data()))
        }
        if path == "/register" {
            guard let id = object["correlation-id"], id.count == 20, let secret = object["secret-key"],
                let publicKey = try? Interactsh.decodePublicKey(object["public-key"] ?? "")
            else { return json(["error": "bad request"], 400) }
            let key = SymmetricKey(size: .bits256)
            let wrapped = try Interactsh.wrap(key, for: publicKey)
            let bytes = key.withUnsafeBytes { Array($0) }
            sessions.withLockedValue { $0[id] = Session(secret: secret, key: bytes, wrapped: wrapped) }
            return json(["message": "registration successful"])
        }
        if path.hasPrefix("/poll") {
            let query = Dictionary(
                uniqueKeysWithValues: (path.split(separator: "?").last ?? "").split(separator: "&").map {
                    let pair = $0.split(separator: "=")
                    return (String(pair[0]), String(pair.count > 1 ? pair[1] : ""))
                })
            let reply = sessions.withLockedValue { sessions -> (Int, [UInt8])? in
                guard let id = query["id"], var session = sessions[id], session.secret == query["secret"]
                else { return nil }
                let data = session.pending
                session.pending = []
                sessions[id] = session
                return json(["data": data, "extra": [String](), "aes_key": session.wrapped])
            }
            return reply ?? json(["error": "could not get interactions"], 400)
        }
        if path == "/deregister" {
            sessions.withLockedValue { $0[object["correlation-id"] ?? ""] = nil }
            return json(["message": "deregistration successful"])
        }
        return (404, [])
    }
}

@Suite("OAST client (BCN-001, BCN-002, BCN-005)")
struct InteractshTests {
    @Test("Register, mint unique payloads, see an interaction, poll and decrypt it, deregister")
    func test_BCN005_loop() async throws {
        let server = FakeInteractsh()
        let client = try InteractshClient(serverURL: "https://oast.example/", transport: server)
        try await client.register()
        let a = await client.newPayload()
        let b = await client.newPayload()
        // BCN-001: <20-char correlation id><13-char nonce>.<domain>, unique per payload.
        #expect(a.id != b.id && Interactsh.isUniqueID(a.id) && a.host == a.id + ".oast.example")
        #expect(a.id.hasPrefix(await client.correlationID))
        #expect(a.httpURL == "http://\(a.host)/" && a.email == "gulp@\(a.host)")
        #expect(try await client.poll().isEmpty)
        server.interact(host: "x." + b.host.uppercased(), proto: "dns")  // a resolver may change case
        server.interact(host: a.host, raw: "GET /fetched HTTP/1.1\r\nHost: \(a.host)")
        let seen = try await client.poll()
        #expect(seen.map(\.uniqueID) == [b.id, a.id])
        #expect(seen[0].proto == "dns" && seen[0].queryType == "A" && seen[0].remoteAddress == "10.0.0.7")
        #expect(seen[1].rawRequest.hasPrefix("GET /fetched"))
        #expect(try await client.poll().isEmpty)  // delivered once
        try await client.deregister()
        #expect(server.sessions.withLockedValue { $0.isEmpty })
        await #expect(throws: OASTError.self) { try await client.poll() }
    }

    @Test("A server token goes in Authorization; without it registration fails clearly")
    func test_BCN004_token() async throws {
        let server = FakeInteractsh(token: "s3cret")
        let anonymous = try InteractshClient(
            serverURL: "http://127.0.0.1:8090", domain: "oast.test", transport: server)
        await #expect(throws: OASTError.self) { try await anonymous.register() }
        let client = try InteractshClient(
            serverURL: "http://127.0.0.1:8090", domain: "OAST.test", token: "s3cret", transport: server)
        try await client.register()
        #expect(await client.newPayload().host.hasSuffix(".oast.test"))
    }

    @Test("Wire details: key format round trip, AES-CTR round trip, unique ids in text, Go timestamps")
    func test_BCN005_wire() throws {
        let key = try _RSA.Encryption.PrivateKey(keySize: .bits2048)
        let encoded = Interactsh.encodePublicKey(key.publicKey)
        let pem = String(decoding: Data(base64Encoded: encoded)!, as: UTF8.self)
        #expect(
            pem.hasPrefix("-----BEGIN RSA PUBLIC KEY-----\n")
                && pem.hasSuffix("-----END RSA PUBLIC KEY-----\n"))
        #expect(try Interactsh.decodePublicKey(encoded).derRepresentation == key.publicKey.derRepresentation)
        let aes = SymmetricKey(size: .bits256)
        let wrapped = try Interactsh.wrap(aes, for: key.publicKey)
        let message = Array("{\"protocol\":\"http\"}".utf8)
        #expect(
            try Interactsh.decrypt(Interactsh.encrypt(message, key: aes), aesKey: wrapped, privateKey: key)
                == message)
        let id = "c58bduhe008dovpvhvugbfgyhuhk3mtty"
        #expect(Interactsh.isUniqueID(id))
        #expect(Interactsh.uniqueID(in: "GET http://abc.\(id.uppercased()).oast.fun/ HTTP/1.1") == id)
        #expect(Interactsh.uniqueID(in: "nothing here") == nil)
        let date = Interactsh.parseDate("2026-11-11T21:13:05.123456789Z")
        #expect(date.map { abs($0.timeIntervalSince1970 - 1_794_431_585.123) < 0.01 } == true)
    }
}
