import BeaconKit
import Crypto
import Foundation
import Testing
import _CryptoExtras

// F10 BCN-021 (dev mode) / BCN-024: the interactsh server protocol and the DNS responder.

@Suite("Dev Beacon (BCN-024)")
struct BeaconTests {
    /// What a client sends to register: base64(PEM "RSA PUBLIC KEY" with the PKIX DER).
    static func registration(_ key: _RSA.Encryption.PrivateKey, id: String, secret: String) -> [UInt8] {
        let pem =
            "-----BEGIN RSA PUBLIC KEY-----\n"
            + key.publicKey.derRepresentation.base64EncodedString(options: [
                .lineLength64Characters, .endLineWithLineFeed,
            ])
            + "\n-----END RSA PUBLIC KEY-----\n"
        let body = [
            "public-key": Data(pem.utf8).base64EncodedString(), "secret-key": secret, "correlation-id": id,
        ]
        return Array(try! JSONSerialization.data(withJSONObject: body))
    }

    static func json(_ reply: BeaconReply) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(reply.body))) as? [String: Any] ?? [:]
    }

    @Test("Register, record, poll: interactions come back once, encrypted for the client only")
    func test_BCN024_protocol() async throws {
        let store = BeaconStore()
        let key = try _RSA.Encryption.PrivateKey(keySize: .bits2048)
        let id = "c58bduhe008dovpvhvug"
        #expect(await store.register(Self.registration(key, id: id, secret: "s")).status == 200)
        #expect(await store.register(Self.registration(key, id: id, secret: "s")).status == 400)  // taken
        #expect(await store.register(Self.registration(key, id: "UPPER", secret: "s")).status == 400)
        let unique = id + "bfgyhuhk3mtty"
        #expect(BeaconIDs.find(in: "x.\(unique.uppercased()).oast.test")?.unique == unique)
        #expect(BeaconIDs.find(in: "x.\(unique).oast.test")?.full == "x.\(unique)")
        #expect(
            await store.record(
                BeaconInteraction(
                    proto: "dns", uniqueID: unique, fullID: unique, queryType: "A", rawRequest: "q",
                    remoteAddress: "1.2.3.4")))
        #expect(
            !(await store.record(
                BeaconInteraction(
                    proto: "dns", uniqueID: "zzzzzzzzzzzzzzzzzzzz" + "bfgyhuhk3mtty", fullID: "",
                    rawRequest: "", remoteAddress: ""))))
        #expect(await store.poll(id: id, secret: "wrong").status == 400)
        let reply = Self.json(await store.poll(id: id, secret: "s"))
        let data = try #require(reply["data"] as? [String])
        #expect(data.count == 1)
        // Decrypt like a client: unwrap the AES key, AES-256-CTR with the IV prefix.
        let wrapped = try #require(Data(base64Encoded: reply["aes_key"] as? String ?? ""))
        let aes = SymmetricKey(data: try key.decrypt(wrapped, padding: .PKCS1_OAEP_SHA256))
        let item = try #require(Data(base64Encoded: data[0]))
        let plain = try AES._CTR.decrypt(
            item.dropFirst(16), using: aes, nonce: AES._CTR.Nonce(nonceBytes: item.prefix(16)))
        let interaction = try #require(try JSONSerialization.jsonObject(with: plain) as? [String: Any])
        #expect(interaction["protocol"] as? String == "dns" && interaction["unique-id"] as? String == unique)
        #expect(
            interaction["q-type"] as? String == "A" && interaction["remote-address"] as? String == "1.2.3.4")
        #expect((Self.json(await store.poll(id: id, secret: "s"))["data"] as? [String])?.isEmpty == true)
        let deregister = Array(
            try JSONSerialization.data(withJSONObject: ["correlation-id": id, "secret-key": "s"]))
        #expect(await store.deregister(deregister).status == 200)
        #expect(await store.poll(id: id, secret: "s").status == 400)
    }

    @Test("A token, when set, is required")
    func test_BCN024_token() async {
        let store = BeaconStore(token: "t")
        let ok = await store.authorized("t")
        let anonymous = await store.authorized(nil)
        #expect(ok && !anonymous)
        #expect(await BeaconStore().authorized(nil))
    }

    @Test("DNS: parse a query; answer A with the address and TXT, keeping the id and question")
    func test_BCN024_dns() throws {
        let query = DNSCodec.query("abc.oast.test", type: 1, id: 0xBEEF)
        let question = try #require(DNSCodec.question(query))
        #expect(question.name == "abc.oast.test" && question.typeName == "A" && question.id == 0xBEEF)
        let answer = DNSCodec.answer(query, question: question, address: [127, 0, 0, 1])
        #expect(Array(answer.prefix(2)) == [0xBE, 0xEF] && answer[2] & 0x80 != 0 && answer[7] == 1)
        #expect(Array(answer.suffix(4)) == [127, 0, 0, 1])
        let txt = DNSCodec.query("abc.oast.test", type: 16)
        let txtAnswer = DNSCodec.answer(
            txt, question: try #require(DNSCodec.question(txt)), address: [127, 0, 0, 1])
        #expect(String(decoding: txtAnswer.suffix(11), as: UTF8.self) == "gulp-beacon")
        #expect(DNSCodec.question([1, 2, 3]) == nil)
    }
}
