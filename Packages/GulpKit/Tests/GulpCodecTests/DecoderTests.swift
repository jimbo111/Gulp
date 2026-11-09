import Foundation
import Testing

@testable import GulpCodec

// F12 DEC-001…DEC-005: the transform registry, chains and Smart Decode.

@Suite("GulpCodec — Decoder transforms (DEC-001…DEC-005)")
struct DecoderTests {
    /// Every operation whose inverse restores arbitrary bytes.
    static let byteExact = [
        "url-encode", "url-encode-all", "base64", "base64url", "base32", "base58", "hex", "decimal", "octal",
        "binary", "gzip", "zlib", "deflate", "reverse", "rot13",
    ]
    /// Text escapes: their inverse restores any valid UTF-8 string.
    static let textExact = ["html-encode", "unicode-escape", "js-escape", "css-escape", "json-escape"]

    @Test("F12 acceptance 4: every reversible operation round-trips over random bytes and text")
    func test_DEC005_roundTrips() throws {
        var generator = SystemRandomNumberGenerator()
        for name in Self.byteExact {
            let transform = try #require(Transforms.named(name))
            let inverse = try #require(transform.inverse.flatMap(Transforms.named))
            for length in [0, 1, 2, 3, 7, 64, 1_000] {
                let input = (0..<length).map { _ in UInt8.random(in: 0...255, using: &generator) }
                let back = try inverse.apply(try transform.apply(input))
                #expect(back == input, "\(name) length \(length)")
            }
        }
        let xorKey = ["key": "k3y"]
        let random = (0..<100).map { _ in UInt8.random(in: 0...255) }
        #expect(
            try Transforms.named("xor")!.apply(Transforms.named("xor")!.apply(random, xorKey), xorKey)
                == random)
        let samples = [
            "", "plain", "<a href=\"x\">'&'</a>", "é ü 漢字 🎉 \u{0}\u{1F}\n\t\\\"",
            String(repeating: "x/\\y", count: 50),
        ]
        for name in Self.textExact {
            let transform = try #require(Transforms.named(name))
            let inverse = try #require(transform.inverse.flatMap(Transforms.named))
            for sample in samples {
                let back = try inverse.apply(try transform.apply(Array(sample.utf8)))
                #expect(
                    String(decoding: back, as: UTF8.self) == sample, "\(name) on \(sample.debugDescription)")
            }
        }
    }

    @Test("Known vectors: hashes, HMAC, SHA-3, CRC-32, Base32/58")
    func test_DEC002_vectors() throws {
        func run(_ name: String, _ input: String, _ arguments: [String: String] = [:]) throws -> String {
            String(decoding: try Transforms.named(name)!.apply(Array(input.utf8), arguments), as: UTF8.self)
        }
        #expect(try run("md5", "abc") == "900150983cd24fb0d6963f7d28e17f72")
        #expect(try run("sha1", "abc") == "a9993e364706816aba3e25717850c26c9cd0d89d")
        #expect(
            try run("sha256", "abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(try run("sha3-256", "") == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        #expect(
            try run("sha3-256", "abc") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        #expect(
            try run("sha3-512", "abc")
                == "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        )
        #expect(try run("crc32", "123456789") == "cbf43926")
        #expect(
            try run("hmac-sha256", "The quick brown fox jumps over the lazy dog", ["key": "key"])
                == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
        #expect(try Transforms.named("sha256")!.apply([], ["raw": "true"]).count == 32)
        #expect(try run("base32", "foobar") == "MZXW6YTBOI======")
        #expect(try run("base58", "hello world") == "StV1DL6CwTryKyV")
        #expect(try run("base58", "\u{0}\u{0}a") == "112g")
        #expect(try run("url-decode", "a+b%20c", ["plus": "true"]) == "a b c")
        #expect(try run("html-decode", "&lt;&#x41;&#66;&amp;&bogus;") == "<AB&&bogus;")
        #expect(try run("unicode-unescape", "\\ud83c\\udf89\\u{1F600}\\x41") == "🎉😀A")
        #expect(try run("hex-decode", "0x48 65:6c-6c 6f") == "Hello")
        #expect(throws: CodecError.self) { try run("hex-decode", "abc") }
        #expect(throws: CodecError.self) { try run("base64-decode", "!!!") }
        #expect(try run("base64-decode", "aGk") == "hi")  // padding optional
        #expect(try run("upper", "aé") == "Aé")  // bytes, not code points
        #expect(try run("shell-escape", "it's") == "'it'\\''s'")
    }

    @Test("Decompression is capped (compression bombs fail instead of filling memory)")
    func test_DEC005_bomb() throws {
        let bomb = try Compression.compress([UInt8](repeating: 0, count: 2_000_000), .gzip)
        #expect(throws: CodecError.self) { try Compression.decompress(bomb, .gzip, limit: 1_000_000) }
        #expect(try Compression.decompress(bomb, .gzip).count == 2_000_000)
    }

    @Test("F12 acceptance 1: URL → Base64 → gunzip → pretty JSON, edited and reversed")
    func test_DEC001_chain() throws {
        let original = Array(#"{"user":"alice","admin":false}"#.utf8)
        let encoded = try Transforms.run(
            original, [TransformStep("gzip"), TransformStep("base64"), TransformStep("url-encode")]
        ).last!
        let steps = [
            TransformStep("url-decode"), TransformStep("base64-decode"), TransformStep("gunzip"),
            TransformStep("json-pretty"),
        ]
        let levels = try Transforms.run(encoded, steps)
        #expect(levels.count == 5)
        let pretty = String(decoding: levels.last!, as: UTF8.self)
        #expect(pretty.contains("\"admin\" : false") || pretty.contains("\"admin\": false"))
        // Edit the decoded JSON and run the chain backwards (json-pretty has no inverse; drop it).
        let edited = Array(pretty.replacingOccurrences(of: "false", with: "true").utf8)
        let reverse = try #require(Transforms.reversed(Array(steps.dropLast())))
        #expect(reverse.map(\.name) == ["gzip", "base64", "url-encode"])
        let reencoded = try Transforms.run(edited, reverse).last!
        let roundTrip = try Transforms.run(reencoded, Array(steps.dropLast())).last!
        #expect(String(decoding: roundTrip, as: UTF8.self).contains("true"))
        #expect(Transforms.reversed([TransformStep("sha256")]) == nil)
        #expect(throws: CodecError.self) { try Transforms.run(encoded, [TransformStep("nope")]) }
    }

    @Test("F12 acceptance 2: Smart Decode solves the fixture set and reports the chain")
    func test_DEC003_smartDecode() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/decoder/smart-decode.json")
        let cases = try #require(
            try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [[String: Any]])
        #expect(cases.count >= 8)
        for item in cases {
            let name = item["name"] as? String ?? "?"
            let result = SmartDecode.run(Array((item["input"] as? String ?? "").utf8))
            #expect(result.chain == item["chain"] as? [String], "\(name)")
            #expect(String(decoding: result.output, as: UTF8.self) == item["output"] as? String, "\(name)")
        }
        let jwt = SmartDecode.run(Array("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln".utf8))
        #expect(jwt.chain == ["jwt-decode"] && String(decoding: jwt.output, as: UTF8.self).contains("alice"))
    }
}
