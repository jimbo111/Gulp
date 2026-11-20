import Foundation
import GulpTestSupport
import Testing

@testable import GulpCore

// Property and round-trip tests for the raw HTTP/1 parser (doc 06 §2, HTTP-001/HTTP-002):
// `parse(bytes).serialize() == bytes` over the fixture corpus and random inputs, structural
// invariants that never depend on the input being well-formed, and "editing a header changes only
// that header's bytes".

/// The fixture corpus in `Fixtures/http/` (exact wire bytes; see `.gitattributes`).
enum HTTPFixtures {
    struct Fixture: CustomTestStringConvertible, Sendable {
        let name: String
        let bytes: Bytes
        var isResponse: Bool { name.hasPrefix("response-") }
        var testDescription: String { name }
    }

    static func load() -> [Fixture] {
        guard let root = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else { return [] }
        let dir = root.appendingPathComponent("http")
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        return names.filter { $0.hasSuffix(".http") }.sorted().compactMap { name in
            let path = dir.appendingPathComponent(name).path
            guard let data = FileManager.default.contents(atPath: path) else { return nil }
            return Fixture(name: name, bytes: Bytes([UInt8](data)))
        }
    }

    static let all = load()
    static let requests = all.filter { !$0.isResponse }
}

/// Invariants every parse must satisfy, whatever the input.
func checkInvariants(_ req: RawRequest) {
    let n = req.bytes.count
    let p = req.parsed
    #expect(p.headerBlockEnd >= 0 && p.headerBlockEnd <= n)
    #expect(p.body == p.headerBlockEnd..<n)
    for r in [p.method, p.target, p.version] {
        #expect(r.lowerBound >= 0 && r.upperBound <= p.headerBlockEnd)
    }
    checkHeaders(p.headers, limit: p.headerBlockEnd)
}

func checkInvariants(_ resp: RawResponse) {
    let n = resp.bytes.count
    let p = resp.parsed
    #expect(p.headerBlockEnd >= 0 && p.headerBlockEnd <= n)
    #expect(p.body == p.headerBlockEnd..<n)
    for r in [p.version, p.reasonPhrase] {
        #expect(r.lowerBound >= 0 && r.upperBound <= p.headerBlockEnd)
    }
    checkHeaders(p.headers, limit: p.headerBlockEnd)
    if p.dechunkedBody != nil {
        #expect(p.bodyFraming == .chunked && !p.incomplete)
    }
    #expect(p.interimResponses.isEmpty)
}

func checkHeaders(_ headers: [HeaderField], limit: Int) {
    var previous = -1
    for h in headers {
        for r in [h.name, h.value, h.line] {
            #expect(r.lowerBound >= 0 && r.upperBound <= limit)
        }
        #expect(h.value.lowerBound >= h.line.lowerBound && h.value.upperBound <= h.line.upperBound)
        #expect(h.line.lowerBound > previous)  // order preserved
        previous = h.line.lowerBound
    }
}

@Suite("GulpCore — parser properties (doc 06 §2)")
struct ParserPropertyTests {
    @Test("the fixture corpus is present")
    func corpusPresent() {
        #expect(HTTPFixtures.all.count >= 17)
        #expect(HTTPFixtures.all.contains { $0.name == "request-nul-bytes.http" })
    }

    @Test("HTTP-001: parse(bytes).serialize() == bytes for every fixture", arguments: HTTPFixtures.all)
    func fixtureRoundTrip(_ fixture: HTTPFixtures.Fixture) {
        if fixture.isResponse {
            let resp = RawResponse(fixture.bytes)
            #expect(resp.serialize().rawBytes == fixture.bytes.rawBytes)
            checkInvariants(resp)
        } else {
            let req = RawRequest(fixture.bytes)
            #expect(req.serialize().rawBytes == fixture.bytes.rawBytes)
            checkInvariants(req)
        }
    }

    @Test("editing a header changes only that header's bytes", arguments: HTTPFixtures.requests)
    func headerEditIsLocal(_ fixture: HTTPFixtures.Fixture) {
        let req = RawRequest(fixture.bytes)
        let newValue = Bytes("EDITED")
        for (i, h) in req.parsed.headers.enumerated() {
            let edited = req.replacing(h.value, with: newValue)
            var expected = Array(req.bytes.rawBytes[..<h.value.lowerBound])
            expected += newValue.rawBytes
            expected += req.bytes.rawBytes[h.value.upperBound...]
            #expect(edited.bytes.rawBytes == expected)
            #expect(edited.parsed.headers.count == req.parsed.headers.count)
            #expect(edited.bytes[edited.parsed.headers[i].value].string() == "EDITED")
            for (j, other) in req.parsed.headers.enumerated() where j != i {
                let after = edited.parsed.headers[j]
                #expect(edited.bytes[after.line].rawBytes == req.bytes[other.line].rawBytes)
            }
        }
    }

    @Test("a 1 MB header and 10k headers parse and round-trip")
    func hugeHeaders() {
        let big = String(repeating: "a", count: 1_048_576)
        let raw = Bytes("GET / HTTP/1.1\r\nHost: h\r\nX-Big: \(big)\r\n\r\n")
        let req = RawRequest(raw)
        #expect(req.serialize().rawBytes == raw.rawBytes)
        #expect(req.parsed.headers.count == 2)
        #expect(req.headerValue("x-big")?.count == 1_048_576)

        var many = "GET / HTTP/1.1\r\n"
        for i in 0..<10_000 { many += "X-\(i): \(i)\r\n" }
        many += "\r\n"
        let manyReq = RawRequest(Bytes(many))
        #expect(manyReq.parsed.headers.count == 10_000)
        checkInvariants(manyReq)
    }

    @Test("an LF-terminated header block is not reported as missing its final CRLF")
    func lfTerminatorIsABlankLine() {
        let lf = RawRequest(Bytes("GET / HTTP/1.1\nHost: a\n\nbody"))
        #expect(!lf.parsed.warnings.contains(.missingFinalCRLF))
        #expect(lf.bytes[lf.parsed.body].string() == "body")
        let none = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: a\r\n"))
        #expect(none.parsed.warnings.contains(.missingFinalCRLF))
        #expect(none.parsed.body.isEmpty)
    }

    @Test("an absurd chunk size is rejected, never wrapped negative")
    func hugeChunkSize() {
        let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        let raw = head + "FFFFFFFFFFFFFFFFFFFF\r\nab\r\n0\r\n\r\n"
        let r = RawResponse(Bytes(raw))
        #expect(r.parsed.dechunkedBody == nil)
        checkInvariants(r)
    }

    @Test("fuzz: random HTTP-shaped inputs never crash and keep every invariant")
    func fuzz() {
        let tokenStrings: [String] = [
            "GET", "POST", "HTTP/1.1", "HTTP/1.0", "200", "204", "304", "100", " ", "  ", "\r\n", "\n",
            "\r", ":", ": ", "Host: a", "Content-Length: ", "content-length: 5", "Transfer-Encoding: ",
            "chunked", "gzip, chunked", "0", "5", "FFFFFFFFFFFFFFFFFF", "-3", ";ext", "\r\n\r\n", "\n\n",
            "\t", "hello", "\u{0}", "/", "?a=1&b=2", "X-Dup: 1", "\r\n 1", "é",
        ]
        let tokens = tokenStrings.map { Array($0.utf8) }
        var rng = SplitMix64(seed: 0x6775_6C70)  // "gulp"
        for _ in 0..<2_000 {
            var bytes: [UInt8] = []
            for _ in 0..<Int.random(in: 0...40, using: &rng) {
                if Int.random(in: 0..<8, using: &rng) == 0 {
                    bytes.append(UInt8.random(in: 0...255, using: &rng))
                } else {
                    bytes += tokens[Int.random(in: 0..<tokens.count, using: &rng)]
                }
            }
            let input = Bytes(bytes)
            let req = RawRequest(input)
            #expect(req.serialize().rawBytes == bytes)
            checkInvariants(req)
            let resp = RawResponse(input)
            #expect(resp.serialize().rawBytes == bytes)
            checkInvariants(resp)
        }
    }
}
