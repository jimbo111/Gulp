import Testing

@testable import GulpCore

// M1 GulpCore: the raw-bytes-are-truth guarantee (CLAUDE.md §4) and HTTP/1 framing (F03 HTTP-001/002).
// Tests name the requirement ID they cover, per CLAUDE.md §2.

@Suite("GulpCore — Bytes")
struct BytesTests {
    @Test("value semantics and slicing")
    func slicing() {
        let b = Bytes("hello world")
        #expect(b.count == 11)
        #expect(b[0..<5].string() == "hello")
        #expect(b[6..<11].string() == "world")
        var c = b
        c.replaceSubrange(0..<5, with: Bytes("HELLO"))
        #expect(c.string() == "HELLO world")
        #expect(b.string() == "hello world")  // original unchanged (value semantics)
    }

    @Test("strict vs lossy UTF-8")
    func utf8() {
        #expect(Bytes("café").validUTF8() == "café")
        let invalid = Bytes([0x66, 0x6F, 0x6F, 0xFF])  // "foo" + a lone 0xFF
        #expect(invalid.validUTF8() == nil)
        #expect(invalid.string().hasPrefix("foo"))  // lossy: substitutes U+FFFD, never nil
    }
}

@Suite("GulpCore — HTTP/1 round-trip (HTTP-001)")
struct RoundTripTests {
    @Test("serialize() is the identity over the input bytes")
    func identity() {
        let raw = "GET /a?x=1 HTTP/1.1\r\nHost: example.com\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\nbody"
        let req = RawRequest(Bytes(raw))
        #expect(req.serialize().rawBytes == Bytes(raw).rawBytes)
    }

    @Test("request start-line and headers frame as byte ranges, order and duplicates preserved")
    func requestFraming() {
        let raw = "POST /login HTTP/1.1\r\nHost: h\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\nq=1"
        let req = RawRequest(Bytes(raw))
        #expect(req.bytes[req.parsed.method].string() == "POST")
        #expect(req.bytes[req.parsed.target].string() == "/login")
        #expect(req.bytes[req.parsed.version].string() == "HTTP/1.1")
        #expect(req.parsed.headers.count == 3)
        #expect(req.bytes[req.parsed.body].string() == "q=1")
        #expect(req.headerValue("host")?.string() == "h")  // case-insensitive lookup
        #expect(req.headerValue("x-dup")?.string() == "2")  // last duplicate wins for lookup
    }

    @Test("editing splices bytes and re-parses without touching the rest")
    func editSplice() {
        let raw = "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"
        let req = RawRequest(Bytes(raw))
        let edited = req.replacing(req.parsed.target, with: Bytes("/bb"))
        #expect(edited.bytes[edited.parsed.target].string() == "/bb")
        #expect(edited.headerValue("host")?.string() == "example.com")  // untouched
        #expect(edited.serialize().string() == "GET /bb HTTP/1.1\r\nHost: example.com\r\n\r\n")
    }
}

@Suite("GulpCore — HTTP/1 response framing (HTTP-002)")
struct FramingTests {
    private func resp(_ s: String) -> ParsedResponse { RawResponse(Bytes(s)).parsed }

    @Test("Content-Length framing")
    func contentLength() {
        let r = resp("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        #expect(r.statusCode == 200)
        #expect(r.bodyFraming == .contentLength)
        #expect(r.contentLength == 5)
        #expect(r.incomplete == false)
        #expect(r.dechunkedBody == nil)
    }

    @Test("Content-Length shorter than the arrived body marks it incomplete")
    func contentLengthIncomplete() {
        let r = resp("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nhello")
        #expect(r.incomplete == true)
    }

    @Test("chunked framing decodes dechunkedBody")
    func chunked() {
        let r = resp(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        #expect(r.bodyFraming == .chunked)
        #expect(r.transferEncodingChunked == true)
        #expect(r.incomplete == false)
        #expect(r.dechunkedBody?.string() == "hello world")
    }

    @Test("a truncated chunked body is incomplete and not decoded")
    func chunkedTruncated() {
        let r = resp("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel")
        #expect(r.bodyFraming == .chunked)
        #expect(r.incomplete == true)
        #expect(r.dechunkedBody == nil)
    }

    @Test("HTTP-002: a header-block scan resumed from the last read finds the same end at any split")
    func test_HTTP002_resumableHeaderBlockEnd() {
        for text in ["HTTP/1.1 200 OK\r\nA: b\r\n\r\nbody", "HTTP/1.1 200 OK\nA: b\n\nbody", "X\r\n\nrest"] {
            let all = Array(text.utf8)
            let whole = HTTP1.headerBlockEnd(all)
            var buffer: [UInt8] = []
            var resume = 0
            var found: (end: Int, terminator: Int)?
            for byte in all where found == nil {
                buffer.append(byte)
                let scan = HTTP1.headerBlockEnd(buffer, from: resume)
                if scan.terminator != 0 {
                    found = scan
                } else {
                    resume = HTTP1.headerScanResume(buffer.count)
                }
            }
            #expect(found?.end == whole.end && found?.terminator == whole.terminator)
        }
    }

    @Test("HTTP-002: every chunked view reads a chunk-size line the same way (BWS before ';' is allowed)")
    func test_HTTP002_oneChunkSizeGrammar() {
        // RFC 9112 §7.1.1: whitespace may precede a chunk extension.
        let body = "5 ;a=1\r\nhello\r\n6\t; b\r\n world\r\n0 \r\ngrpc-status: 0\r\n\r\n"
        let r = resp("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body)
        #expect(!r.incomplete && r.dechunkedBody?.string() == "hello world")
        let parts = HTTP2Text.responseParts(
            RawResponse(Bytes("HTTP/2 200\r\ntransfer-encoding: chunked\r\n\r\n" + body)))
        #expect(parts.body == Array("hello world".utf8) && parts.trailers == [H2Header("grpc-status", "0")])
        // A signed or prefixed size is not a chunk size anywhere.
        for size in ["-5", "+5", "0x5", " 5", ""] {
            let bad = Array((size + "\r\nhello\r\n0\r\n\r\n").utf8)
            #expect(HTTP1.scanChunked(bad, from: 0) == .malformed)
            let response = resp(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + String(decoding: bad, as: UTF8.self)
            )
            #expect(response.incomplete && response.dechunkedBody == nil)
        }
    }

    @Test("chunked wins over Content-Length and flags the conflict")
    func conflictingFraming() {
        let r = resp("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n")
        #expect(r.bodyFraming == .chunked)
        #expect(r.warnings.contains(.conflictingFraming))
    }

    @Test("duplicate Content-Length is flagged")
    func duplicateContentLength() {
        let r = resp("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello")
        #expect(r.warnings.contains(.duplicateContentLength))
    }

    @Test("204 is bodyless regardless of a trailing newline")
    func bodyless204() {
        let r = resp("HTTP/1.1 204 No Content\r\n\r\n")
        #expect(r.statusCode == 204)
        #expect(r.bodyFraming == .none)
    }

    @Test("304 is bodyless even with a Content-Length present")
    func bodyless304() {
        // 304 carries header metadata (incl. a Content-Length echoing the cached body) but no body.
        let r = resp("HTTP/1.1 304 Not Modified\r\nContent-Length: 42\r\n\r\n")
        #expect(r.statusCode == 304)
        #expect(r.bodyFraming == .none)
        #expect(r.incomplete == false)
    }

    @Test("no framing headers on a 200 means close-delimited")
    func closeDelimited() {
        let r = resp("HTTP/1.1 200 OK\r\nServer: x\r\n\r\nraw bytes, length unknown")
        #expect(r.bodyFraming == .closeDelimited)
    }

    @Test("bare-LF line endings are tolerated with a warning")
    func bareLF() {
        let r = resp("HTTP/1.1 200 OK\nContent-Length: 2\n\nhi")
        #expect(r.lineEnding == .lf)
        #expect(r.warnings.contains(.bareLF))
        #expect(r.statusCode == 200)
        #expect(r.contentLength == 2)
    }

    @Test("obsolete line folding is preserved and warned")
    func obsFold() {
        let r = resp("HTTP/1.1 200 OK\r\nX-Long: a\r\n b\r\nContent-Length: 0\r\n\r\n")
        #expect(r.warnings.contains(.obsoleteLineFolding))
    }
}

@Suite("GulpCore — module marker")
struct ModuleMarkerTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpCore.moduleName == "GulpCore")
    }
}
