// GulpCore — raw-preserving HTTP/1 messages: parser + response framer (doc 04 §2, F03 HTTP-001/002).
//
// The parser frames a message (finds the header block, the status/request line, headers as byte
// ranges, and the body) WITHOUT ever rejecting or normalizing it — malformed input yields warnings,
// not errors (parser tolerance rules, doc 04 §2). `serialize()` is the identity over the input bytes.

// MARK: - Supporting enums

/// URL scheme of a message's target.
public enum Scheme: String, Sendable, Codable, Hashable { case http, https }

/// HTTP protocol version, carrying its exact wire token as the raw value.
public enum HTTPVersion: String, Sendable, Codable, Hashable {
    case http1_0 = "HTTP/1.0", http1_1 = "HTTP/1.1", http2 = "HTTP/2"
}

/// The line-ending style observed in a message's header block (preserved, never normalized).
public enum LineEnding: Sendable, Hashable { case crlf, lf, mixed, none }

/// How a message body is delimited on the wire.
public enum BodyFraming: Sendable, Hashable { case contentLength, chunked, closeDelimited, none }

/// A non-fatal tolerance note raised while parsing. The parser never rejects input; it records these.
public enum ParseWarning: Sendable, Equatable, Hashable {
    case bareLF, obsoleteLineFolding, missingFinalCRLF, invalidCharInName
    case duplicateContentLength, conflictingFraming, malformedStartLine
    // `oversizedHeaders` is emitted by the engine's header-size guard, not the pure parser.
    case oversizedHeaders
    case nonUTF8Header
}

// MARK: - Header field

/// One header line, as byte ranges into the owning message's bytes (order and duplicates preserved).
public struct HeaderField: Sendable, Hashable {
    /// The field name range (bytes before the colon).
    public var name: Range<Int>
    /// The field value range: trimmed of surrounding OWS, but pointing at the real bytes.
    public var value: Range<Int>
    /// The whole field line (terminator excluded).
    public var line: Range<Int>
    /// Create a header field from its three byte ranges.
    public init(name: Range<Int>, value: Range<Int>, line: Range<Int>) {
        self.name = name
        self.value = value
        self.line = line
    }
}

// MARK: - Parsed views

/// A framed view of a request's start line, headers, and body as byte ranges into its bytes.
public struct ParsedRequest: Sendable, Hashable {
    /// The request method range (e.g. `GET`).
    public var method: Range<Int>
    /// The request-target range (origin/absolute/authority/asterisk form).
    public var target: Range<Int>
    /// The HTTP-version range (e.g. `HTTP/1.1`).
    public var version: Range<Int>
    /// Header fields, in order, duplicates allowed.
    public var headers: [HeaderField]
    /// Index just past the end of the header block (after CRLFCRLF, or LFLF when tolerated).
    public var headerBlockEnd: Int
    /// The body range `[headerBlockEnd, end)`.
    public var body: Range<Int>
    /// The line-ending style of the header block.
    public var lineEnding: LineEnding
    /// Tolerance notes raised while parsing.
    public var warnings: [ParseWarning]
}

/// A framed view of a response's status line, headers, and body as byte ranges into its bytes.
public struct ParsedResponse: Sendable, Hashable {
    /// The HTTP-version range (e.g. `HTTP/1.1`).
    public var version: Range<Int>
    /// The parsed status code (e.g. 200); 0 if the status line was malformed.
    public var statusCode: Int
    /// The reason-phrase range.
    public var reasonPhrase: Range<Int>
    /// Header fields, in order, duplicates allowed.
    public var headers: [HeaderField]
    /// Index just past the end of the header block.
    public var headerBlockEnd: Int
    /// The body as framed (raw; chunked stays chunked).
    public var body: Range<Int>
    /// Decoded payload when `bodyFraming == .chunked` and `!incomplete`; nil otherwise. Chunk
    /// extensions and trailers are dropped from this view (the raw bytes still hold them in `body`).
    public var dechunkedBody: Bytes?
    /// True when a `Transfer-Encoding: chunked` token was present.
    public var transferEncodingChunked: Bool
    /// The parsed `Content-Length`, if present and well-formed.
    public var contentLength: Int?
    /// How the body is delimited.
    public var bodyFraming: BodyFraming
    /// Recorded 1xx responses that preceded this final one (HTTP-002). The single-message parser
    /// never populates this — it is accumulated by the HTTP engine across an exchange — so it is
    /// always `[]` here, kept for shape-parity with the engine's view (doc 04 §2).
    public var interimResponses: [ParsedResponse]
    /// The line-ending style of the header block.
    public var lineEnding: LineEnding
    /// Tolerance notes raised while parsing.
    public var warnings: [ParseWarning]
    /// Declared body not fully present (short Content-Length body, or no terminal chunk). For
    /// `.closeDelimited` this is a connection fact, so the parser leaves it false; the engine sets it.
    public var incomplete: Bool
}

// MARK: - Raw messages

/// An HTTP/1 request as raw bytes plus an eagerly-computed, re-computed-on-edit parsed view.
public struct RawRequest: Sendable, Hashable {
    /// The exact bytes of the message (the source of truth).
    public let bytes: Bytes
    /// The framed view, computed in `init` and recomputed by `replacing`.
    public let parsed: ParsedRequest
    /// Parse `bytes` eagerly into `parsed`.
    public init(_ bytes: Bytes) {
        self.bytes = bytes
        self.parsed = HTTP1.parseRequest(bytes)
    }
    /// Return the exact input bytes unchanged (HTTP-001 identity).
    public func serialize() -> Bytes { bytes }
    /// Splice `new` over `range` and re-parse; only those bytes change.
    public func replacing(_ range: Range<Int>, with new: Bytes) -> RawRequest {
        var b = bytes
        b.replaceSubrange(range, with: new)
        return RawRequest(b)
    }
    /// The value bytes of the last header with this (case-insensitive) name, if any.
    public func headerValue(_ name: String) -> Bytes? {
        HTTP1.lastHeaderValue(name, parsed.headers, bytes)
    }
}

/// An HTTP/1 response as raw bytes plus an eagerly-computed, re-computed-on-edit parsed view.
public struct RawResponse: Sendable, Hashable {
    /// The exact bytes of the message (the source of truth).
    public let bytes: Bytes
    /// The framed view, computed in `init` and recomputed by `replacing`.
    public let parsed: ParsedResponse
    /// Parse `bytes` eagerly into `parsed`.
    public init(_ bytes: Bytes) {
        self.bytes = bytes
        self.parsed = HTTP1.parseResponse(bytes)
    }
    /// Return the exact input bytes unchanged (HTTP-001 identity).
    public func serialize() -> Bytes { bytes }
    /// Splice `new` over `range` and re-parse; only those bytes change.
    public func replacing(_ range: Range<Int>, with new: Bytes) -> RawResponse {
        var b = bytes
        b.replaceSubrange(range, with: new)
        return RawResponse(b)
    }
    /// The value bytes of the last header with this (case-insensitive) name, if any.
    public func headerValue(_ name: String) -> Bytes? {
        HTTP1.lastHeaderValue(name, parsed.headers, bytes)
    }
}

// MARK: - Parser

/// Stateless, raw-preserving HTTP/1 framing routines used by `RawRequest`/`RawResponse`.
public enum HTTP1 {
    static let CR: UInt8 = 0x0D
    static let LF: UInt8 = 0x0A
    static let SP: UInt8 = 0x20
    static let HT: UInt8 = 0x09
    static let COLON: UInt8 = 0x3A
    static let SEMI: UInt8 = 0x3B
    static let COMMA: UInt8 = 0x2C

    typealias LineScan = (ranges: [Range<Int>], ending: LineEnding, warnings: [ParseWarning])
    typealias HeaderScan = (fields: [HeaderField], warnings: [ParseWarning])

    /// Returns (index just past the end of the header block, sawCRLFCRLF). If no blank line is found,
    /// returns (count, false) — the whole input is headers, body empty (missingFinalCRLF warning).
    static func headerBlockEnd(_ a: [UInt8]) -> (end: Int, crlf: Bool) {
        var i = 0
        while i < a.count {
            if i + 3 < a.count, a[i] == CR, a[i + 1] == LF, a[i + 2] == CR, a[i + 3] == LF {
                return (i + 4, true)
            }
            if i + 1 < a.count, a[i] == LF, a[i + 1] == LF {
                return (i + 2, false)
            }
            i += 1
        }
        return (a.count, false)
    }

    /// Split a header region `[0, end)` into content line ranges (terminator excluded) plus the
    /// observed line-ending style and any warnings.
    static func lines(_ a: [UInt8], upTo end: Int) -> LineScan {
        var ranges: [Range<Int>] = []
        var warnings: [ParseWarning] = []
        var start = 0
        var i = 0
        var sawCRLF = false
        var sawLF = false
        while i < end {
            if a[i] == LF {
                var lineEnd = i
                if lineEnd > start, a[lineEnd - 1] == CR {
                    lineEnd -= 1
                    sawCRLF = true
                } else {
                    sawLF = true
                }
                ranges.append(start..<lineEnd)
                start = i + 1
            }
            i += 1
        }
        // Trailing bytes without a terminator (the last header before the blank line).
        if start < end {
            ranges.append(start..<end)
        }
        if sawLF && !sawCRLF {
            warnings.append(.bareLF)
        }
        let ending: LineEnding
        if ranges.isEmpty {
            ending = .none
        } else if sawCRLF && sawLF {
            ending = .mixed
        } else if sawCRLF {
            ending = .crlf
        } else if sawLF {
            ending = .lf
        } else {
            ending = .none
        }
        return (ranges, ending, warnings)
    }

    /// Parse header field lines (the lines after the start line), handling obsolete line folding.
    static func parseHeaders(_ a: [UInt8], _ lineRanges: ArraySlice<Range<Int>>) -> HeaderScan {
        var fields: [HeaderField] = []
        var warnings: [ParseWarning] = []
        for r in lineRanges {
            if r.isEmpty { continue }
            let first = a[r.lowerBound]
            if first == SP || first == HT {
                // obs-fold: continuation of the previous header's value.
                warnings.append(.obsoleteLineFolding)
                if var last = fields.popLast() {
                    last.value = last.value.lowerBound..<r.upperBound
                    last.line = last.line.lowerBound..<r.upperBound
                    fields.append(last)
                }
                continue
            }
            guard let colon = (r.first { a[$0] == COLON }) else {
                // No colon: malformed field line; keep raw as a nameless line.
                warnings.append(.invalidCharInName)
                fields.append(HeaderField(name: r.lowerBound..<r.lowerBound, value: r, line: r))
                continue
            }
            var vStart = colon + 1
            while vStart < r.upperBound, a[vStart] == SP || a[vStart] == HT {
                vStart += 1
            }
            var vEnd = r.upperBound
            while vEnd > vStart, a[vEnd - 1] == SP || a[vEnd - 1] == HT {
                vEnd -= 1
            }
            fields.append(HeaderField(name: r.lowerBound..<colon, value: vStart..<vEnd, line: r))
        }
        return (fields, warnings)
    }

    /// Frame a request's start line, headers, and body as byte ranges, never normalizing.
    public static func parseRequest(_ bytes: Bytes) -> ParsedRequest {
        let a = bytes.rawBytes
        let (end, crlf) = headerBlockEnd(a)
        var warnings: [ParseWarning] = crlf ? [] : (a.isEmpty ? [] : [.missingFinalCRLF])
        let headerRegionEnd = end == a.count ? a.count : end - (crlf ? 2 : 1)
        let (lineRanges, ending, lineWarn) = lines(a, upTo: headerRegionEnd)
        warnings.append(contentsOf: lineWarn)
        let startLine = lineRanges.first ?? 0..<0
        // request-line: METHOD SP target SP version
        var method = startLine
        var target = 0..<0
        var version = 0..<0
        let parts = splitOnSpace(a, startLine)
        if parts.count >= 3 {
            method = parts[0]
            target = parts[1]
            version = parts[2]
        } else {
            warnings.append(.malformedStartLine)
            if let p0 = parts.first { method = p0 }
        }
        let (fields, hWarn) = parseHeaders(a, lineRanges.dropFirst())
        warnings.append(contentsOf: hWarn)
        return ParsedRequest(
            method: method, target: target, version: version, headers: fields,
            headerBlockEnd: end, body: end..<a.count, lineEnding: ending, warnings: warnings)
    }

    /// Frame a response's status line, headers, and body, and resolve body framing (HTTP-002).
    public static func parseResponse(_ bytes: Bytes) -> ParsedResponse {
        let a = bytes.rawBytes
        let (end, crlf) = headerBlockEnd(a)
        var warnings: [ParseWarning] = crlf ? [] : (a.isEmpty ? [] : [.missingFinalCRLF])
        let headerRegionEnd = end == a.count ? a.count : end - (crlf ? 2 : 1)
        let (lineRanges, ending, lineWarn) = lines(a, upTo: headerRegionEnd)
        warnings.append(contentsOf: lineWarn)
        let startLine = lineRanges.first ?? 0..<0
        // status-line: version SP status SP reason
        var version = 0..<0
        var status = 0
        var reason = 0..<0
        let parts = splitOnSpace(a, startLine, max: 3)
        if parts.count >= 2 {
            version = parts[0]
            status = Int(bytes[parts[1]].string()) ?? 0
            if parts.count >= 3 { reason = parts[2] }
        } else {
            warnings.append(.malformedStartLine)
        }
        let (fields, hWarn) = parseHeaders(a, lineRanges.dropFirst())
        warnings.append(contentsOf: hWarn)

        // Framing (HTTP-002, RFC 9112 §6.3). Precedence:
        //   1. A bodyless status (1xx/204/304) is ALWAYS terminated at the header block, regardless
        //      of any Content-Length/Transfer-Encoding present (a 304 echoes the cached body's
        //      length but carries no body). HEAD is also bodyless but needs the request method, so
        //      it is decided at the engine layer, not here (F03 §4).
        //   2. Otherwise chunked wins over Content-Length (and the conflict is flagged).
        //   3. Otherwise Content-Length, else read-until-close.
        let teChunked = headerContains(a, fields, name: "transfer-encoding", token: "chunked")
        let clValues = headerValues("content-length", fields, a)
        if clValues.count > 1 { warnings.append(.duplicateContentLength) }
        let contentLength = clValues.last.flatMap { Int(Bytes(Array(a[$0])).string().trimmedASCII()) }
        if teChunked && contentLength != nil { warnings.append(.conflictingFraming) }
        let bodyless = status == 204 || status == 304 || (status >= 100 && status < 200)
        let framing: BodyFraming
        if bodyless {
            framing = .none
        } else if teChunked {
            framing = .chunked
        } else if contentLength != nil {
            framing = .contentLength
        } else {
            framing = .closeDelimited
        }
        let body = end..<a.count
        var incomplete = false
        if framing == .contentLength, let cl = contentLength {
            incomplete = (a.count - end) < cl
        }
        if framing == .chunked {
            incomplete = !endsWithTerminalChunk(a, from: end)
        }
        // De-chunked view (HTTP-002): only when framed as chunked and the terminal chunk is present.
        let dechunked: Bytes? = (framing == .chunked && !incomplete) ? dechunk(a, from: end) : nil

        return ParsedResponse(
            version: version, statusCode: status, reasonPhrase: reason, headers: fields,
            headerBlockEnd: end, body: body, dechunkedBody: dechunked,
            transferEncodingChunked: teChunked, contentLength: contentLength,
            bodyFraming: framing, interimResponses: [], lineEnding: ending,
            warnings: warnings, incomplete: incomplete)
    }

    // MARK: helpers

    static func splitOnSpace(_ a: [UInt8], _ r: Range<Int>, max: Int = 3) -> [Range<Int>] {
        var out: [Range<Int>] = []
        var i = r.lowerBound
        while i < r.upperBound {
            while i < r.upperBound, a[i] == SP { i += 1 }
            if i >= r.upperBound { break }
            let start = i
            if out.count == max - 1 {
                // The last part keeps any inner spaces (e.g. a multi-word reason phrase).
                out.append(start..<r.upperBound)
                break
            }
            while i < r.upperBound, a[i] != SP { i += 1 }
            out.append(start..<i)
        }
        return out
    }

    static func headerValues(_ name: String, _ fields: [HeaderField], _ a: [UInt8]) -> [Range<Int>] {
        let want = Array(name.lowercased().utf8)
        return fields.filter { eqCI(a, $0.name, want) }.map { $0.value }
    }

    static func lastHeaderValue(_ name: String, _ fields: [HeaderField], _ bytes: Bytes) -> Bytes? {
        guard let r = headerValues(name, fields, bytes.rawBytes).last else { return nil }
        return bytes[r]
    }

    static func headerContains(
        _ a: [UInt8], _ fields: [HeaderField], name: String, token: String
    ) -> Bool {
        let tok = Array(token.lowercased().utf8)
        for v in headerValues(name, fields, a) where containsTokenCI(a, v, tok) {
            return true
        }
        return false
    }

    static func eqCI(_ a: [UInt8], _ r: Range<Int>, _ lowerWant: [UInt8]) -> Bool {
        guard r.count == lowerWant.count else { return false }
        for (k, idx) in r.enumerated() where lower(a[idx]) != lowerWant[k] {
            return false
        }
        return true
    }

    /// Split a header value on commas/OWS and compare each token case-insensitively.
    static func containsTokenCI(_ a: [UInt8], _ r: Range<Int>, _ lowerTok: [UInt8]) -> Bool {
        var i = r.lowerBound
        while i < r.upperBound {
            while i < r.upperBound, a[i] == SP || a[i] == HT || a[i] == COMMA { i += 1 }
            let s = i
            while i < r.upperBound, a[i] != COMMA { i += 1 }
            var e = i
            while e > s, a[e - 1] == SP || a[e - 1] == HT { e -= 1 }
            if eqCI(a, s..<e, lowerTok) { return true }
        }
        return false
    }

    static func lower(_ b: UInt8) -> UInt8 { (b >= 0x41 && b <= 0x5A) ? b + 0x20 : b }

    /// True if the chunked body ending at `a.count` contains a terminating zero-length chunk.
    static func endsWithTerminalChunk(_ a: [UInt8], from start: Int) -> Bool {
        // Minimal check: a "0" chunk-size line somewhere after `start` followed by CRLF.
        var i = start
        while i < a.count {
            let lineStart = i
            while i < a.count, a[i] != LF { i += 1 }
            let end = (i > lineStart && a[i - 1] == CR) ? i - 1 : i
            let sizeHex = a[lineStart..<end].prefix { $0 != SEMI }  // ';' starts a chunk-ext
            if sizeHex.allSatisfy({ $0 == 0x30 }) && !sizeHex.isEmpty { return true }  // all '0'
            i += 1
            if i >= a.count { break }
        }
        return false
    }

    /// Decode a complete chunked body `[start, a.count)` into its payload bytes. Returns nil if the
    /// framing is malformed or truncated. Chunk extensions (`;name=value`) and the trailer are ignored.
    static func dechunk(_ a: [UInt8], from start: Int) -> Bytes? {
        var out: [UInt8] = []
        var i = start
        while i < a.count {
            // chunk-size line: hex digits up to ';' or CRLF
            let lineStart = i
            while i < a.count, a[i] != LF { i += 1 }
            guard i < a.count else { return nil }  // no LF terminating the size line
            let lineEnd = (i > lineStart && a[i - 1] == CR) ? i - 1 : i
            let hexEnd = a[lineStart..<lineEnd].firstIndex(of: SEMI) ?? lineEnd  // ';' = chunk-ext
            guard let size = hexValue(a, lineStart..<hexEnd) else { return nil }
            i += 1  // step past LF
            if size == 0 { return Bytes(out) }  // terminal chunk; ignore trailer
            guard i + size <= a.count else { return nil }  // truncated chunk data
            out.append(contentsOf: a[i..<i + size])
            i += size
            // chunk data is followed by CRLF
            if i < a.count, a[i] == CR { i += 1 }
            if i < a.count, a[i] == LF {
                i += 1
            } else {
                return nil
            }
        }
        return nil  // ran out before the terminal chunk
    }

    /// Parse an ASCII hex integer over `a[range]` (no "0x"); nil if empty or a non-hex byte appears.
    static func hexValue(_ a: [UInt8], _ range: Range<Int>) -> Int? {
        if range.isEmpty { return nil }
        var v = 0
        for idx in range {
            let b = a[idx]
            let d: Int
            switch b {
            case 0x30...0x39: d = Int(b - 0x30)  // 0-9
            case 0x41...0x46: d = Int(b - 0x41 + 10)  // A-F
            case 0x61...0x66: d = Int(b - 0x61 + 10)  // a-f
            default: return nil
            }
            v = v &* 16 &+ d
        }
        return v
    }
}

extension String {
    /// Trim ASCII spaces/tabs from both ends (no Foundation).
    func trimmedASCII() -> String {
        var s = self[...]
        while let f = s.first, f == " " || f == "\t" { s = s.dropFirst() }
        while let l = s.last, l == " " || l == "\t" { s = s.dropLast() }
        return String(s)
    }
}
