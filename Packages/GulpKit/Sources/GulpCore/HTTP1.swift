// GulpCore — raw-preserving HTTP/1 messages: parser + response framer (doc 04 §2, F03 HTTP-001/002).
//
// The parser frames a message (finds the header block, the status/request line, headers as byte
// ranges, and the body) WITHOUT ever rejecting or normalizing it — malformed input yields warnings,
// not errors (parser tolerance rules, doc 04 §2). `serialize()` is the identity over the input bytes.

// MARK: - Supporting enums

public enum Scheme: String, Sendable, Codable, Hashable { case http, https }

public enum HTTPVersion: String, Sendable, Codable, Hashable {
    case http1_0 = "HTTP/1.0", http1_1 = "HTTP/1.1", http2 = "HTTP/2"
}

public enum LineEnding: Sendable, Hashable { case crlf, lf, mixed, none }

public enum BodyFraming: Sendable, Hashable { case contentLength, chunked, closeDelimited, none }

public enum ParseWarning: Sendable, Equatable, Hashable {
    case bareLF, obsoleteLineFolding, missingFinalCRLF, invalidCharInName
    case duplicateContentLength, conflictingFraming, malformedStartLine
    case oversizedHeaders   // emitted by the engine's header-size guard, not the pure parser
    case nonUTF8Header
}

// MARK: - Header field

/// One header line, as byte ranges into the owning message's bytes (order and duplicates preserved).
public struct HeaderField: Sendable, Hashable {
    public var name: Range<Int>
    public var value: Range<Int>     // trimmed of leading OWS, but points at the real bytes
    public var line: Range<Int>      // the whole field line, terminator excluded
    public init(name: Range<Int>, value: Range<Int>, line: Range<Int>) {
        self.name = name; self.value = value; self.line = line
    }
}

// MARK: - Parsed views

public struct ParsedRequest: Sendable, Hashable {
    public var method: Range<Int>
    public var target: Range<Int>
    public var version: Range<Int>
    public var headers: [HeaderField]
    public var headerBlockEnd: Int
    public var body: Range<Int>
    public var lineEnding: LineEnding
    public var warnings: [ParseWarning]
}

public struct ParsedResponse: Sendable, Hashable {
    public var version: Range<Int>
    public var statusCode: Int
    public var reasonPhrase: Range<Int>
    public var headers: [HeaderField]
    public var headerBlockEnd: Int
    public var body: Range<Int>                 // the body as framed (raw; chunked stays chunked)
    public var dechunkedBody: Bytes?            // de-chunked view when Transfer-Encoding: chunked (nil otherwise)
    public var transferEncodingChunked: Bool
    public var contentLength: Int?
    public var bodyFraming: BodyFraming
    /// Recorded 1xx responses that preceded this final one (HTTP-002). The single-message parser
    /// never populates this — it is accumulated by the HTTP engine across an exchange — so it is
    /// always `[]` here, kept for shape-parity with the engine's view (doc 04 §2).
    public var interimResponses: [ParsedResponse]
    public var lineEnding: LineEnding
    public var warnings: [ParseWarning]
    public var incomplete: Bool                 // true if the connection closed before the declared body finished
}

// MARK: - Raw messages

public struct RawRequest: Sendable, Hashable {
    public let bytes: Bytes
    public let parsed: ParsedRequest
    public init(_ bytes: Bytes) { self.bytes = bytes; self.parsed = HTTP1.parseRequest(bytes) }
    public func serialize() -> Bytes { bytes }
    /// Splice `new` over `range` and re-parse; only those bytes change.
    public func replacing(_ range: Range<Int>, with new: Bytes) -> RawRequest {
        var b = bytes; b.replaceSubrange(range, with: new); return RawRequest(b)
    }
    /// Convenience: the value bytes of the last header with this (case-insensitive) name.
    public func headerValue(_ name: String) -> Bytes? { HTTP1.lastHeaderValue(name, parsed.headers, bytes) }
}

public struct RawResponse: Sendable, Hashable {
    public let bytes: Bytes
    public let parsed: ParsedResponse
    public init(_ bytes: Bytes) { self.bytes = bytes; self.parsed = HTTP1.parseResponse(bytes) }
    public func serialize() -> Bytes { bytes }
    public func replacing(_ range: Range<Int>, with new: Bytes) -> RawResponse {
        var b = bytes; b.replaceSubrange(range, with: new); return RawResponse(b)
    }
    public func headerValue(_ name: String) -> Bytes? { HTTP1.lastHeaderValue(name, parsed.headers, bytes) }
}

// MARK: - Parser

public enum HTTP1 {
    static let CR: UInt8 = 0x0D, LF: UInt8 = 0x0A, SP: UInt8 = 0x20, HT: UInt8 = 0x09, COLON: UInt8 = 0x3A

    /// Returns (index just past the end of the header block, sawCRLFCRLF). If no blank line is found,
    /// returns (count, false) — the whole input is headers, body empty (missingFinalCRLF warning).
    static func headerBlockEnd(_ a: [UInt8]) -> (end: Int, crlf: Bool) {
        var i = 0
        while i < a.count {
            if a[i] == CR, i + 3 < a.count + 0, i + 3 <= a.count - 1, a[i+1] == LF, a[i+2] == CR, a[i+3] == LF {
                return (i + 4, true)
            }
            if a[i] == LF, i + 1 <= a.count - 1, a[i+1] == LF {
                return (i + 2, false)
            }
            i += 1
        }
        return (a.count, false)
    }

    /// Split a header region [0, end) into content line ranges (terminator excluded) + line-ending info.
    static func lines(_ a: [UInt8], upTo end: Int) -> (ranges: [Range<Int>], ending: LineEnding, warnings: [ParseWarning]) {
        var ranges: [Range<Int>] = []
        var warnings: [ParseWarning] = []
        var start = 0, i = 0
        var sawCRLF = false, sawLF = false
        while i < end {
            if a[i] == LF {
                var lineEnd = i
                if lineEnd > start, a[lineEnd - 1] == CR { lineEnd -= 1; sawCRLF = true } else { sawLF = true }
                ranges.append(start..<lineEnd)
                start = i + 1
            }
            i += 1
        }
        if start < end { ranges.append(start..<end) }   // trailing bytes w/o terminator (last header before blank line)
        if sawLF && !sawCRLF { warnings.append(.bareLF) }
        let ending: LineEnding = ranges.isEmpty ? .none : (sawCRLF && sawLF ? .mixed : (sawCRLF ? .crlf : (sawLF ? .lf : .none)))
        return (ranges, ending, warnings)
    }

    /// Parse header field lines (index 1...) handling obsolete line folding.
    static func parseHeaders(_ a: [UInt8], _ lineRanges: ArraySlice<Range<Int>>) -> (fields: [HeaderField], warnings: [ParseWarning]) {
        var fields: [HeaderField] = []
        var warnings: [ParseWarning] = []
        for r in lineRanges {
            if r.isEmpty { continue }
            let first = a[r.lowerBound]
            if first == SP || first == HT {
                // obs-fold: continuation of the previous header's value
                warnings.append(.obsoleteLineFolding)
                if var last = fields.popLast() {
                    last.value = last.value.lowerBound..<r.upperBound
                    last.line = last.line.lowerBound..<r.upperBound
                    fields.append(last)
                }
                continue
            }
            guard let colon = (r.first { a[$0] == COLON }) else {
                warnings.append(.invalidCharInName)   // no colon: malformed field line; keep raw as a nameless line
                fields.append(HeaderField(name: r.lowerBound..<r.lowerBound, value: r, line: r))
                continue
            }
            var vStart = colon + 1
            while vStart < r.upperBound, a[vStart] == SP || a[vStart] == HT { vStart += 1 }
            var vEnd = r.upperBound
            while vEnd > vStart, a[vEnd - 1] == SP || a[vEnd - 1] == HT { vEnd -= 1 }   // trim trailing OWS
            fields.append(HeaderField(name: r.lowerBound..<colon, value: vStart..<vEnd, line: r))
        }
        return (fields, warnings)
    }

    public static func parseRequest(_ bytes: Bytes) -> ParsedRequest {
        let a = bytes.rawBytes
        let (end, crlf) = headerBlockEnd(a)
        var warnings: [ParseWarning] = crlf ? [] : (a.isEmpty ? [] : [.missingFinalCRLF])
        let (lineRanges, ending, lineWarn) = lines(a, upTo: end == a.count ? a.count : end - (crlf ? 2 : 1))
        warnings.append(contentsOf: lineWarn)
        let startLine = lineRanges.first ?? 0..<0
        // request-line: METHOD SP target SP version
        var method = startLine, target = 0..<0, version = 0..<0
        let parts = splitOnSpace(a, startLine)
        if parts.count >= 3 { method = parts[0]; target = parts[1]; version = parts[2] }
        else { warnings.append(.malformedStartLine); if let p0 = parts.first { method = p0 } }
        let (fields, hWarn) = parseHeaders(a, lineRanges.dropFirst())
        warnings.append(contentsOf: hWarn)
        return ParsedRequest(method: method, target: target, version: version, headers: fields,
                             headerBlockEnd: end, body: end..<a.count, lineEnding: ending, warnings: warnings)
    }

    public static func parseResponse(_ bytes: Bytes) -> ParsedResponse {
        let a = bytes.rawBytes
        let (end, crlf) = headerBlockEnd(a)
        var warnings: [ParseWarning] = crlf ? [] : (a.isEmpty ? [] : [.missingFinalCRLF])
        let (lineRanges, ending, lineWarn) = lines(a, upTo: end == a.count ? a.count : end - (crlf ? 2 : 1))
        warnings.append(contentsOf: lineWarn)
        let startLine = lineRanges.first ?? 0..<0
        // status-line: version SP status SP reason
        var version = 0..<0, status = 0, reason = 0..<0
        let parts = splitOnSpace(a, startLine, max: 3)
        if parts.count >= 2 {
            version = parts[0]
            status = Int(bytes[parts[1]].string()) ?? 0
            if parts.count >= 3 { reason = parts[2] }
        } else { warnings.append(.malformedStartLine) }
        let (fields, hWarn) = parseHeaders(a, lineRanges.dropFirst())
        warnings.append(contentsOf: hWarn)

        // Framing (HTTP-002, RFC 9112 §6.3). Precedence:
        //   1. A bodyless status (1xx/204/304) is ALWAYS terminated at the header block, regardless of
        //      any Content-Length/Transfer-Encoding present (a 304 echoes the cached body's length but
        //      carries no body). HEAD is also bodyless but needs the request method, so it is decided at
        //      the engine layer, not here (F03 §4).
        //   2. Otherwise chunked wins over Content-Length (and the conflict is flagged).
        //   3. Otherwise Content-Length, else read-until-close.
        let teChunked = headerContains(a, fields, name: "transfer-encoding", token: "chunked")
        let clValues = headerValues("content-length", fields, a)
        if clValues.count > 1 { warnings.append(.duplicateContentLength) }
        let contentLength = clValues.last.flatMap { Int(Bytes(Array(a[$0])).string().trimmedASCII()) }
        if teChunked && contentLength != nil { warnings.append(.conflictingFraming) }
        let bodyless = status == 204 || status == 304 || (status >= 100 && status < 200)
        let framing: BodyFraming = bodyless ? .none
            : (teChunked ? .chunked
            : (contentLength != nil ? .contentLength : .closeDelimited))
        let body = end..<a.count
        var incomplete = false
        if framing == .contentLength, let cl = contentLength { incomplete = (a.count - end) < cl }
        if framing == .chunked { incomplete = !endsWithTerminalChunk(a, from: end) }

        // De-chunked view (HTTP-002): only when framed as chunked and the terminal chunk is present.
        let dechunked: Bytes? = (framing == .chunked && !incomplete) ? dechunk(a, from: end) : nil

        return ParsedResponse(version: version, statusCode: status, reasonPhrase: reason, headers: fields,
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
            if out.count == max - 1 { out.append(start..<r.upperBound); break }   // last part keeps inner spaces
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

    static func headerContains(_ a: [UInt8], _ fields: [HeaderField], name: String, token: String) -> Bool {
        let tok = Array(token.lowercased().utf8)
        for v in headerValues(name, fields, a) where containsTokenCI(a, v, tok) { return true }
        return false
    }

    static func eqCI(_ a: [UInt8], _ r: Range<Int>, _ lowerWant: [UInt8]) -> Bool {
        guard r.count == lowerWant.count else { return false }
        for (k, idx) in r.enumerated() where lower(a[idx]) != lowerWant[k] { return false }
        return true
    }
    static func containsTokenCI(_ a: [UInt8], _ r: Range<Int>, _ lowerTok: [UInt8]) -> Bool {
        // split value on commas/OWS and compare case-insensitively
        var i = r.lowerBound
        while i < r.upperBound {
            while i < r.upperBound, a[i] == SP || a[i] == HT || a[i] == 0x2C { i += 1 }   // ',' = 0x2C
            let s = i
            while i < r.upperBound, a[i] != 0x2C { i += 1 }
            var e = i
            while e > s, a[e-1] == SP || a[e-1] == HT { e -= 1 }
            if eqCI(a, s..<e, lowerTok) { return true }
        }
        return false
    }
    static func lower(_ b: UInt8) -> UInt8 { (b >= 0x41 && b <= 0x5A) ? b + 0x20 : b }

    /// True if the chunked body ending at `a.count` contains a terminating zero-length chunk ("0\r\n").
    static func endsWithTerminalChunk(_ a: [UInt8], from start: Int) -> Bool {
        // Minimal check: a "0" chunk-size line somewhere after `start` followed by CRLF.
        var i = start
        while i < a.count {
            // read a chunk-size line
            let lineStart = i
            while i < a.count, a[i] != LF { i += 1 }
            let end = (i > lineStart && a[i-1] == CR) ? i - 1 : i
            let sizeHex = a[lineStart..<end].prefix { $0 != 0x3B }   // ';' starts chunk-ext
            if sizeHex.allSatisfy({ $0 == 0x30 }) && !sizeHex.isEmpty { return true }   // all '0'
            i += 1
            // skip chunk data of parsed size would require full parse; this is the "is it terminated" heuristic
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
            guard i < a.count else { return nil }                 // no LF terminating the size line
            let lineEnd = (i > lineStart && a[i - 1] == CR) ? i - 1 : i
            let hexEnd = (a[lineStart..<lineEnd].firstIndex(of: 0x3B)) ?? lineEnd   // ';' = chunk-ext
            guard let size = hexValue(a, lineStart..<hexEnd) else { return nil }
            i += 1                                                // step past LF
            if size == 0 { return Bytes(out) }                    // terminal chunk; ignore trailer
            guard i + size <= a.count else { return nil }         // truncated chunk data
            out.append(contentsOf: a[i..<i + size])
            i += size
            // chunk data is followed by CRLF
            if i < a.count, a[i] == CR { i += 1 }
            if i < a.count, a[i] == LF { i += 1 } else { return nil }
        }
        return nil                                                // ran out before the terminal chunk
    }

    /// Parse an ASCII hex integer over `a[range]` (no "0x"); nil if empty or a non-hex byte appears.
    static func hexValue(_ a: [UInt8], _ range: Range<Int>) -> Int? {
        if range.isEmpty { return nil }
        var v = 0
        for idx in range {
            let b = a[idx]
            let d: Int
            switch b {
            case 0x30...0x39: d = Int(b - 0x30)          // 0-9
            case 0x41...0x46: d = Int(b - 0x41 + 10)     // A-F
            case 0x61...0x66: d = Int(b - 0x61 + 10)     // a-f
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
