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
    /// The value bytes of every header with this (case-insensitive) name, in order.
    public func headerValues(_ name: String) -> [Bytes] {
        HTTP1.headerValues(name, parsed.headers, bytes.rawBytes).map { bytes[$0] }
    }
    /// True if any `name` header lists `token` (comma-separated, case-insensitive), e.g.
    /// `Connection: close`.
    public func hasHeaderToken(_ name: String, _ token: String) -> Bool {
        HTTP1.headerContains(bytes.rawBytes, parsed.headers, name: name, token: token)
    }
}

/// An HTTP/1 response as raw bytes plus an eagerly-computed, re-computed-on-edit parsed view.
public struct RawResponse: Sendable, Hashable {
    /// The exact bytes of the final response (the source of truth).
    public let bytes: Bytes
    /// The framed view, computed in `init` and recomputed by `replacing`.
    public let parsed: ParsedResponse
    /// Interim (1xx) responses that preceded this final one on the wire, each with its own bytes
    /// (HTTP-002). `parsed.interimResponses` mirrors their parsed views.
    public let interim: [RawResponse]
    /// True when this answers a HEAD request: such a response has no body whatever its framing
    /// headers say (RFC 9112 §6.3), so `bodyFraming` is `.none` and it is never `incomplete`.
    public let isHeadResponse: Bool

    /// Parse `bytes` eagerly into `parsed`. The engine passes `interim` and `headRequest` because
    /// only it knows what preceded the response on the wire and which method was sent.
    public init(_ bytes: Bytes, interim: [RawResponse] = [], headRequest: Bool = false) {
        var p = HTTP1.parseResponse(bytes)
        if headRequest {
            p.bodyFraming = .none
            p.incomplete = false
            p.dechunkedBody = nil
        }
        p.interimResponses = interim.map(\.parsed)
        self.bytes = bytes
        self.parsed = p
        self.interim = interim
        self.isHeadResponse = headRequest
    }
    /// Rebuild a response from every byte received on the wire, splitting off the interim (1xx,
    /// except 101) responses that precede the final one. Inverse of `wireBytes`.
    public init(wire: Bytes, headRequest: Bool = false) {
        var interim: [RawResponse] = []
        var rest = wire.rawBytes
        while true {
            let (end, terminator) = HTTP1.headerBlockEnd(rest)
            guard terminator != 0, end < rest.count else { break }
            let status = HTTP1.parseResponse(Bytes(Array(rest[..<end]))).statusCode
            guard status >= 100, status < 200, status != 101 else { break }
            interim.append(RawResponse(Bytes(Array(rest[..<end]))))
            rest = Array(rest[end...])
        }
        self.init(Bytes(rest), interim: interim, headRequest: headRequest)
    }

    /// Every byte received for this response, in wire order: interim responses, then the final one.
    public var wireBytes: Bytes {
        var all = Bytes()
        for response in interim { all.append(response.bytes) }
        all.append(bytes)
        return all
    }

    /// Return the exact input bytes unchanged (HTTP-001 identity).
    public func serialize() -> Bytes { bytes }
    /// Splice `new` over `range` and re-parse; only those bytes change.
    public func replacing(_ range: Range<Int>, with new: Bytes) -> RawResponse {
        var b = bytes
        b.replaceSubrange(range, with: new)
        return RawResponse(b, interim: interim, headRequest: isHeadResponse)
    }
    /// The value bytes of the last header with this (case-insensitive) name, if any.
    public func headerValue(_ name: String) -> Bytes? {
        HTTP1.lastHeaderValue(name, parsed.headers, bytes)
    }
    /// The value bytes of every header with this (case-insensitive) name, in order.
    public func headerValues(_ name: String) -> [Bytes] {
        HTTP1.headerValues(name, parsed.headers, bytes.rawBytes).map { bytes[$0] }
    }
    /// True if any `name` header lists `token` (comma-separated, case-insensitive), e.g.
    /// `Connection: close`.
    public func hasHeaderToken(_ name: String, _ token: String) -> Bool {
        HTTP1.headerContains(bytes.rawBytes, parsed.headers, name: name, token: token)
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

    /// A header block larger than this is refused rather than buffered on: the proxy answers 431,
    /// the engine fails the exchange with `.tooLarge`.
    public static let maxHeaderBytes = 1_024 * 1_024

    /// Locate the blank line that ends the header block, scanning from `start`. Returns the index
    /// just past it and the terminator length: 4 for CRLFCRLF, 2 for a tolerated LFLF (including
    /// CRLF+LF), or 0 when no blank line exists (then `end == a.count`: the whole input is headers,
    /// body empty). A growing buffer stays linear: resume at `headerScanResume(previousCount)`.
    public static func headerBlockEnd(_ a: [UInt8], from start: Int = 0) -> (end: Int, terminator: Int) {
        var i = start
        while i < a.count {
            if i + 3 < a.count, a[i] == CR, a[i + 1] == LF, a[i + 2] == CR, a[i + 3] == LF {
                return (i + 4, 4)
            }
            if i + 1 < a.count, a[i] == LF, a[i + 1] == LF {
                return (i + 2, 2)
            }
            i += 1
        }
        return (a.count, 0)
    }

    /// Where to resume `headerBlockEnd` after a scan of `count` bytes found nothing: a terminator
    /// (at most 4 bytes) may straddle the old end, so back up 3.
    public static func headerScanResume(_ count: Int) -> Int { max(0, count - 3) }

    /// The header region `[0, regionEnd)` (start line + field lines, excluding the blank line) and
    /// the warning for a missing blank line.
    static func headerRegion(_ a: [UInt8]) -> (blockEnd: Int, regionEnd: Int, warnings: [ParseWarning]) {
        let (end, terminator) = headerBlockEnd(a)
        switch terminator {
        case 4: return (end, end - 2, [])
        case 2: return (end, end - 1, [])
        default: return (end, a.count, a.isEmpty ? [] : [.missingFinalCRLF])
        }
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
        let (end, headerRegionEnd, regionWarn) = headerRegion(a)
        var warnings = regionWarn
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
        // Framing ambiguity stays visible (F01 §4.1): it is exactly what smuggling tests look for.
        let lengths = headerValues("content-length", fields, a)
        if lengths.count > 1 { warnings.append(.duplicateContentLength) }
        if !lengths.isEmpty, !headerValues("transfer-encoding", fields, a).isEmpty {
            warnings.append(.conflictingFraming)
        }
        return ParsedRequest(
            method: method, target: target, version: version, headers: fields,
            headerBlockEnd: end, body: end..<a.count, lineEnding: ending, warnings: warnings)
    }

    /// Frame a response's status line, headers, and body, and resolve body framing (HTTP-002).
    public static func parseResponse(_ bytes: Bytes) -> ParsedResponse {
        let a = bytes.rawBytes
        let (end, headerRegionEnd, regionWarn) = headerRegion(a)
        var warnings = regionWarn
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
        // De-chunked view (HTTP-002): only when the chunked body is complete.
        var dechunked: Bytes?
        if framing == .chunked {
            var payload: [UInt8] = []
            if case .complete = walkChunked(a, from: end, data: { payload += a[$0] }) {
                dechunked = Bytes(payload)
            } else {
                incomplete = true
            }
        }

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

    /// Result of scanning a chunked body.
    public enum ChunkScan: Sendable, Equatable {
        /// The body is complete; `end` is the index just past the trailer section's empty line.
        case complete(end: Int)
        /// More bytes are needed; resume scanning at `resumeAt` (the first incomplete chunk).
        case needMore(resumeAt: Int)
        /// The framing is broken (bad chunk size, or data not followed by a line break).
        case malformed
    }

    /// Scan a chunked body that starts at `start` — every chunk, the last (zero-size) chunk, and the
    /// trailer section up to its empty line. Exact: chunk data is skipped by its declared size, so a
    /// body line that happens to read `0` is never mistaken for the last chunk. Resumable: pass a
    /// previous `.needMore(resumeAt:)` as `start` so repeated scans of a growing buffer stay linear.
    public static func scanChunked(_ a: [UInt8], from start: Int) -> ChunkScan {
        walkChunked(a, from: start)
    }

    /// Index just past the end of a complete chunked body starting at `start`, or nil when more bytes
    /// are needed or the framing is malformed (see `scanChunked`).
    public static func chunkedBodyEnd(_ a: [UInt8], from start: Int) -> Int? {
        if case .complete(let end) = scanChunked(a, from: start) { return end }
        return nil
    }

    /// The one chunked-body walker (RFC 9112 §7.1): `scanChunked`, the de-chunked views and the SSE
    /// timeline all read chunked framing through it, so they never disagree about where a body ends.
    /// `data` receives each chunk's payload range in `a` — including what has arrived of a truncated
    /// last chunk — and `trailer` each trailer field line (line ending excluded), in order.
    public static func walkChunked(
        _ a: [UInt8], from start: Int, data: (Range<Int>) -> Void = { _ in },
        trailer: (Range<Int>) -> Void = { _ in }
    ) -> ChunkScan {
        var i = start
        while true {
            let chunkStart = i
            guard let lf = firstLF(a, from: i) else { return .needMore(resumeAt: chunkStart) }
            guard let size = chunkSize(a, line: i..<lf) else { return .malformed }
            i = lf + 1
            if size == 0 {
                // Trailer section: field lines until an empty line (CRLF or bare LF).
                while true {
                    guard let tlf = firstLF(a, from: i) else { return .needMore(resumeAt: chunkStart) }
                    let lineEnd = (tlf > i && a[tlf - 1] == CR) ? tlf - 1 : tlf
                    if lineEnd == i { return .complete(end: tlf + 1) }
                    trailer(i..<lineEnd)
                    i = tlf + 1
                }
            }
            guard i + size <= a.count else {
                if i < a.count { data(i..<a.count) }
                return .needMore(resumeAt: chunkStart)
            }
            data(i..<i + size)
            i += size
            if i < a.count, a[i] == CR { i += 1 }
            guard i < a.count else { return .needMore(resumeAt: chunkStart) }
            guard a[i] == LF else { return .malformed }
            i += 1
        }
    }

    /// The size on the chunk-size line `a[line]` (its LF excluded): hex digits, optional whitespace
    /// (BWS, RFC 9112 §7.1.1), an optional `;chunk-extension`, an optional CR. Nil when malformed —
    /// a sign, a `0x` prefix or leading whitespace is not a chunk size.
    static func chunkSize(_ a: [UInt8], line: Range<Int>) -> Int? {
        var end = line.upperBound
        if end > line.lowerBound, a[end - 1] == CR { end -= 1 }
        end = a[line.lowerBound..<end].firstIndex(of: SEMI) ?? end
        while end > line.lowerBound, a[end - 1] == SP || a[end - 1] == HT { end -= 1 }
        return hexValue(a, line.lowerBound..<end)
    }

    /// Index of the first LF at or after `from`, if any.
    static func firstLF(_ a: [UInt8], from: Int) -> Int? {
        var i = from
        while i < a.count {
            if a[i] == LF { return i }
            i += 1
        }
        return nil
    }

    /// Parse an ASCII hex integer over `a[range]` (no "0x"); nil if empty or a non-hex byte appears.
    static func hexValue(_ a: [UInt8], _ range: Range<Int>) -> Int? {
        // At most 15 hex digits (< 2^60), so the value can neither overflow nor wrap negative —
        // a negative size would otherwise make a chunk walker slice backwards and trap.
        if range.isEmpty || range.count > 15 { return nil }
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
