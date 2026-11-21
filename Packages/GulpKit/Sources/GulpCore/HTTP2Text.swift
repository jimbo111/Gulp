// GulpCore — HTTP/2 messages as HTTP/1-style text (doc 04 §3; F03 HTTP-021, HTTP-022, HTTP-027).
//
// HTTP/2 has no text form on the wire (it is binary frames), so Gulp shows, stores and edits it as
// HTTP/1-style text with the version token `HTTP/2`:
//
//     GET /path?q=1 HTTP/2            HTTP/2 200
//     host: example.com               content-type: text/plain
//
// Trailers (a HEADERS frame after the DATA frames — how gRPC sends `grpc-status`) are kept by
// rendering the body the way an HTTP/2→HTTP/1.1 gateway does: as a chunked body followed by the
// trailer section. The stored text then parses with the ordinary HTTP/1 parser, and is exactly what
// an HTTP/1.1 client must receive.

/// One HTTP/2 header field (names are lowercase on the wire).
public struct H2Header: Sendable, Hashable {
    /// Field name.
    public var name: String
    /// Field value.
    public var value: String

    /// A header field.
    public init(_ name: String, _ value: String) {
        self.name = name
        self.value = value
    }
}

/// The parts of an HTTP/2 request (pseudo-headers, regular headers, body).
public struct H2RequestParts: Sendable, Equatable {
    /// `:method`.
    public var method: String
    /// `:scheme`.
    public var scheme: String
    /// `:authority`.
    public var authority: String
    /// `:path`.
    public var path: String
    /// Regular headers, lowercase names, connection-specific ones removed.
    public var headers: [H2Header]
    /// The body (de-chunked).
    public var body: [UInt8]

    /// Request parts.
    public init(
        method: String, scheme: String, authority: String, path: String, headers: [H2Header], body: [UInt8]
    ) {
        self.method = method
        self.scheme = scheme
        self.authority = authority
        self.path = path
        self.headers = headers
        self.body = body
    }
}

/// The parts of an HTTP/2 response.
public struct H2ResponseParts: Sendable, Equatable {
    /// `:status`.
    public var status: Int
    /// Regular headers, lowercase names, connection-specific ones removed.
    public var headers: [H2Header]
    /// The body (de-chunked).
    public var body: [UInt8]
    /// Trailers (empty when there were none).
    public var trailers: [H2Header]

    /// Response parts.
    public init(status: Int, headers: [H2Header], body: [UInt8], trailers: [H2Header] = []) {
        self.status = status
        self.headers = headers
        self.body = body
        self.trailers = trailers
    }
}

/// Conversions between HTTP/2 messages and Gulp's HTTP/1-style text.
public enum HTTP2Text {
    /// Headers that are meaningless or forbidden in HTTP/2 (RFC 9113 §8.2.2); `host` becomes
    /// `:authority`.
    public static let connectionSpecific: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "upgrade", "transfer-encoding", "host",
    ]

    /// HTTP-021: an HTTP/1-style request (or one in HTTP/2 text form) as HTTP/2 parts. `Host` becomes
    /// `:authority` (falling back to `defaultAuthority`), names are lowercased, connection-specific
    /// headers are dropped, `TE` survives only as `trailers`, and a chunked body is de-chunked.
    public static func requestParts(
        _ request: RawRequest, scheme: Scheme, defaultAuthority: String
    ) -> H2RequestParts {
        let bytes = request.bytes
        let parsed = request.parsed
        var authority = defaultAuthority
        var headers: [H2Header] = []
        for field in parsed.headers {
            let name = bytes[field.name].string().lowercased()
            let value = bytes[field.value].string()
            if name == "host" { authority = value }
            if connectionSpecific.contains(name) { continue }
            if name == "te" {
                let codings = value.lowercased().split(separator: ",").map(\.trimmingASCIIWhitespace)
                if codings.contains("trailers") {
                    headers.append(H2Header("te", "trailers"))
                }
                continue
            }
            headers.append(H2Header(name, value))
        }
        var target = bytes[parsed.target].string()
        // An absolute-form target (`http://host/p`) still carries only the path in `:path`.
        if let schemeEnd = target.firstRange(of: "://") {
            let rest = target[schemeEnd.upperBound...]
            target = rest.firstIndex(where: { $0 == "/" || $0 == "?" }).map { String(rest[$0...]) } ?? "/"
            if target.hasPrefix("?") { target = "/" + target }
        }
        return H2RequestParts(
            method: bytes[parsed.method].string(), scheme: scheme.rawValue, authority: authority,
            path: target.isEmpty ? "/" : target, headers: headers, body: requestBody(request))
    }

    /// An HTTP/2 request as Gulp stores it: `GET /path HTTP/2` + `host:` + headers + body.
    public static func request(_ parts: H2RequestParts) -> RawRequest {
        var text = "\(parts.method) \(parts.path) HTTP/2\r\nhost: \(parts.authority)\r\n"
        for header in parts.headers where header.name != "host" {
            text += "\(header.name): \(header.value)\r\n"
        }
        return RawRequest(Bytes(Array((text + "\r\n").utf8) + parts.body))
    }

    /// HTTP-022/HTTP-027: an HTTP/2 response as Gulp stores it (`HTTP/2 200` text). With trailers the
    /// body is rendered chunked and followed by the trailer section (see the file comment).
    public static func response(_ parts: H2ResponseParts) -> RawResponse {
        var head = "HTTP/2 \(parts.status)\r\n"
        for header in parts.headers { head += "\(header.name): \(header.value)\r\n" }
        guard !parts.trailers.isEmpty else {
            return RawResponse(Bytes(Array((head + "\r\n").utf8) + parts.body))
        }
        head += "transfer-encoding: chunked\r\n\r\n"
        var out = Array(head.utf8)
        if !parts.body.isEmpty {
            let crlf: [UInt8] = [0x0D, 0x0A]
            out += Array(String(parts.body.count, radix: 16).utf8) + crlf + parts.body + crlf
        }
        var tail = "0\r\n"
        for trailer in parts.trailers { tail += "\(trailer.name): \(trailer.value)\r\n" }
        out += Array((tail + "\r\n").utf8)
        return RawResponse(Bytes(out))
    }

    /// A stored response (HTTP/1 or HTTP/2 text) as HTTP/2 parts, for writing frames to an h2 client.
    public static func responseParts(_ response: RawResponse) -> H2ResponseParts {
        let bytes = response.bytes
        let parsed = response.parsed
        var headers: [H2Header] = []
        for field in parsed.headers {
            let name = bytes[field.name].string().lowercased()
            if connectionSpecific.contains(name) { continue }
            headers.append(H2Header(name, bytes[field.value].string()))
        }
        let all = bytes.rawBytes
        if parsed.bodyFraming == .chunked, let walked = walkChunked(all, from: parsed.headerBlockEnd) {
            return H2ResponseParts(
                status: parsed.statusCode, headers: headers, body: walked.body, trailers: walked.trailers)
        }
        let body = bytes[parsed.body].rawBytes
        return H2ResponseParts(status: parsed.statusCode, headers: headers, body: body)
    }

    /// A request in HTTP/2 text form, made sendable over HTTP/1.1: the version token becomes
    /// `HTTP/1.1` and a body without framing gets a `content-length`. Other requests are unchanged.
    public static func http1Request(from request: RawRequest) -> RawRequest {
        guard request.bytes[request.parsed.version].string() == "HTTP/2" else { return request }
        var result = request.replacing(request.parsed.version, with: Bytes("HTTP/1.1"))
        let body = requestBody(result)
        let framed =
            result.headerValue("content-length") != nil || result.headerValue("transfer-encoding") != nil
        if !body.isEmpty, !framed {
            let end = result.parsed.headerBlockEnd
            let crlfTerminated = result.bytes.rawBytes[..<end].suffix(2) == [0x0D, 0x0A]
            let insertAt = end - (crlfTerminated ? 2 : 1)
            result = result.replacing(insertAt..<insertAt, with: Bytes("content-length: \(body.count)\r\n"))
        }
        return result
    }

    /// A stored response as HTTP/1.1 wire bytes for an HTTP/1.1 client. HTTP/1 responses are their
    /// wire bytes; an `HTTP/2` one gets an `HTTP/1.1` status line, and either keeps its chunked
    /// rendering (dropping a `content-length`, which chunked overrides) or gains a `content-length`.
    public static func http1Response(from response: RawResponse) -> [UInt8] {
        let parsed = response.parsed
        guard response.bytes[parsed.version].string() == "HTTP/2" else { return response.wireBytes.rawBytes }
        let bytes = response.bytes
        let chunked = parsed.bodyFraming == .chunked
        var head = "HTTP/1.1 \(parsed.statusCode) \(reasonPhrase(parsed.statusCode))\r\n"
        var hasLength = false
        for field in parsed.headers {
            let name = bytes[field.name].string().lowercased()
            if name == "content-length" {
                if chunked { continue }
                hasLength = true
            }
            head += "\(bytes[field.name].string()): \(bytes[field.value].string())\r\n"
        }
        let body = bytes[parsed.body].rawBytes
        let bodyless = parsed.statusCode == 204 || parsed.statusCode == 304 || response.isHeadResponse
        if !chunked, !hasLength, !bodyless { head += "content-length: \(body.count)\r\n" }
        return Array((head + "\r\n").utf8) + body
    }

    // MARK: helpers

    /// The request body, de-chunked when `Transfer-Encoding: chunked`.
    static func requestBody(_ request: RawRequest) -> [UInt8] {
        let all = request.bytes.rawBytes
        let start = request.parsed.headerBlockEnd
        let chunked = request.hasHeaderToken("transfer-encoding", "chunked")
        if chunked, let walked = walkChunked(all, from: start) { return walked.body }
        return start < all.count ? Array(all[start...]) : []
    }

    /// A complete chunked body's data and trailer fields (via `HTTP1.walkChunked`); nil when the
    /// body is malformed or truncated.
    static func walkChunked(_ a: [UInt8], from start: Int) -> (body: [UInt8], trailers: [H2Header])? {
        var body: [UInt8] = []
        var trailers: [H2Header] = []
        let scan = HTTP1.walkChunked(a, from: start, data: { body += a[$0] }) { line in
            let text = String(decoding: a[line], as: UTF8.self)
            guard let colon = text.firstIndex(of: ":") else { return }
            let value = text[text.index(after: colon)...].trimmingASCIIWhitespace
            trailers.append(H2Header(text[..<colon].lowercased(), value))
        }
        guard case .complete = scan else { return nil }
        return (body, trailers)
    }

    /// A conventional reason phrase (HTTP/2 has none; HTTP/1.1 clients expect one).
    public static func reasonPhrase(_ status: Int) -> String {
        let phrases = [
            100: "Continue", 101: "Switching Protocols", 103: "Early Hints", 200: "OK",
            201: "Created", 202: "Accepted", 204: "No Content", 206: "Partial Content",
            301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
            307: "Temporary Redirect", 308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized",
            403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict",
            413: "Content Too Large", 415: "Unsupported Media Type", 429: "Too Many Requests",
            500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
            503: "Service Unavailable", 504: "Gateway Timeout",
        ]
        return phrases[status] ?? "Status"
    }
}

extension StringProtocol {
    /// Trimmed of spaces and tabs at both ends (no Foundation).
    var trimmingASCIIWhitespace: String {
        var s = self[...]
        while let first = s.first, first == " " || first == "\t" { s = s.dropFirst() }
        while let last = s.last, last == " " || last == "\t" { s = s.dropLast() }
        return String(s)
    }
}
