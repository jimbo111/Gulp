// GulpHTTP — the only byte rewrites the engine performs, each strictly opt-in via `SendOptions`
// (CLAUDE.md §4: send exactly the bytes the user wrote unless a documented option says otherwise).

import GulpCore

extension RawRequest {
    /// The body length as framed: every byte after the header block.
    var bodyCount: Int { bytes.count - parsed.headerBlockEnd }

    /// HTTP-008: set every `Content-Length` value to the actual body length; if there is none, the
    /// method normally carries a body (POST, PUT, PATCH) and no `Transfer-Encoding` frames it (a
    /// message must not carry both, RFC 9112 §6.2), add one before the blank line using the
    /// message's own line ending. Everything else is left byte-for-byte untouched.
    public func updatingContentLength() -> RawRequest {
        let length = Bytes(String(bodyCount))
        let fields = parsed.headers.filter { bytes[$0.name].string().lowercased() == "content-length" }
        if !fields.isEmpty {
            var result = self
            for field in fields.reversed() {  // back to front, so earlier ranges stay valid
                result = result.replacing(field.value, with: length)
            }
            return result
        }
        guard ["POST", "PUT", "PATCH"].contains(bytes[parsed.method].string()),
            headerValue("transfer-encoding") == nil
        else { return self }
        let (end, terminator) = HTTP1.headerBlockEnd(bytes.rawBytes)
        guard terminator != 0 else { return self }  // no header block end to insert before
        let lineEnding = terminator == 4 ? "\r\n" : "\n"
        let insertAt = end - (terminator == 4 ? 2 : 1)
        return replacing(insertAt..<insertAt, with: Bytes("Content-Length: \(bodyCount)\(lineEnding)"))
    }

    /// Rewrite the header block's line endings (bare LF or mixed) to CRLF; the body is untouched.
    public func normalizingLineEndings() -> RawRequest {
        let a = bytes.rawBytes
        let (end, terminator) = HTTP1.headerBlockEnd(a)
        guard terminator != 0 else { return self }
        let regionEnd = end - (terminator == 4 ? 2 : 1)
        var out: [UInt8] = []
        out.reserveCapacity(a.count + 64)
        var lineStart = 0
        for i in 0..<regionEnd where a[i] == 0x0A {
            var lineEnd = i
            if lineEnd > lineStart, a[lineEnd - 1] == 0x0D { lineEnd -= 1 }
            out += a[lineStart..<lineEnd]
            out += [0x0D, 0x0A]
            lineStart = i + 1
        }
        out += [0x0D, 0x0A]
        out += a[end...]
        return RawRequest(Bytes(out))
    }

    /// Insert a header line before the blank line, using the message's own line ending. Unchanged if
    /// the header block has no end.
    public func insertingHeader(_ line: String) -> RawRequest {
        let (end, terminator) = HTTP1.headerBlockEnd(bytes.rawBytes)
        guard terminator != 0 else { return self }
        let lineEnding = terminator == 4 ? "\r\n" : "\n"
        let insertAt = end - (terminator == 4 ? 2 : 1)
        return replacing(insertAt..<insertAt, with: Bytes("\(line)\(lineEnding)"))
    }

    /// HTTP-006 classic proxying of a plain-HTTP request: rewrite an origin-form request-target to
    /// absolute-form (`http://host:port/path`) and add `Proxy-Authorization` when given. Used only
    /// when a plain HTTP proxy is configured without tunnelling.
    func forPlainHTTPProxy(target: HTTPTarget, proxyAuthorization: String?) -> RawRequest {
        var result = self
        let requestTarget = bytes[parsed.target].string()
        if requestTarget.hasPrefix("/") {
            let host = target.host.contains(":") ? "[\(target.host)]" : target.host
            let authority = target.port == 80 ? host : "\(host):\(target.port)"
            result = replacing(parsed.target, with: Bytes("http://\(authority)\(requestTarget)"))
        }
        if let proxyAuthorization {
            result = result.insertingHeader("Proxy-Authorization: \(proxyAuthorization)")
        }
        return result
    }
}
