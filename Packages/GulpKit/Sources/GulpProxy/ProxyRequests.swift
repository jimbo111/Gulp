// GulpProxy — raw request framing and the forward-proxy rewrites (F01 §4.1, PRX-002). Requests are
// framed with GulpCore's raw-preserving parser (never NIO's normalizing HTTP decoder); the only bytes
// changed on forward are the request-target (absolute-form → origin-form) and the proxy hop-by-hop
// headers.

import GulpCore

/// Framing of client requests from a connection's byte stream.
enum RequestFramer {
    /// A header block larger than this is refused (431) instead of buffered forever.
    static let maxHeaderBytes = 1_024 * 1_024

    /// The first complete request in `bytes` and how many bytes it used, or nil if more are needed.
    /// Body length (F01 §4.1 framing policy): chunked wins over Content-Length (the conflict stays
    /// visible in the parsed warnings); otherwise Content-Length; otherwise no body. Malformed
    /// chunking ends the request at the header block, so the bytes still reach the upstream.
    static func next(_ bytes: [UInt8]) -> (request: RawRequest, length: Int)? {
        let (end, terminator) = HTTP1.headerBlockEnd(bytes)
        guard terminator != 0 else { return nil }
        let head = RawRequest(Bytes(Array(bytes[..<end])))
        var length = end
        if head.hasHeaderToken("transfer-encoding", "chunked") {
            switch HTTP1.scanChunked(bytes, from: end) {
            case .complete(let bodyEnd): length = bodyEnd
            case .needMore: return nil
            case .malformed: length = end
            }
        } else if let declared = head.headerValue("content-length").flatMap({ Int($0.string()) }),
            declared > 0
        {
            guard bytes.count >= end + declared else { return nil }
            length = end + declared
        }
        return (RawRequest(Bytes(Array(bytes[..<length]))), length)
    }

    /// True when the buffered (incomplete) request asks for `100 Continue` before sending its body.
    static func awaitsContinue(_ bytes: [UInt8]) -> Bool {
        let (end, terminator) = HTTP1.headerBlockEnd(bytes)
        guard terminator != 0 else { return false }
        return RawRequest(Bytes(Array(bytes[..<end]))).hasHeaderToken("expect", "100-continue")
    }

    /// True when a header block is still incomplete and already too large.
    static func headerTooLarge(_ bytes: [UInt8]) -> Bool {
        bytes.count > maxHeaderBytes && HTTP1.headerBlockEnd(bytes).terminator == 0
    }
}

/// The forward-proxy rewrites (PRX-002).
enum ForwardRewrite {
    /// For an absolute-form request (`GET http://host:port/path HTTP/1.1`), the target it names and
    /// the request with only its request-target rewritten to origin-form (`/path`). Nil for
    /// origin-form, authority-form (CONNECT) or unparsable targets.
    static func originForm(_ request: RawRequest) -> (request: RawRequest, target: HTTPTarget)? {
        let targetRange = request.parsed.target
        let raw = request.bytes[targetRange].rawBytes
        guard let target = HTTPTarget(url: Bytes(raw).string()) else { return nil }
        guard let separator = firstIndex(of: Array("://".utf8), in: raw) else { return nil }
        let afterAuthority = separator + 3
        var origin: [UInt8] = Array("/".utf8)
        if let start = raw[afterAuthority...].firstIndex(where: { $0 == 0x2F || $0 == 0x3F }) {  // '/' or '?'
            origin = raw[start] == 0x2F ? Array(raw[start...]) : origin + raw[start...]
        }
        return (request.replacing(targetRange, with: Bytes(origin)), target)
    }

    /// Remove the proxy-management hop-by-hop headers — `Proxy-Connection`, `Proxy-Authorization`
    /// and any header named in `Connection` — with their line endings (F01 §4.1). Every other byte,
    /// including the `Connection` header itself, is kept.
    static func strippingHopByHop(_ request: RawRequest) -> RawRequest {
        var names: Set<String> = ["proxy-connection", "proxy-authorization"]
        let fields = request.parsed.headers
        for field in fields where request.bytes[field.name].string().lowercased() == "connection" {
            for token in request.bytes[field.value].string().split(separator: ",") {
                let name = token.trimmedOf(" \t").lowercased()
                if !name.isEmpty, name != "close", name != "keep-alive" { names.insert(name) }
            }
        }
        var result = request
        for field in fields.reversed() where names.contains(request.bytes[field.name].string().lowercased()) {
            var end = field.line.upperBound
            let bytes = result.bytes
            if end < bytes.count, bytes[end] == 0x0D { end += 1 }
            if end < bytes.count, bytes[end] == 0x0A { end += 1 }
            result = result.replacing(field.line.lowerBound..<end, with: Bytes())
        }
        return result
    }

    static func firstIndex(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard needle.count <= haystack.count else { return nil }
        for i in 0...(haystack.count - needle.count) where Array(haystack[i..<(i + needle.count)]) == needle {
            return i
        }
        return nil
    }
}

extension String {
    /// Trim the given ASCII characters from both ends (no Foundation).
    func trimmedOf(_ set: String) -> String {
        var s = self[...]
        while let f = s.first, set.contains(f) { s = s.dropFirst() }
        while let l = s.last, set.contains(l) { s = s.dropLast() }
        return String(s)
    }
}
