// GulpProxy — raw request framing and the forward-proxy rewrites (F01 §4.1, PRX-002). Requests are
// framed with GulpCore's raw-preserving parser (never NIO's normalizing HTTP decoder); the only bytes
// changed on forward are the request-target (absolute-form → origin-form) and the proxy hop-by-hop
// headers.

import GulpCore

/// The outcome of framing the next request off a client connection.
enum Framed: Equatable {
    /// More bytes are needed.
    case incomplete
    /// A complete request and the number of buffered bytes it used.
    case request(RawRequest, length: Int)
    /// The input cannot be framed safely; answer `status` and close the connection.
    case reject(status: Int, message: String)
}

/// Framing of client requests from a connection's byte stream (F01 §4.1 framing-ambiguity policy).
enum RequestFramer {
    /// A header block larger than this is refused (431) instead of buffered forever.
    static let maxHeaderBytes = 1_024 * 1_024
    /// A request body larger than this is refused (413). Bodies are buffered until streaming
    /// request bodies land (see docs/07-decisions.md).
    static let maxBodyBytes = 256 * 1_024 * 1_024

    /// Frame the first request in `bytes`.
    ///
    /// Policy: `Transfer-Encoding` ending in `chunked` wins over `Content-Length` for *our* delimiting
    /// (the parser records `conflictingFraming`, so the exchange shows it); any other
    /// `Transfer-Encoding` is refused (RFC 9112 §6.3 item 4). `Content-Length` values must be plain
    /// decimal and agree with each other. Malformed chunking is refused, because guessing where the
    /// body ends is how a proxy gets desynchronised from the server behind it.
    static func next(_ bytes: [UInt8], maxBody: Int = maxBodyBytes) -> Framed {
        let (end, terminator) = HTTP1.headerBlockEnd(bytes)
        guard terminator != 0 else {
            return bytes.count > maxHeaderBytes
                ? .reject(status: 431, message: "Request header block too large") : .incomplete
        }
        let head = RawRequest(Bytes(Array(bytes[..<end])))
        let fields = head.parsed.headers
        func values(_ name: String) -> [String] {
            fields.filter { head.bytes[$0.name].string().lowercased() == name }
                .map { head.bytes[$0.value].string() }
        }
        let codings = values("transfer-encoding").flatMap { $0.split(separator: ",") }
            .map { String($0).trimmedOf(" \t").lowercased() }
        var bodyLength = 0
        if !codings.isEmpty {
            guard codings.last == "chunked" else {
                return .reject(status: 400, message: "Transfer-Encoding must end in chunked")
            }
            switch HTTP1.scanChunked(bytes, from: end) {
            case .complete(let bodyEnd):
                bodyLength = bodyEnd - end
            case .needMore:
                return bytes.count - end > maxBody ? tooLarge : .incomplete
            case .malformed:
                return .reject(status: 400, message: "Malformed chunked request body")
            }
        } else {
            let lengths = values("content-length").flatMap { $0.split(separator: ",") }
                .map { String($0).trimmedOf(" \t") }
            if let first = lengths.first {
                guard lengths.allSatisfy({ $0 == first }), let declared = decimal(first) else {
                    return .reject(status: 400, message: "Invalid or conflicting Content-Length")
                }
                bodyLength = declared
            }
        }
        guard bodyLength <= maxBody else { return tooLarge }
        let (total, overflow) = end.addingReportingOverflow(bodyLength)
        guard !overflow else { return tooLarge }
        guard bytes.count >= total else { return .incomplete }
        return .request(RawRequest(Bytes(Array(bytes[..<total]))), length: total)
    }

    private static var tooLarge: Framed {
        .reject(status: 413, message: "Request body larger than \(maxBodyBytes / 1_048_576) MB")
    }

    /// A non-negative decimal of at most 18 digits (so it always fits in an `Int`).
    static func decimal(_ text: String) -> Int? {
        guard !text.isEmpty, text.utf8.count <= 18, text.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 })
        else { return nil }
        return Int(text)
    }

    /// True when the buffered (incomplete) request asks for `100 Continue` before sending its body.
    static func awaitsContinue(_ bytes: [UInt8]) -> Bool {
        let (end, terminator) = HTTP1.headerBlockEnd(bytes)
        guard terminator != 0 else { return false }
        return RawRequest(Bytes(Array(bytes[..<end]))).hasHeaderToken("expect", "100-continue")
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
        // The path starts at the first '/' (0x2F) or, for "http://host?q", at '?' (0x3F).
        if let start = raw[afterAuthority...].firstIndex(where: { $0 == 0x2F || $0 == 0x3F }) {
            origin = raw[start] == 0x2F ? Array(raw[start...]) : origin + raw[start...]
        }
        return (request.replacing(targetRange, with: Bytes(origin)), target)
    }

    /// Remove the proxy-management hop-by-hop headers — `Proxy-Connection`, `Proxy-Authorization`
    /// and any header named in `Connection` — with their line endings (F01 §4.1). Every other byte,
    /// including the `Connection` header itself, is kept.
    static let protected: Set<String> = [
        "close", "keep-alive", "content-length", "transfer-encoding", "host", "connection",
    ]

    /// With `keepingUpgrade`, `Upgrade` survives being named in `Connection` (PRX-030: the upgrade
    /// is what the request is for).
    static func strippingHopByHop(_ request: RawRequest, keepingUpgrade: Bool = false) -> RawRequest {
        let protected = keepingUpgrade ? Self.protected.union(["upgrade"]) : Self.protected
        var names: Set<String> = ["proxy-connection", "proxy-authorization"]
        let fields = request.parsed.headers
        for field in fields where request.bytes[field.name].string().lowercased() == "connection" {
            for token in request.bytes[field.value].string().split(separator: ",") {
                let name = String(token).trimmedOf(" \t").lowercased()
                // Never strip the headers that frame or route the message, whatever `Connection` says.
                if !name.isEmpty, !protected.contains(name) { names.insert(name) }
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
