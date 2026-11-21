// GulpCore — the exchange model (doc 04 §2): targets, exchanges and their supporting value types.

import Foundation

// MARK: - Identifiers

/// Row id of an exchange in the project store.
public typealias ExchangeID = Int64

// MARK: - Target

/// Where a request is sent. HTTP-version preference is per-send (`SendOptions`), not per-target.
public struct HTTPTarget: Sendable, Hashable, Codable {
    /// `.http` or `.https`.
    public var scheme: Scheme
    /// Host as used for `Host`/SNI by default.
    public var host: String
    /// TCP port.
    public var port: Int
    /// SNI to present instead of `host` (TLS only).
    public var sniOverride: String?
    /// Connect to this IP instead of resolving `host` (HTTP-004).
    public var ipOverride: String?

    /// Create a target; `port` defaults to the scheme's well-known port.
    public init(
        scheme: Scheme, host: String, port: Int? = nil, sniOverride: String? = nil,
        ipOverride: String? = nil
    ) {
        self.scheme = scheme
        self.host = host
        self.port = port ?? (scheme == .https ? 443 : 80)
        self.sniOverride = sniOverride
        self.ipOverride = ipOverride
    }

    /// Parse `http://host[:port]` / `https://host[:port]` (any path is ignored); nil if malformed.
    public init?(url: String) {
        let scheme: Scheme
        var rest: Substring
        if url.lowercased().hasPrefix("http://") {
            scheme = .http
            rest = url.dropFirst(7)
        } else if url.lowercased().hasPrefix("https://") {
            scheme = .https
            rest = url.dropFirst(8)
        } else {
            return nil
        }
        if let slash = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) {
            rest = rest[..<slash]
        }
        if rest.isEmpty { return nil }
        var host = String(rest)
        var port: Int?
        if rest.hasPrefix("[") {
            // IPv6 literal: [::1]:8080
            guard let close = rest.firstIndex(of: "]") else { return nil }
            host = String(rest[rest.index(after: rest.startIndex)..<close])
            let after = rest[rest.index(after: close)...]
            if after.hasPrefix(":") {
                guard let p = Int(after.dropFirst()) else { return nil }
                port = p
            }
        } else if let colon = rest.lastIndex(of: ":") {
            guard let p = Int(rest[rest.index(after: colon)...]) else { return nil }
            host = String(rest[..<colon])
            port = p
        }
        if host.isEmpty { return nil }
        if let p = port, !(1...65535).contains(p) { return nil }
        self.init(scheme: scheme, host: host, port: port)
    }
}

extension HTTPTarget {
    /// The `Host` header value: the host, plus `:port` unless it is the scheme's default port.
    public var hostHeader: String {
        port == (scheme == .https ? 443 : 80) ? host : "\(host):\(port)"
    }
}

// MARK: - Supporting value types

/// Lifecycle of an exchange (`Exchange.state`). Network failures are data, not exceptions.
public enum ExchangeState: Sendable, Equatable {
    case pending, complete, dropped, intercepted
    case failed(GulpNetworkError)
}

/// Color tag for an exchange (`Annotation.highlight`, `exchanges.highlight`).
public enum Highlight: String, Sendable, Codable, CaseIterable {
    case red, orange, yellow, green, cyan, blue, purple, pink, gray
}

/// Per-phase timing of an exchange in milliseconds (HTTP-010). Phases that did not happen are nil
/// (for example `connectMs`/`tlsMs` on a reused connection).
public struct Timing: Sendable, Codable, Equatable {
    /// Wall-clock start of the send.
    public var start: Date
    /// DNS resolution time.
    public var dnsMs: Double?
    /// TCP connect time.
    public var connectMs: Double?
    /// TLS handshake time.
    public var tlsMs: Double?
    /// Time to write the request bytes.
    public var requestWriteMs: Double?
    /// Time from the end of the write to the first response byte.
    public var ttfbMs: Double?
    /// Time from the first to the last response byte.
    public var downloadMs: Double?
    /// End-to-end time.
    public var totalMs: Double?
    /// For a streamed response (HIS-007): when each piece arrived — cumulative bytes received and
    /// milliseconds since the send started.
    public var streamMarks: [StreamMark]?
    /// For a single-packet group send (HTTP-035): when this request's withheld final bytes were
    /// written, in ms after the first of its group's final writes (the group's spread is the max).
    public var finalWriteOffsetMs: Double?

    /// Create a timing record that starts at `start`.
    public init(start: Date = Date()) {
        self.start = start
    }
}

/// One piece of a streamed response (HIS-007 chunk timeline and SSE event times).
public struct StreamMark: Sendable, Codable, Equatable {
    /// Bytes received so far, this piece included.
    public var offset: Int
    /// Milliseconds since the send started.
    public var ms: Double

    /// A mark.
    public init(offset: Int, ms: Double) {
        self.offset = offset
        self.ms = ms
    }
}

/// Outcome of upstream TLS certificate validation.
public enum TLSValidation: Sendable, Codable, Equatable { case ok, notChecked, failed(String) }

/// Negotiated TLS parameters of an exchange's connection (`Exchange.tls`).
public struct TLSInfo: Sendable, Codable, Equatable {
    /// Protocol version, e.g. `TLSv1.3`.
    public var version: String
    /// Negotiated cipher suite name.
    public var cipherSuite: String
    /// ALPN protocol (`h2` / `http/1.1`), if negotiated.
    public var alpn: String?
    /// SHA-256 fingerprints of the server chain, leaf first.
    public var serverChainSHA256: [String]
    /// Validation outcome.
    public var validation: TLSValidation

    /// Create a TLS info record.
    public init(
        version: String, cipherSuite: String, alpn: String? = nil, serverChainSHA256: [String] = [],
        validation: TLSValidation = .notChecked
    ) {
        self.version = version
        self.cipherSuite = cipherSuite
        self.alpn = alpn
        self.serverChainSHA256 = serverChainSHA256
        self.validation = validation
    }
}

/// The original messages of an exchange that intercept or match & replace modified.
public struct EditInfo: Sendable {
    /// The request before modification, if it was modified.
    public var originalRequest: RawRequest?
    /// The response before modification, if it was modified.
    public var originalResponse: RawResponse?
    /// Who changed it.
    public var editedBy: ToolSource

    /// Create an edit record.
    public init(
        originalRequest: RawRequest? = nil, originalResponse: RawResponse? = nil, editedBy: ToolSource
    ) {
        self.originalRequest = originalRequest
        self.originalResponse = originalResponse
        self.editedBy = editedBy
    }
}

/// User annotations on an exchange.
public struct Annotation: Sendable, Codable, Equatable {
    /// Free-text comment.
    public var comment: String?
    /// Color tag.
    public var highlight: Highlight?
    /// Tags.
    public var tags: [String]

    /// Create an annotation (empty by default).
    public init(comment: String? = nil, highlight: Highlight? = nil, tags: [String] = []) {
        self.comment = comment
        self.highlight = highlight
        self.tags = tags
    }
}

// MARK: - Tool source

/// Which tool produced an exchange. Encodes to a stable string (`exchanges.source`): the simple
/// cases are their names; `.extension(id)` encodes as `extension:<id>`.
public enum ToolSource: Sendable, Hashable {
    case proxy, repeater, fuzzer, scanner, crawler, sequencer, session, browser, automation, ai
    case `extension`(id: String)

    /// The stable TEXT encoding.
    public var rawValue: String {
        switch self {
        case .proxy: "proxy"
        case .repeater: "repeater"
        case .fuzzer: "fuzzer"
        case .scanner: "scanner"
        case .crawler: "crawler"
        case .sequencer: "sequencer"
        case .session: "session"
        case .browser: "browser"
        case .automation: "automation"
        case .ai: "ai"
        case .`extension`(let id): "extension:\(id)"
        }
    }

    /// Decode the stable TEXT encoding; nil for unknown values.
    public init?(rawValue: String) {
        switch rawValue {
        case "proxy": self = .proxy
        case "repeater": self = .repeater
        case "fuzzer": self = .fuzzer
        case "scanner": self = .scanner
        case "crawler": self = .crawler
        case "sequencer": self = .sequencer
        case "session": self = .session
        case "browser": self = .browser
        case "automation": self = .automation
        case "ai": self = .ai
        default:
            let prefix = "extension:"
            guard rawValue.hasPrefix(prefix), rawValue.count > prefix.count else { return nil }
            self = .`extension`(id: String(rawValue.dropFirst(prefix.count)))
        }
    }
}

extension ToolSource: Codable {
    /// Decode from the stable TEXT encoding.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        guard let value = ToolSource(rawValue: raw) else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "Unknown ToolSource '\(raw)'")
        }
        self = value
    }

    /// Encode as the stable TEXT encoding.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

// MARK: - Derived fields

/// Denormalized, rebuildable columns derived from an exchange (mirrored into `exchanges`, doc 04 §4).
public struct DerivedFields: Sendable, Codable, Equatable {
    /// Target host.
    public var host: String
    /// Target port.
    public var port: Int
    /// Target scheme.
    public var scheme: Scheme
    /// Request method.
    public var method: String?
    /// Request path (without the query).
    public var path: String?
    /// Raw query string (without `?`).
    public var query: String?
    /// File extension of the path's last segment, lowercased.
    public var ext: String?
    /// Response status code.
    public var status: Int?
    /// Response body length in bytes as framed on the wire: every byte after the header block, so a
    /// chunked body counts its chunk-size lines and trailers (not the de-chunked payload).
    public var responseLength: Int?
    /// Response MIME type (`Content-Type` without parameters), lowercased.
    public var mime: String?
    /// HTML `<title>` of the response, if any.
    public var title: String?
    /// Number of query parameters.
    public var paramCount: Int
    /// The request carried a `Cookie` header.
    public var hasCookies: Bool
    /// The response set at least one cookie.
    public var setsCookies: Bool

    /// Derive the fields for an exchange of `request`/`response` sent to `target`.
    public init(target: HTTPTarget, request: RawRequest, response: RawResponse?) {
        host = target.host
        port = target.port
        scheme = target.scheme
        let p = request.parsed
        let m = request.bytes[p.method].string()
        method = m.isEmpty ? nil : m
        var requestTarget = request.bytes[p.target].string()
        // Absolute-form (`http://host/path`): keep only the path part. Only a target that *starts*
        // with a scheme is absolute — `/fetch?url=http://x/` is origin-form with a URL in its query.
        if !requestTarget.hasPrefix("/"), let schemeEnd = requestTarget.range(of: "://"),
            requestTarget[..<schemeEnd.lowerBound].allSatisfy({
                $0.isLetter || $0.isNumber || "+-.".contains($0)
            })
        {
            let afterAuthority = requestTarget[schemeEnd.upperBound...]
            requestTarget = afterAuthority.firstIndex(of: "/").map { String(afterAuthority[$0...]) } ?? "/"
        }
        if let q = requestTarget.firstIndex(of: "?") {
            path = String(requestTarget[..<q])
            query = String(requestTarget[requestTarget.index(after: q)...])
        } else {
            path = requestTarget.isEmpty ? nil : requestTarget
            query = nil
        }
        if let lastSegment = path?.split(separator: "/").last, let dot = lastSegment.lastIndex(of: ".") {
            let e = lastSegment[lastSegment.index(after: dot)...].lowercased()
            ext = e.isEmpty ? nil : e
        } else {
            ext = nil
        }
        paramCount = query.map { $0.split(separator: "&").filter { !$0.isEmpty }.count } ?? 0
        hasCookies = request.headerValue("cookie") != nil
        if let r = response {
            status = r.parsed.statusCode
            responseLength = r.parsed.body.count
            mime = r.headerValue("content-type").map {
                String($0.string().split(separator: ";").first ?? "").trimmedASCII().lowercased()
            }
            setsCookies = HTTP1.headerValues("set-cookie", r.parsed.headers, r.bytes.rawBytes).count > 0
            title = (mime?.contains("html") ?? false) ? Self.htmlTitle(r.bytes[r.parsed.body]) : nil
        } else {
            status = nil
            responseLength = nil
            mime = nil
            setsCookies = false
            title = nil
        }
    }

    /// The text of the first `<title>` element in the first 64 KB of `body`, trimmed.
    static func htmlTitle(_ body: Bytes) -> String? {
        let text = body[0..<min(body.count, 65_536)].string()
        guard let open = text.range(of: "<title", options: .caseInsensitive) else { return nil }
        guard let openEnd = text[open.upperBound...].firstIndex(of: ">") else { return nil }
        let rest = text[text.index(after: openEnd)...]
        guard let close = rest.range(of: "</title", options: .caseInsensitive) else { return nil }
        let t = rest[..<close.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? nil : t
    }
}

// MARK: - Exchange

/// One request/response pair with its metadata (doc 04 §2).
public struct Exchange: Sendable, Identifiable {
    /// Row id (0 until the store assigns one).
    public var id: ExchangeID
    /// Which tool produced it.
    public var source: ToolSource
    /// Where it was sent.
    public var target: HTTPTarget
    /// Protocol version used on the wire.
    public var httpVersion: HTTPVersion
    /// The exact request bytes sent.
    public var request: RawRequest
    /// The exact response bytes received; nil while pending or on failure before any byte.
    public var response: RawResponse?
    /// Lifecycle state.
    public var state: ExchangeState
    /// Per-phase timing (HTTP-010).
    public var timing: Timing
    /// Client address, for proxy traffic.
    public var clientAddress: String?
    /// Groups exchanges sent on the same connection.
    public var connectionID: UInt64
    /// Negotiated TLS parameters, if TLS was used.
    public var tls: TLSInfo?
    /// Originals, if intercept or match & replace modified the messages.
    public var edited: EditInfo?
    /// User annotation.
    public var annotation: Annotation
    /// Derived, rebuildable columns.
    public var derived: DerivedFields

    /// Create an exchange; `derived` is computed from the target and messages.
    public init(
        id: ExchangeID = 0, source: ToolSource, target: HTTPTarget, httpVersion: HTTPVersion = .http1_1,
        request: RawRequest, response: RawResponse? = nil, state: ExchangeState = .pending,
        timing: Timing = Timing(), clientAddress: String? = nil, connectionID: UInt64 = 0,
        tls: TLSInfo? = nil, edited: EditInfo? = nil, annotation: Annotation = Annotation()
    ) {
        self.id = id
        self.source = source
        self.target = target
        self.httpVersion = httpVersion
        self.request = request
        self.response = response
        self.state = state
        self.timing = timing
        self.clientAddress = clientAddress
        self.connectionID = connectionID
        self.tls = tls
        self.edited = edited
        self.annotation = annotation
        self.derived = DerivedFields(target: target, request: request, response: response)
    }
}
