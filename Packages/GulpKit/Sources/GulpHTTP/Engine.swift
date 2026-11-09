// GulpHTTP — the engine's public API (F03 §2, §4). Every tool sends through one `HTTPEngine`, which
// writes exactly the bytes it is given (HTTP-001).

import GulpCore
import GulpTLS

// MARK: - Options

/// Which protocol to speak.
public enum HTTPVersionPreference: Sendable, Hashable {
    /// Negotiate via ALPN (HTTP/1.1 for plaintext).
    case auto
    /// Always HTTP/1.1.
    case http1_1
    /// HTTP/2 via ALPN (M3).
    case http2
    /// Cleartext HTTP/2 with prior knowledge, h2c (M3).
    case http2PriorKnowledge
}

/// How a send uses pooled connections (HTTP-003).
public enum ConnectionPolicy: Sendable, Hashable {
    /// Take an idle pooled connection if one is open; return it afterwards if still reusable.
    case reuse
    /// Open a fresh connection, then pool it if reusable.
    case new
    /// Open a fresh connection and close it after the response.
    case newAndClose
}

/// Whether and where to follow redirects.
public struct RedirectPolicy: Sendable, Hashable {
    /// Which redirects to follow.
    public enum Mode: Sendable, Hashable { case never, onSite, inScope, always }
    /// Which redirects to follow.
    public var mode: Mode
    /// Maximum hops.
    public var maxHops: Int
    /// Apply `Set-Cookie` from each hop to the next request.
    public var processCookies: Bool

    /// Never follow redirects (the default; other modes arrive with the Repeater in M5).
    public static let never = RedirectPolicy(mode: .never)

    /// Create a policy.
    public init(mode: Mode, maxHops: Int = 10, processCookies: Bool = false) {
        self.mode = mode
        self.maxHops = maxHops
        self.processCookies = processCookies
    }
}

/// Every timeout phase of HTTP-005. Each expiry is recorded as a typed `GulpNetworkError`.
public struct Timeouts: Sendable, Hashable {
    /// TCP connect.
    public var connect: Duration = .seconds(10)
    /// TLS handshake.
    public var tlsHandshake: Duration = .seconds(10)
    /// From the end of the request write to the first response byte.
    public var firstByte: Duration = .seconds(30)
    /// Longest silence between response bytes.
    public var idleBetweenBytes: Duration = .seconds(30)
    /// End to end.
    public var total: Duration = .seconds(120)

    /// Default timeouts.
    public init() {}
}

/// An upstream proxy (HTTP-006).
public struct UpstreamProxy: Sendable, Hashable {
    /// Proxy protocol.
    public enum Kind: Sendable, Hashable { case http, socks5 }
    /// Proxy protocol.
    public var kind: Kind
    /// Proxy host.
    public var host: String
    /// Proxy port.
    public var port: Int
    /// Optional credentials (Basic for HTTP, username/password for SOCKS5).
    public var username: String?
    /// Optional credentials.
    public var password: String?
    /// HTTP proxies only: reach plain-HTTP targets through a CONNECT tunnel, so the request bytes stay
    /// exactly as written. Off (the default) uses classic proxying, which must rewrite the request
    /// line to absolute-form. HTTPS targets always tunnel.
    public var tunnelPlainHTTP: Bool

    /// Create a proxy definition.
    public init(
        kind: Kind, host: String, port: Int, username: String? = nil, password: String? = nil,
        tunnelPlainHTTP: Bool = false
    ) {
        self.kind = kind
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.tunnelPlainHTTP = tunnelPlainHTTP
    }
}

/// One upstream-proxy rule (PRX-041): hosts matching `hostPattern` use `proxy` (nil = direct).
/// Rules are ordered; the first match wins.
public struct UpstreamRule: Sendable, Hashable {
    /// A case-insensitive host glob where `*` matches any run of characters, e.g. `*.example.com`.
    public var hostPattern: String
    /// The proxy to use, or nil to connect directly.
    public var proxy: UpstreamProxy?

    /// Create a rule.
    public init(hostPattern: String, proxy: UpstreamProxy?) {
        self.hostPattern = hostPattern
        self.proxy = proxy
    }

    /// Whether `host` matches the pattern.
    public func matches(_ host: String) -> Bool {
        Self.glob(Array(hostPattern.lowercased()), Array(host.lowercased()))
    }

    static func glob(_ pattern: [Character], _ text: [Character]) -> Bool {
        var p = 0
        var t = 0
        var star = -1
        var mark = 0
        while t < text.count {
            if p < pattern.count, pattern[p] == "*" {
                star = p
                mark = t
                p += 1
            } else if p < pattern.count, pattern[p] == text[t] {
                p += 1
                t += 1
            } else if star >= 0 {
                p = star + 1
                mark += 1
                t = mark
            } else {
                return false
            }
        }
        while p < pattern.count, pattern[p] == "*" { p += 1 }
        return p == pattern.count
    }
}

/// Per-send override of the upstream-proxy rules (PRX-041).
public enum UpstreamProxyOverride: Sendable, Hashable {
    /// Apply the configured rules (direct when there are none).
    case useRules
    /// Connect directly.
    case direct
    /// Use this proxy.
    case proxy(UpstreamProxy)
}

/// Which request/response hooks run for a send.
public struct HookSet: OptionSet, Sendable, Hashable {
    /// The raw option bits.
    public let rawValue: Int
    /// Create from raw bits.
    public init(rawValue: Int) { self.rawValue = rawValue }

    /// Session-handling rules (F15).
    public static let sessions = HookSet(rawValue: 1 << 0)
    /// Transform tags (F12).
    public static let transformTags = HookSet(rawValue: 1 << 1)
    /// Match and replace.
    public static let matchReplace = HookSet(rawValue: 1 << 2)
    /// Extensions (F18).
    public static let extensions = HookSet(rawValue: 1 << 3)
    /// Every hook.
    public static let all: HookSet = [.sessions, .transformTags, .matchReplace, .extensions]
}

/// Options for one send (F03 §2).
public struct SendOptions: Sendable {
    /// Protocol preference.
    public var httpVersion: HTTPVersionPreference = .auto
    /// Connection reuse policy.
    public var connection: ConnectionPolicy = .reuse
    /// Redirect policy.
    public var followRedirects: RedirectPolicy = .never
    /// Single-packet group sends (HTTP-033/034): how long to wait between sending everything but
    /// the final bytes and releasing the final bytes together.
    public var singlePacketWarmUp: Duration = .milliseconds(100)
    /// Recompute `Content-Length` from the body (HTTP-008). Never touched when false.
    public var updateContentLength = false
    /// Rewrite header-block line endings to CRLF before sending.
    public var normalizeLineEndings = false
    /// Per-phase timeouts (HTTP-005).
    public var timeouts = Timeouts()
    /// Responses larger than this fail with `.tooLarge` and close the connection.
    public var maxResponseBytes = 50 * 1024 * 1024
    /// Decompress bodies for hooks and views (HTTP-007); the raw response stays as received.
    public var decompressForHooks = true
    /// Upstream TLS: versions, ciphers, ALPN, whether to enforce certificate validation (TLS-008/009).
    public var tls = UpstreamTLSSettings()
    /// Upstream proxy override (HTTP-006).
    public var upstreamProxy: UpstreamProxyOverride = .useRules
    /// Which hooks run.
    public var applyHooks: HookSet = .all
    /// The tool the exchange is recorded as.
    public var recordAs: ToolSource
    /// The client the request came from (proxy traffic, PRX-004); recorded with the exchange.
    public var clientAddress: String?
    /// The request before someone edited it (intercept, PRX-012); recorded as the original.
    public var originalRequest: RawRequest?
    /// Streaming (F01 PRX-050): HTTP/1 response bytes are handed here as they arrive (interim
    /// responses and headers included), there is no total-time cap (the idle timeout still
    /// applies), and the exchange is recorded as pending when bytes start and updated at the end.
    public var onResponseBytes: (@Sendable ([UInt8]) -> Void)?

    /// Options with defaults, recorded as `recordAs`.
    public init(recordAs: ToolSource) {
        self.recordAs = recordAs
    }
}

// MARK: - Results

/// The outcome of a send: the final exchange (failures are data, in `exchange.state`).
public struct ExchangeResult: Sendable {
    /// The final record.
    public var exchange: Exchange
    /// Hops followed before the final exchange (empty unless redirects were followed).
    public var redirectChain: [Exchange]
    /// Nil on success; mirrors `exchange.state` on failure.
    public var error: GulpNetworkError?

    /// Create a result.
    public init(exchange: Exchange, redirectChain: [Exchange] = [], error: GulpNetworkError? = nil) {
        self.exchange = exchange
        self.redirectChain = redirectChain
        self.error = error
    }
}

/// One request of a group send (F03 §3.3).
public struct GroupItem: Sendable {
    /// The request.
    public var request: RawRequest
    /// Where to send it.
    public var target: HTTPTarget

    /// Create a group item.
    public init(request: RawRequest, target: HTTPTarget) {
        self.request = request
        self.target = target
    }
}

/// How a group of requests is sent (HTTP-030…HTTP-034).
public enum GroupSendMode: Sendable {
    case sequentialSingleConnection, sequentialSeparateConnections, parallel, singlePacket
}

/// A live WebSocket (F01 §2.4 / F26). Declared in M1; implemented in M4. (Its synthesized
/// initializer is internal, so only the engine can create one.)
public struct WebSocketSession: Sendable {}

// MARK: - Hooks and recording

/// A request about to be written, as seen by hooks.
public struct OutgoingRequest: Sendable {
    /// The bytes that will be written.
    public var request: RawRequest
    /// Where they will be written.
    public var target: HTTPTarget

    /// Create an outgoing request.
    public init(request: RawRequest, target: HTTPTarget) {
        self.request = request
        self.target = target
    }
}

/// Context passed to hooks.
public struct HookContext: Sendable {
    /// The tool the send is recorded as.
    public var source: ToolSource

    /// Create a context.
    public init(source: ToolSource) {
        self.source = source
    }
}

/// Rewrites a request before it is written (session rules, transform tags, extensions…). Defined
/// here, implemented by higher layers and registered by `GulpWorkspace` (doc 01 §3 rule 5).
public protocol RequestHook: Sendable {
    /// Which `HookSet` member this hook belongs to.
    var kind: HookSet { get }
    /// Modify `req` in place; throwing fails the send.
    func willSend(_ req: inout OutgoingRequest, context: HookContext) async throws
}

/// Observes or rewrites a response after it is received (extensions, cookie-jar updates).
public protocol ResponseHook: Sendable {
    /// Which `HookSet` member this hook belongs to.
    var kind: HookSet { get }
    /// Inspect or modify `response`; throwing is logged and ignored (the bytes were received).
    func didReceive(
        _ response: inout RawResponse, for request: OutgoingRequest, context: HookContext
    ) async throws
}

/// Persists exchanges (implemented by `GulpStore` in M2).
public protocol ExchangeRecorder: Sendable {
    /// Store `exchange` and return its assigned id.
    func record(_ exchange: Exchange) async -> ExchangeID
    /// Replace the exchange recorded earlier with the same id (a streaming response that finished,
    /// F05 HIS-007).
    func update(_ exchange: Exchange) async
}

// MARK: - Engine

/// The one engine every tool sends through (F03 §2).
public protocol HTTPEngine: Sendable {
    /// Send raw HTTP/1 bytes exactly as given (after hooks and the opt-in rewrites).
    func send(_ request: RawRequest, to target: HTTPTarget, options: SendOptions) async -> ExchangeResult
    /// Send a structured HTTP/2 request (M3).
    func send(_ request: H2RequestSpec, to target: HTTPTarget, options: SendOptions) async -> ExchangeResult
    /// Send a group of requests in one of the race/sequence modes.
    func sendGroup(_ items: [GroupItem], mode: GroupSendMode, options: SendOptions) async -> [ExchangeResult]
    /// Open a WebSocket (M4).
    func openWebSocket(
        _ upgrade: RawRequest, to target: HTTPTarget, options: SendOptions
    ) async throws -> WebSocketSession
    /// Connect to an HTTPS `target` ahead of the first request and return the ALPN protocol the
    /// server chose (`h2`, `http/1.1`), leaving the connection pooled for the sends that follow with
    /// the same options. The proxy uses it to mirror ALPN to its client (F01 PRX-008).
    func negotiatedProtocol(for target: HTTPTarget, options: SendOptions) async -> String?
}

extension HTTPEngine {
    /// Engines that can't pre-connect report no protocol (the proxy then offers HTTP/1.1).
    public func negotiatedProtocol(for target: HTTPTarget, options: SendOptions) async -> String? {
        nil
    }
}
