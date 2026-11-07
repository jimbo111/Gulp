// GulpCore — the error model (doc 04 §2, doc 01 §8).
//
// Network failures are data: `GulpNetworkError` is stored in `ExchangeState.failed` and serialized
// into `exchanges.error`. `GulpError` is the user-facing error thrown to the UI/CLI.

/// A typed network failure, stored with the exchange it ended.
public enum GulpNetworkError: Error, Sendable, Codable, Equatable, Hashable {
    case cancelled, connectTimeout, tlsHandshakeTimeout, firstByteTimeout, idleTimeout, totalTimeout
    case connectionRefused, connectionReset, dnsFailure(String), tlsFailure(String)
    case tooLarge(limit: Int), incompleteResponse, upstreamProxyError(String), other(String)

    /// The stable `exchanges.error` token, e.g. `connect_timeout`.
    public var code: String {
        switch self {
        case .cancelled: "cancelled"
        case .connectTimeout: "connect_timeout"
        case .tlsHandshakeTimeout: "tls_handshake_timeout"
        case .firstByteTimeout: "first_byte_timeout"
        case .idleTimeout: "idle_timeout"
        case .totalTimeout: "total_timeout"
        case .connectionRefused: "connection_refused"
        case .connectionReset: "connection_reset"
        case .dnsFailure: "dns_failure"
        case .tlsFailure: "tls_failure"
        case .tooLarge: "too_large"
        case .incompleteResponse: "incomplete_response"
        case .upstreamProxyError: "upstream_proxy_error"
        case .other: "other"
        }
    }

    /// A short human-readable description for tables and the event log.
    public var userDescription: String {
        switch self {
        case .cancelled: "Cancelled"
        case .connectTimeout: "Connect timed out"
        case .tlsHandshakeTimeout: "TLS handshake timed out"
        case .firstByteTimeout: "No response (first-byte timeout)"
        case .idleTimeout: "Response stalled (idle timeout)"
        case .totalTimeout: "Total timeout exceeded"
        case .connectionRefused: "Connection refused"
        case .connectionReset: "Connection reset"
        case .dnsFailure(let host): "DNS lookup failed for \(host)"
        case .tlsFailure(let reason): "TLS failure: \(reason)"
        case .tooLarge(let limit): "Response exceeded \(limit) bytes"
        case .incompleteResponse: "Connection closed before the response was complete"
        case .upstreamProxyError(let reason): "Upstream proxy error: \(reason)"
        case .other(let reason): reason
        }
    }
}

/// A user-facing error thrown to the UI/CLI; never stored in an exchange.
public struct GulpError: Error, Sendable, Equatable {
    /// User-facing message.
    public var message: String
    /// What the user can do about it.
    public var recoverySuggestion: String?
    /// The network failure behind it, if any.
    public var underlying: GulpNetworkError?

    /// Create an error.
    public init(message: String, recoverySuggestion: String? = nil, underlying: GulpNetworkError? = nil) {
        self.message = message
        self.recoverySuggestion = recoverySuggestion
        self.underlying = underlying
    }
}
