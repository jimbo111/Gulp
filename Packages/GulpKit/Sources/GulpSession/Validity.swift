// GulpSession — the session-validity check (F15 SES-012): a configurable signal that decides whether
// a response shows the session is still valid. It drives re-authentication (SES-011): when a tool's
// response looks "logged out", the session layer runs the identity's login macro once and retries.

import Foundation
import GulpCore

/// How to tell a valid session from an expired one (SES-012). All configured conditions must hold
/// for the session to count as valid; an empty check is always valid.
public struct ValidityCheck: Sendable, Hashable, Codable {
    /// Valid only if the status is one of these (empty: any status).
    public var statusIn: [Int]
    /// Invalid if the response redirects to a URL containing this (e.g. `/login`).
    public var redirectContains: String?
    /// Valid only if the body contains this marker (e.g. a username, a logout link).
    public var bodyContains: String?
    /// Invalid if the body contains this marker (e.g. "Please log in").
    public var bodyAbsent: String?

    /// A check.
    public init(
        statusIn: [Int] = [], redirectContains: String? = nil, bodyContains: String? = nil,
        bodyAbsent: String? = nil
    ) {
        self.statusIn = statusIn
        self.redirectContains = redirectContains
        self.bodyContains = bodyContains
        self.bodyAbsent = bodyAbsent
    }

    /// Nothing configured, so nothing to check.
    public var isEmpty: Bool {
        statusIn.isEmpty && redirectContains == nil && bodyContains == nil && bodyAbsent == nil
    }

    /// Whether `response` indicates a still-valid session (SES-012).
    public func isValid(_ response: RawResponse) -> Bool {
        let status = response.parsed.statusCode
        if !statusIn.isEmpty, !statusIn.contains(status) { return false }
        if let redirectContains, (300..<400).contains(status),
            response.headerValue("location")?.string().contains(redirectContains) == true
        {
            return false
        }
        let body = String(decoding: response.bytes.rawBytes[response.parsed.body], as: UTF8.self)
        if let bodyContains, !body.contains(bodyContains) { return false }
        if let bodyAbsent, body.contains(bodyAbsent) { return false }
        return true
    }
}
