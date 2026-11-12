// GulpWorkspace — the Authorization Matrix (F23 §1 ADV-001…006, M12b): replay a set of requests as a
// set of identities (swapping each identity's auth via the F15 session state), then judge, per cell,
// whether access control is Enforced, Bypassed, the Same as the authorized user, or Needs review.
// The analysis is a pure function (unit-tested); the orchestration sends through the engine as
// `scanner` traffic under ScopeGuard and raises an access-control issue for each bypass.

import Foundation
import GulpCore
import GulpHTTP
import GulpSession

/// The verdict for one request replayed as one identity (ADV-002).
public enum AuthzVerdict: String, Sendable, Hashable, Codable {
    /// This identity is the authorized baseline.
    case authorized
    /// The identity was denied (its response differs from the authorized one) — access control works.
    case enforced
    /// A lower-privilege/unauthenticated identity got the authorized response — access control is
    /// missing (the headline finding).
    case bypassed
    /// The response matches the authorized one, but so does the unauthenticated response, so the
    /// resource is simply public (not a bypass).
    case sameAsAuthorized = "same-as-authorized"
    /// Ambiguous — a human should look.
    case needsReview = "needs-review"
}

/// One replayed response (status + body), enough to judge a cell.
public struct AuthzResponse: Sendable, Hashable {
    /// HTTP status (0 on a network error).
    public var status: Int
    /// The response body (decoded text; truncated by the caller if huge).
    public var body: String
    /// The exchange id (for evidence), 0 if none.
    public var exchangeID: ExchangeID

    /// A response.
    public init(status: Int, body: String, exchangeID: ExchangeID = 0) {
        self.status = status
        self.body = body
        self.exchangeID = exchangeID
    }
}

/// The pure verdict analysis (ADV-003).
public enum AuthzAnalysis {
    /// Two responses are "the same" when the status matches and the bodies are similar within
    /// `threshold` (0…1, the allowed fraction of length difference), ignoring reflected ids.
    public static func similar(_ a: AuthzResponse, _ b: AuthzResponse, threshold: Double) -> Bool {
        guard a.status == b.status else { return false }
        if a.body == b.body { return true }
        let longer = max(a.body.count, b.body.count)
        guard longer > 0 else { return true }
        let difference = abs(a.body.count - b.body.count)
        // Length-based similarity plus a shared prefix guards against same-length different bodies.
        let prefix = a.body.prefix(64) == b.body.prefix(64)
        return Double(difference) / Double(longer) <= (1 - threshold) && prefix
    }

    /// The verdict for `candidate` against the authorized baseline (ADV-003). `isAuthorized` marks the
    /// baseline identity's own cell; `isUnauthenticated` marks the no-credentials column, where a match
    /// means the resource is public rather than a per-identity bypass.
    public static func verdict(
        candidate: AuthzResponse, authorized: AuthzResponse, isAuthorized: Bool,
        isUnauthenticated: Bool = false,
        threshold: Double = 0.95
    ) -> AuthzVerdict {
        if isAuthorized { return .authorized }
        // The candidate got the authorized user's response: an authenticated non-owner matching is a
        // bypass; the unauthenticated column matching means the resource is simply public.
        if similar(candidate, authorized, threshold: threshold) {
            return isUnauthenticated ? .sameAsAuthorized : .bypassed
        }
        // A clear denial (401/403) or a visibly different body ⇒ access control is enforced.
        if candidate.status == 401 || candidate.status == 403 { return .enforced }
        if candidate.status == authorized.status { return .needsReview }
        return .enforced
    }
}

/// One cell of the matrix (ADV-002).
public struct AuthzCell: Sendable, Hashable {
    /// The request index (row).
    public var requestIndex: Int
    /// The identity id (column); nil for the unauthenticated column.
    public var identity: UUID?
    /// The response.
    public var response: AuthzResponse
    /// The verdict.
    public var verdict: AuthzVerdict
}

/// A finished matrix run (ADV-002).
public struct AuthzMatrixResult: Sendable {
    /// The requests, by their display label (method + path).
    public var requests: [String]
    /// The identity ids in column order (the authorized one first); the unauthenticated column is nil.
    public var columns: [UUID?]
    /// Every cell.
    public var cells: [AuthzCell]
    /// Issue ids raised for bypasses.
    public var issuesRaised: [IssueID]

    /// The cell for a request/identity.
    public func cell(request: Int, identity: UUID?) -> AuthzCell? {
        cells.first { $0.requestIndex == request && $0.identity == identity }
    }
}
