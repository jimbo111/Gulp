// GulpCore — the issue model (F08 SCN-001…SCN-004; doc 04 §4 `issues`, `issue_evidence`). Checks
// produce `IssueFinding`s; the store merges findings with the same dedup key into one `Issue` and
// keeps the user's triage (status, severity/confidence overrides, notes) when it is found again.

import Foundation

/// How bad an issue is (SCN-001), lowest first.
public enum IssueSeverity: String, Sendable, Hashable, Codable, CaseIterable, Comparable {
    /// Informational.
    case info
    /// Low.
    case low
    /// Medium.
    case medium
    /// High.
    case high

    var rank: Int { Self.allCases.firstIndex(of: self) ?? 0 }

    /// Ordered info < low < medium < high.
    public static func < (a: Self, b: Self) -> Bool { a.rank < b.rank }

    /// "High", "Medium"…
    public var title: String { rawValue.capitalized }
}

/// How sure the check is (SCN-001), lowest first.
public enum IssueConfidence: String, Sendable, Hashable, Codable, CaseIterable, Comparable {
    /// Might be a false positive.
    case tentative
    /// Strong signal.
    case firm
    /// Proven.
    case certain

    var rank: Int { Self.allCases.firstIndex(of: self) ?? 0 }

    /// Ordered tentative < firm < certain.
    public static func < (a: Self, b: Self) -> Bool { a.rank < b.rank }

    /// "Certain", "Firm"…
    public var title: String { rawValue.capitalized }
}

/// Triage state, with doc 04's exact tokens (SCN-001).
public enum IssueStatus: String, Sendable, Hashable, Codable, CaseIterable {
    /// Needs attention.
    case open
    /// Not a real issue.
    case falsePositive = "false_positive"
    /// Real, accepted by the client.
    case acceptedRisk = "accepted_risk"
    /// Fixed (reopened if found again).
    case fixed

    /// "Open", "False positive"…
    public var title: String {
        switch self {
        case .open: "Open"
        case .falsePositive: "False positive"
        case .acceptedRisk: "Accepted risk"
        case .fixed: "Fixed"
        }
    }
}

/// A byte range to highlight in a message (SCN-002).
public struct MarkerRange: Sendable, Hashable, Codable {
    /// First byte.
    public var start: Int
    /// One past the last byte.
    public var end: Int

    /// A range.
    public init(_ start: Int, _ end: Int) {
        self.start = start
        self.end = max(start, end)
    }

    /// From a Swift range.
    public init(_ range: Range<Int>) { self.init(range.lowerBound, range.upperBound) }

    /// As a Swift range.
    public var range: Range<Int> { start..<end }
}

/// What proved an issue (SCN-002): an exchange (or OAST interaction) and the ranges to highlight.
public struct IssueEvidence: Sendable, Hashable, Codable {
    /// Row id (0 until stored).
    public var id: Int64
    /// The exchange.
    public var exchangeID: ExchangeID?
    /// The OAST interaction (M11a).
    public var oastInteractionID: Int64?
    /// Byte ranges in the request.
    public var requestMarkers: [MarkerRange]
    /// Byte ranges in the response (wire bytes).
    public var responseMarkers: [MarkerRange]
    /// A short note ("Set-Cookie: sid lacks HttpOnly").
    public var note: String?

    /// The note on the evidence row that holds an active finding's base request (SCN-037).
    public static let baseRequestNote = "base request"

    /// Evidence.
    public init(
        id: Int64 = 0, exchangeID: ExchangeID? = nil, oastInteractionID: Int64? = nil,
        requestMarkers: [MarkerRange] = [], responseMarkers: [MarkerRange] = [], note: String? = nil
    ) {
        self.id = id
        self.exchangeID = exchangeID
        self.oastInteractionID = oastInteractionID
        self.requestMarkers = requestMarkers
        self.responseMarkers = responseMarkers
        self.note = note
    }
}

/// What a check reports; the store turns it into (or merges it with) an `Issue`.
public struct IssueFinding: Sendable, Hashable {
    /// Stable issue type id (`passive.cookie.no-httponly`).
    public var typeID: String
    /// Display name.
    public var name: String
    /// Check-defined severity.
    public var severity: IssueSeverity
    /// Check-defined confidence.
    public var confidence: IssueConfidence
    /// `scheme://host:port`.
    public var host: String
    /// Normalized path (`/` for host-wide issues).
    public var path: String
    /// The parameter, header or cookie involved, if any.
    public var insertionPoint: String?
    /// Distinguishes findings of one type on one location (the payload class, SCN-003).
    public var variant: String
    /// Markdown: what was found here.
    public var detail: String
    /// Markdown: why it matters.
    public var background: String
    /// Markdown: how to fix it.
    public var remediation: String
    /// Markdown: links.
    public var references: String
    /// The proof.
    public var evidence: IssueEvidence
    /// For active findings: the unmodified request the probe was derived from. Stored as an extra
    /// evidence row noted `IssueEvidence.baseRequestNote`, so a re-test (SCN-037) can start from it.
    public var baseExchangeID: ExchangeID?

    /// A finding.
    public init(
        typeID: String, name: String, severity: IssueSeverity, confidence: IssueConfidence, host: String,
        path: String, insertionPoint: String? = nil, variant: String = "", detail: String,
        background: String = "", remediation: String = "", references: String = "", evidence: IssueEvidence
    ) {
        self.typeID = typeID
        self.name = name
        self.severity = severity
        self.confidence = confidence
        self.host = host
        self.path = path
        self.insertionPoint = insertionPoint
        self.variant = variant
        self.detail = detail
        self.background = background
        self.remediation = remediation
        self.references = references
        self.evidence = evidence
    }

    /// SCN-003: type + host + normalized path + insertion point + payload class.
    public var dedupKey: String {
        [typeID, host.lowercased(), Issue.normalizedPath(path), insertionPoint?.lowercased() ?? "", variant]
            .joined(separator: "|")
    }
}

/// A stored issue (SCN-001).
public struct Issue: Sendable, Hashable, Identifiable {
    /// Row id.
    public var id: IssueID
    /// Stable issue type id.
    public var typeID: String
    /// Display name.
    public var name: String
    /// What the check said.
    public var checkSeverity: IssueSeverity
    /// What the check said.
    public var checkConfidence: IssueConfidence
    /// The user's override (SCN-004).
    public var severityOverride: IssueSeverity?
    /// The user's override (SCN-004).
    public var confidenceOverride: IssueConfidence?
    /// `scheme://host:port`.
    public var host: String
    /// Path.
    public var path: String
    /// Parameter/header/cookie, if any.
    public var insertionPoint: String?
    /// SCN-003 key.
    public var dedupKey: String
    /// Markdown.
    public var detail: String
    /// Markdown.
    public var background: String
    /// Markdown.
    public var remediation: String
    /// Markdown.
    public var references: String
    /// Triage.
    public var status: IssueStatus
    /// The user's notes (SCN-004).
    public var notes: String
    /// First found.
    public var createdAt: Date
    /// Last found or changed.
    public var updatedAt: Date
    /// Evidence (newest kept, capped).
    public var evidence: [IssueEvidence]
    /// Evidence rows (may exceed `evidence` when only a summary was loaded).
    public var evidenceCount: Int

    /// Effective severity: the override, else the check's.
    public var severity: IssueSeverity { severityOverride ?? checkSeverity }
    /// Effective confidence.
    public var confidence: IssueConfidence { confidenceOverride ?? checkConfidence }

    /// An issue.
    public init(
        id: IssueID, typeID: String, name: String, checkSeverity: IssueSeverity,
        checkConfidence: IssueConfidence,
        severityOverride: IssueSeverity? = nil, confidenceOverride: IssueConfidence? = nil, host: String,
        path: String, insertionPoint: String?, dedupKey: String, detail: String, background: String,
        remediation: String, references: String, status: IssueStatus, notes: String, createdAt: Date,
        updatedAt: Date, evidence: [IssueEvidence], evidenceCount: Int
    ) {
        self.id = id
        self.typeID = typeID
        self.name = name
        self.checkSeverity = checkSeverity
        self.checkConfidence = checkConfidence
        self.severityOverride = severityOverride
        self.confidenceOverride = confidenceOverride
        self.host = host
        self.path = path
        self.insertionPoint = insertionPoint
        self.dedupKey = dedupKey
        self.detail = detail
        self.background = background
        self.remediation = remediation
        self.references = references
        self.status = status
        self.notes = notes
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.evidence = evidence
        self.evidenceCount = evidenceCount
    }

    /// A path for dedup (SCN-003): no query or fragment, numeric/hex/UUID segments as `{id}`, no
    /// trailing slash (except `/`).
    public static func normalizedPath(_ path: String) -> String {
        var trimmed = path
        if let cut = trimmed.firstIndex(where: { $0 == "?" || $0 == "#" }) {
            trimmed = String(trimmed[..<cut])
        }
        let segments = trimmed.split(separator: "/", omittingEmptySubsequences: true).map {
            segment -> String in
            let text = String(segment)
            let isNumber = text.allSatisfy(\.isNumber)
            let isHex = text.count >= 16 && text.allSatisfy { $0.isHexDigit }
            let isUUID =
                text.count == 36 && text.filter { $0 == "-" }.count == 4
                && text.replacingOccurrences(of: "-", with: "").allSatisfy(\.isHexDigit)
            return isNumber || isHex || isUUID ? "{id}" : text
        }
        return "/" + segments.joined(separator: "/")
    }

    /// `scheme://host:port` of a target.
    public static func origin(_ target: HTTPTarget) -> String {
        "\(target.scheme.rawValue)://\(target.host.lowercased()):\(target.port)"
    }
}
