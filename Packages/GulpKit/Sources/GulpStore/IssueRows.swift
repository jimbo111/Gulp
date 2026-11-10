// GulpStore — issues and their evidence (F08 SCN-001…SCN-004; doc 04 §4). `record` merges a finding
// into the issue with its dedup key: a new key inserts an issue; a known key keeps the user's triage,
// raises the check's confidence if the new finding is surer, adds the evidence (newest kept, capped)
// and reopens an issue marked fixed (a regression).

import Foundation
import GRDB
import GulpCore

/// Which issues to list (SCN-005 filters).
public struct IssueFilter: Sendable, Hashable {
    /// Severities to keep (empty: all).
    public var severities: Set<IssueSeverity> = []
    /// Confidences to keep (empty: all).
    public var confidences: Set<IssueConfidence> = []
    /// Statuses to keep (empty: all).
    public var statuses: Set<IssueStatus> = []
    /// Host substring.
    public var host: String?
    /// Exact issue type.
    public var typeID: String?
    /// Path prefix (`/safe/`).
    public var pathPrefix: String?

    /// Everything.
    public init() {}
}

/// The outcome of recording a finding.
public struct IssueRecordResult: Sendable, Hashable {
    /// The issue.
    public var id: IssueID
    /// A new issue (not merged into an existing one).
    public var isNew: Bool
    /// The evidence was added (not already there for this exchange).
    public var addedEvidence: Bool
}

extension ProjectStore {
    /// Evidence rows kept per issue (the newest).
    public static let maxEvidencePerIssue = 10

    /// Merge `finding` into the issue with its dedup key, or create one (SCN-003).
    @discardableResult
    public func record(_ finding: IssueFinding, sourceTaskID: Int64? = nil) async throws -> IssueRecordResult
    {
        let now = Date().timeIntervalSince1970
        let key = finding.dedupKey
        let encoder = JSONEncoder()
        let requestMarkers = String(
            decoding: try encoder.encode(finding.evidence.requestMarkers), as: UTF8.self)
        let responseMarkers = String(
            decoding: try encoder.encode(finding.evidence.responseMarkers), as: UTF8.self)
        return try await pool.write { db in
            var isNew = false
            let id: IssueID
            if let row = try Row.fetchOne(
                db, sql: "SELECT id, confidence, status FROM issues WHERE dedup_key = ?", arguments: [key])
            {
                id = row["id"]
                let stored = IssueConfidence(rawValue: row["confidence"] ?? "") ?? .tentative
                let confidence = max(stored, finding.confidence)
                let status: String = row["status"] ?? IssueStatus.open.rawValue
                let reopened = status == IssueStatus.fixed.rawValue ? IssueStatus.open.rawValue : status
                try db.execute(
                    sql: "UPDATE issues SET confidence = ?, status = ?, updated_at = ? WHERE id = ?",
                    arguments: [confidence.rawValue, reopened, now, id])
            } else {
                try db.execute(
                    sql: """
                        INSERT INTO issues (type_id, name, severity, confidence, host, path, insertion_point, \
                        dedup_key, detail_md, background_md, remediation_md, references_md, status, source_task_id, \
                        created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
                        """,
                    arguments: [
                        finding.typeID, finding.name, finding.severity.rawValue, finding.confidence.rawValue,
                        finding.host, Issue.normalizedPath(finding.path), finding.insertionPoint, key,
                        finding.detail,
                        finding.background, finding.remediation, finding.references, sourceTaskID, now, now,
                    ])
                id = db.lastInsertedRowID
                isNew = true
            }
            // One evidence row per exchange; the newest `maxEvidencePerIssue` are kept.
            var added = false
            let duplicate =
                try finding.evidence.exchangeID.map {
                    try Int.fetchOne(
                        db, sql: "SELECT 1 FROM issue_evidence WHERE issue_id = ? AND exchange_id = ?",
                        arguments: [id, $0]) != nil
                } ?? false
            if !duplicate {
                try db.execute(
                    sql: """
                        INSERT INTO issue_evidence (issue_id, exchange_id, request_markers_json, \
                        response_markers_json, oast_interaction_id, note) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                    arguments: [
                        id, finding.evidence.exchangeID, requestMarkers, responseMarkers,
                        finding.evidence.oastInteractionID, finding.evidence.note,
                    ])
                added = true
                try db.execute(
                    sql: """
                        DELETE FROM issue_evidence WHERE issue_id = ? AND id NOT IN \
                        (SELECT id FROM issue_evidence WHERE issue_id = ? ORDER BY id DESC LIMIT ?)
                        """,
                    arguments: [id, id, Self.maxEvidencePerIssue])
            }
            return IssueRecordResult(id: id, isNew: isNew, addedEvidence: added)
        }
    }

    /// Issues matching `filter`, most severe first, then by host, path and type (evidence not
    /// loaded; `evidenceCount` is set).
    public func issues(_ filter: IssueFilter = IssueFilter()) async throws -> [Issue] {
        var clauses: [String] = []
        var arguments: [DatabaseValue] = []
        func membership(_ column: String, _ values: [String]) {
            guard !values.isEmpty else { return }
            clauses.append(
                "\(column) IN (\(Array(repeating: "?", count: values.count).joined(separator: ", ")))")
            arguments += values.map(\.databaseValue)
        }
        membership("COALESCE(severity_user, severity)", filter.severities.map(\.rawValue))
        membership("COALESCE(confidence_user, confidence)", filter.confidences.map(\.rawValue))
        membership("status", filter.statuses.map(\.rawValue))
        if let host = filter.host, !host.isEmpty {
            clauses.append("host LIKE ?")
            arguments.append("%\(host)%".databaseValue)
        }
        if let typeID = filter.typeID {
            clauses.append("type_id = ?")
            arguments.append(typeID.databaseValue)
        }
        if let prefix = filter.pathPrefix {
            clauses.append("substr(path, 1, ?) = ?")
            arguments += [prefix.count.databaseValue, prefix.databaseValue]
        }
        let sql = """
            SELECT issues.*, (SELECT COUNT(*) FROM issue_evidence e WHERE e.issue_id = issues.id) AS evidence_count \
            FROM issues WHERE \(clauses.isEmpty ? "1" : clauses.joined(separator: " AND ")) ORDER BY id
            """
        let values = arguments  // a constant for the read closure
        let rows = try await pool.read { db in
            try Row.fetchAll(db, sql: sql, arguments: StatementArguments(values)).map {
                Self.issue($0, evidence: [])
            }
        }
        return rows.sorted {
            ($0.severity, $1.host, $1.path, $1.typeID) > ($1.severity, $0.host, $0.path, $0.typeID)
        }
    }

    /// One issue with its evidence (newest first).
    public func issue(_ id: IssueID) async throws -> Issue? {
        try await pool.read { db in
            guard
                let row = try Row.fetchOne(
                    db,
                    sql: """
                        SELECT issues.*, (SELECT COUNT(*) FROM issue_evidence e WHERE e.issue_id = issues.id) \
                        AS evidence_count FROM issues WHERE id = ?
                        """,
                    arguments: [id])
            else { return nil }
            let decoder = JSONDecoder()
            let evidence = try Row.fetchAll(
                db, sql: "SELECT * FROM issue_evidence WHERE issue_id = ? ORDER BY id DESC", arguments: [id]
            ).map { e -> IssueEvidence in
                let request: String? = e["request_markers_json"]
                let response: String? = e["response_markers_json"]
                return IssueEvidence(
                    id: e["id"], exchangeID: e["exchange_id"], oastInteractionID: e["oast_interaction_id"],
                    requestMarkers: request.flatMap {
                        try? decoder.decode([MarkerRange].self, from: Data($0.utf8))
                    }
                        ?? [],
                    responseMarkers: response.flatMap {
                        try? decoder.decode([MarkerRange].self, from: Data($0.utf8))
                    } ?? [],
                    note: e["note"])
            }
            return Self.issue(row, evidence: evidence)
        }
    }

    /// Set the status of issues (SCN-005 bulk change).
    public func setIssueStatus(_ status: IssueStatus, for ids: [IssueID]) async throws {
        let now = Date().timeIntervalSince1970
        try await pool.write { db in
            for id in ids {
                try db.execute(
                    sql: "UPDATE issues SET status = ?, updated_at = ? WHERE id = ?",
                    arguments: [status.rawValue, now, id])
            }
        }
    }

    /// Override (or with nil, restore) the check's severity and confidence (SCN-004).
    public func overrideIssue(_ id: IssueID, severity: IssueSeverity?, confidence: IssueConfidence?)
        async throws
    {
        try await pool.write { db in
            try db.execute(
                sql: "UPDATE issues SET severity_user = ?, confidence_user = ?, updated_at = ? WHERE id = ?",
                arguments: [severity?.rawValue, confidence?.rawValue, Date().timeIntervalSince1970, id])
        }
    }

    /// The user's notes on an issue (SCN-004).
    public func setIssueNotes(_ id: IssueID, _ notes: String) async throws {
        try await pool.write { db in
            try db.execute(
                sql: "UPDATE issues SET notes_md = ?, updated_at = ? WHERE id = ?",
                arguments: [notes, Date().timeIntervalSince1970, id])
        }
    }

    /// Delete issues and their evidence.
    public func deleteIssues(_ ids: [IssueID]) async throws {
        try await pool.write { db in
            for id in ids { try db.execute(sql: "DELETE FROM issues WHERE id = ?", arguments: [id]) }
        }
    }

    /// Link a Notebook item to an issue, or unlink it with nil (F14 NB-005): the item records the
    /// issue, and the issue gets an evidence row (the item's exchange, noted `notebook:<id>`).
    public func linkNotebookItem(_ itemID: Int64, to issueID: IssueID?) async throws {
        try await pool.write { db in
            let note = "notebook:\(itemID)"
            try db.execute(sql: "DELETE FROM issue_evidence WHERE note = ?", arguments: [note])
            try db.execute(
                sql: "UPDATE notebook_items SET issue_id = ? WHERE id = ?", arguments: [issueID, itemID])
            guard let issueID else { return }
            let exchange = try ExchangeID.fetchOne(
                db, sql: "SELECT exchange_id FROM notebook_items WHERE id = ?", arguments: [itemID])
            try db.execute(
                sql:
                    "INSERT INTO issue_evidence (issue_id, exchange_id, request_markers_json, response_markers_json, note) VALUES (?, ?, '[]', '[]', ?)",
                arguments: [issueID, exchange, note])
        }
    }

    /// The issue a Notebook item is linked to.
    public func notebookIssue(_ itemID: Int64) async throws -> IssueID? {
        try await pool.read { db in
            try IssueID.fetchOne(
                db, sql: "SELECT issue_id FROM notebook_items WHERE id = ?", arguments: [itemID])
        }
    }

    static func issue(_ row: Row, evidence: [IssueEvidence]) -> Issue {
        let severityUser: String? = row["severity_user"]
        let confidenceUser: String? = row["confidence_user"]
        return Issue(
            id: row["id"], typeID: row["type_id"], name: row["name"],
            checkSeverity: IssueSeverity(rawValue: row["severity"]) ?? .info,
            checkConfidence: IssueConfidence(rawValue: row["confidence"]) ?? .tentative,
            severityOverride: severityUser.flatMap(IssueSeverity.init),
            confidenceOverride: confidenceUser.flatMap(IssueConfidence.init), host: row["host"],
            path: row["path"],
            insertionPoint: row["insertion_point"], dedupKey: row["dedup_key"],
            detail: row["detail_md"] ?? "",
            background: row["background_md"] ?? "", remediation: row["remediation_md"] ?? "",
            references: row["references_md"] ?? "",
            status: IssueStatus(rawValue: row["status"] ?? "") ?? .open,
            notes: row["notes_md"] ?? "", createdAt: Date(timeIntervalSince1970: row["created_at"] ?? 0),
            updatedAt: Date(timeIntervalSince1970: row["updated_at"] ?? 0), evidence: evidence,
            evidenceCount: row["evidence_count"] ?? evidence.count)
    }
}
