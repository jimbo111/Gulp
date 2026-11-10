// GulpWorkspace — exporting issues (F08 SCN-007): Gulp's JSON (everything, round-trippable) and SARIF
// 2.1.0 for code-scanning dashboards and CI. HTML reports belong to F19 (M16a).

import Foundation
import GulpCore
import GulpScanner
import GulpStore

/// An issue export format.
public enum IssueExportFormat: String, Sendable, CaseIterable {
    /// Gulp's JSON.
    case json
    /// SARIF 2.1.0.
    case sarif
}

extension ProjectSession {
    /// Issues matching `filter`, with evidence, as `format`.
    public func exportIssues(_ format: IssueExportFormat, filter: IssueFilter = IssueFilter()) async throws
        -> Data
    {
        var issues: [Issue] = []
        for summary in try await store.issues(filter) {
            if let full = try await store.issue(summary.id) { issues.append(full) }
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        switch format {
        case .json: return try encoder.encode(IssueFile(issues: issues.map(IssueFile.Entry.init)))
        case .sarif: return try encoder.encode(SARIF.log(issues))
        }
    }
}

/// Gulp's issue JSON.
struct IssueFile: Encodable {
    var gulpIssues = 1
    var issues: [Entry]

    struct Entry: Encodable {
        var id: Int64
        var type: String
        var name: String
        var severity: String
        var confidence: String
        var status: String
        var host: String
        var path: String
        var insertionPoint: String?
        var dedupKey: String
        var detail: String
        var background: String
        var remediation: String
        var references: String
        var notes: String
        var firstSeen: Date
        var lastSeen: Date
        var evidence: [IssueEvidence]

        init(_ issue: Issue) {
            id = issue.id
            type = issue.typeID
            name = issue.name
            severity = issue.severity.rawValue
            confidence = issue.confidence.rawValue
            status = issue.status.rawValue
            host = issue.host
            path = issue.path
            insertionPoint = issue.insertionPoint
            dedupKey = issue.dedupKey
            detail = issue.detail
            background = issue.background
            remediation = issue.remediation
            references = issue.references
            notes = issue.notes
            firstSeen = issue.createdAt
            lastSeen = issue.updatedAt
            evidence = issue.evidence
        }
    }
}

/// SARIF 2.1.0 (the subset code-scanning tools read).
enum SARIF {
    struct Log: Encodable {
        var schema = "https://json.schemastore.org/sarif-2.1.0.json"
        var version = "2.1.0"
        var runs: [Run]

        enum CodingKeys: String, CodingKey {
            case schema = "$schema"
            case version, runs
        }
    }

    struct Run: Encodable {
        var tool: Tool
        var results: [Result]
    }

    struct Tool: Encodable { var driver: Driver }

    struct Driver: Encodable {
        var name = "Gulp"
        var rules: [Rule]
    }

    struct Text: Encodable {
        var text: String
        var markdown: String?
    }

    struct Rule: Encodable {
        var id: String
        var name: String
        var shortDescription: Text
        var fullDescription: Text
        var help: Text
        var properties: RuleProperties
    }

    struct RuleProperties: Encodable {
        var securitySeverity: String
        var tags: [String]

        enum CodingKeys: String, CodingKey {
            case securitySeverity = "security-severity"
            case tags
        }
    }

    struct Result: Encodable {
        var ruleId: String
        var level: String
        var message: Text
        var locations: [Location]
        var partialFingerprints: [String: String]
        var properties: [String: String]
    }

    struct Location: Encodable { var physicalLocation: Physical }
    struct Physical: Encodable { var artifactLocation: Artifact }
    struct Artifact: Encodable { var uri: String }

    static func level(_ severity: IssueSeverity) -> String {
        switch severity {
        case .high: "error"
        case .medium, .low: "warning"
        case .info: "note"
        }
    }

    /// GitHub's 0–10 `security-severity`.
    static func score(_ severity: IssueSeverity) -> String {
        switch severity {
        case .high: "8.0"
        case .medium: "5.0"
        case .low: "3.0"
        case .info: "0.0"
        }
    }

    static func log(_ issues: [Issue]) -> Log {
        var rules: [String: Rule] = [:]
        for issue in issues where rules[issue.typeID] == nil {
            let definition = IssueDefinitions.named(issue.typeID)
            rules[issue.typeID] = Rule(
                id: issue.typeID, name: issue.name, shortDescription: Text(text: issue.name),
                fullDescription: Text(text: definition?.background ?? issue.background),
                help: Text(
                    text: definition?.remediation ?? issue.remediation,
                    markdown: definition?.remediation ?? issue.remediation),
                properties: RuleProperties(securitySeverity: score(issue.checkSeverity), tags: ["security"]))
        }
        let results = issues.map { issue in
            Result(
                ruleId: issue.typeID, level: level(issue.severity), message: Text(text: issue.detail),
                locations: [
                    Location(
                        physicalLocation: Physical(artifactLocation: Artifact(uri: issue.host + issue.path)))
                ],
                partialFingerprints: ["gulpDedupKey/v1": issue.dedupKey],
                properties: [
                    "severity": issue.severity.rawValue, "confidence": issue.confidence.rawValue,
                    "status": issue.status.rawValue,
                ])
        }
        return Log(runs: [
            Run(
                tool: Tool(driver: Driver(rules: rules.keys.sorted().compactMap { rules[$0] })),
                results: results)
        ])
    }
}
