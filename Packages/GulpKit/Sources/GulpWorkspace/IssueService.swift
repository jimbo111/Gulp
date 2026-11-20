// GulpWorkspace — issue actions that need more than the store: promoting a Notebook item to an issue
// (F14 NB-005) and checking a project's issues against an expectation manifest (the M10a DoD and
// doc 06 §3's `vulnlab-issues.json`).

import Foundation
import GulpCore
import GulpScanner
import GulpStore

/// One route of an expectation manifest: the exact issue types its response must yield.
public struct IssueExpectation: Sendable, Hashable, Codable {
    /// `http` or `https`.
    public var scheme: String
    /// Path (and query) requested.
    public var path: String
    /// An `Origin` header to send (CORS routes).
    public var origin: String?
    /// The issue types expected on this route (empty: none).
    public var expect: [String]
}

/// The result of checking issues against a manifest.
public struct IssueVerification: Sendable, Hashable {
    /// Routes checked.
    public var routes: Int
    /// Expected (route, type) pairs.
    public var expected: Int
    /// Expected but not found: "origin/path type".
    public var missing: [String]
    /// Found but not expected: "origin/path type".
    public var unexpected: [String]

    /// Everything matched.
    public var passed: Bool { missing.isEmpty && unexpected.isEmpty }
}

extension ProjectSession {
    /// Promote a Notebook item to an issue (`manual.finding`) and link the two (NB-005).
    @discardableResult
    public func promoteNotebookItem(_ itemID: Int64, severity: IssueSeverity = .medium) async throws
        -> IssueID?
    {
        guard let item = try await store.notebookItem(itemID) else { return nil }
        let definition = IssueDefinitions.require("manual.finding")
        let path: String
        if let target = item.target, let request = item.request {
            path =
                DerivedFields(target: target, request: RawRequest(Bytes(request)), response: nil).path ?? "/"
        } else {
            path = "/"
        }
        let finding = IssueFinding(
            typeID: definition.id, name: item.title, severity: severity, confidence: definition.confidence,
            host: item.target.map(Issue.origin) ?? "manual", path: path, variant: "notebook:\(itemID)",
            detail: item.note.isEmpty ? item.title : item.note, background: definition.background,
            remediation: definition.remediation,
            evidence: IssueEvidence(exchangeID: item.exchangeID, note: "notebook:\(itemID)"))
        let result = try await store.record(finding)
        try await store.linkNotebookItem(itemID, to: result.id)
        return result.id
    }

    /// Check the project's issues against `manifest`: every route must yield exactly its expected
    /// issue types (attributed by the evidence's exchanges), and no other route any.
    public func verifyIssues(_ manifest: [IssueExpectation], bases: [String: String]) async throws
        -> IssueVerification
    {
        var expected: [String: Set<String>] = [:]
        for entry in manifest {
            guard let base = bases[entry.scheme], let url = URLComponents(string: base + entry.path),
                let host = url.host
            else { continue }
            let scheme = url.scheme ?? entry.scheme
            let port = url.port ?? (scheme == "https" ? 443 : 80)
            let key = "\(scheme)://\(host.lowercased()):\(port)\(url.path.isEmpty ? "/" : url.path)"
            expected[key, default: []].formUnion(entry.expect)
        }
        var actual: [String: Set<String>] = [:]
        for summary in try await store.issues() {
            guard let issue = try await store.issue(summary.id) else { continue }
            let ids = issue.evidence.compactMap(\.exchangeID)
            for exchange in try await store.exchanges(ids: ids) {
                let key = Issue.origin(exchange.target) + (exchange.derived.path ?? "/")
                actual[key, default: []].insert(issue.typeID)
            }
        }
        var missing: [String] = []
        var unexpected: [String] = []
        for key in Set(expected.keys).union(actual.keys).sorted() {
            let want = expected[key] ?? []
            let got = actual[key] ?? []
            missing += want.subtracting(got).sorted().map { "\(key) \($0)" }
            unexpected += got.subtracting(want).sorted().map { "\(key) \($0)" }
        }
        return IssueVerification(
            routes: expected.count, expected: expected.values.reduce(0) { $0 + $1.count }, missing: missing,
            unexpected: unexpected)
    }
}
