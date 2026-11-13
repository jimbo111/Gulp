import Foundation
import GulpCore
import Testing

import struct GulpCore.Issue

@testable import GulpReport

// F19 (M16): the HTML and Markdown report renderers.

@Suite("Reports (F19)")
struct ReportTests {
    func issue(
        _ name: String, _ severity: IssueSeverity, type: String = "active.sqli.error",
        host: String = "http://lab", path: String = "/x"
    ) -> Issue {
        Issue(
            id: 1, typeID: type, name: name, checkSeverity: severity, checkConfidence: .firm,
            severityOverride: nil, confidenceOverride: nil, host: host, path: path,
            insertionPoint: "url param id",
            dedupKey: "\(type)|\(path)", detail: "A **bug** at `\(path)` see [ref](https://example.com/x).",
            background: "Why it matters.", remediation: "Fix it.",
            references: "- [OWASP](https://owasp.org/x)",
            status: .open, notes: "", createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000), evidence: [], evidenceCount: 0)
    }

    @Test("F19: the HTML report summarises by severity, escapes, and renders inline markup")
    func test_F19_html() {
        let issues = [
            issue("SQL injection", .high),
            issue("Cookie without HttpOnly", .low, type: "passive.cookie.no-httponly"),
        ]
        let html = GulpReport.render(issues, title: "Acme <test>", format: .html)
        #expect(html.hasPrefix("<!doctype html>"))
        #expect(html.contains("Acme &lt;test&gt;"), "the title is HTML-escaped")
        #expect(html.contains("1 high") && html.contains("1 low"), "severity summary")
        #expect(html.contains("<strong>bug</strong>") && html.contains("<code>/x</code>"), "inline markdown")
        #expect(html.contains("<a href=\"https://example.com/x\">ref</a>"), "inline links")
        // High before low (most severe first).
        #expect(
            html.range(of: "SQL injection")!.lowerBound
                < html.range(of: "Cookie without HttpOnly")!.lowerBound)
    }

    @Test("F19: the Markdown report has a severity table and per-issue sections")
    func test_F19_markdown() {
        let md = GulpReport.render([issue("SQL injection", .high)], title: "Acme", format: .markdown)
        #expect(md.contains("# Acme — security report"))
        #expect(md.contains("| Severity | Count |") && md.contains("| High | 1 |"))
        #expect(md.contains("## SQL injection — High"))
        #expect(md.contains("**Location:** `http://lab/x` (url param id)"))
        #expect(md.contains("**Remediation.** Fix it."))
    }

    @Test("F19: counts collapse to present severities, most severe first")
    func test_F19_counts() {
        let counts = GulpReport.counts([issue("a", .high), issue("b", .high), issue("c", .info)])
        #expect(counts.map { "\($0.severity.rawValue):\($0.count)" } == ["high:2", "info:1"])
    }

    @Test("F19: an empty project renders a clean report")
    func test_F19_empty() {
        let html = GulpReport.render([], title: "Empty", format: .html)
        #expect(html.contains("No issues.") && html.contains("0 issue(s)"))
    }
}
