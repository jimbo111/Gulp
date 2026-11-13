// GulpReport — turn a project's issues into a shareable report (F19, M16): a self-contained HTML
// report (inline CSS, a severity summary, issues grouped most-severe first, each with detail,
// background, remediation and references) and a bug-bounty-style Markdown report. Pure Swift over the
// GulpCore `Issue` model, so it builds and tests on Linux; the macOS UI and PDF export reuse it.

import Foundation
import GulpCore

/// Report formats.
public enum ReportFormat: String, Sendable, CaseIterable {
    /// A self-contained HTML page.
    case html
    /// Bug-bounty-style Markdown.
    case markdown
}

/// Report generation.
public enum GulpReport {
    /// The module's name (diagnostics).
    public static let moduleName = "GulpReport"

    /// Render `issues` as `format`. `title` names the engagement/project.
    public static func render(_ issues: [Issue], title: String, format: ReportFormat, now: Date = Date())
        -> String
    {
        let sorted = issues.sorted {
            $0.severity != $1.severity ? $0.severity > $1.severity : ($0.host + $0.path) < ($1.host + $1.path)
        }
        switch format {
        case .html: return HTMLReport.render(sorted, title: title, now: now)
        case .markdown: return MarkdownReport.render(sorted, title: title, now: now)
        }
    }

    /// Issue counts by severity, most severe first (for summaries).
    public static func counts(_ issues: [Issue]) -> [(severity: IssueSeverity, count: Int)] {
        IssueSeverity.allCases.reversed().compactMap { severity in
            let count = issues.filter { $0.severity == severity }.count
            return count > 0 ? (severity, count) : nil
        }
    }

    static func iso(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        return formatter.string(from: date)
    }
}

/// HTML rendering (self-contained, no external assets).
enum HTMLReport {
    static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
    }

    /// A very small Markdown-ish → HTML pass for the detail fields (`**bold**`, `` `code` ``, links).
    static func inline(_ text: String) -> String {
        var out = escape(text)
        out = out.replacingOccurrences(
            of: #"\*\*([^*]+)\*\*"#, with: "<strong>$1</strong>", options: .regularExpression)
        out = out.replacingOccurrences(
            of: #"`([^`]+)`"#, with: "<code>$1</code>", options: .regularExpression)
        out = out.replacingOccurrences(
            of: #"\[([^\]]+)\]\((https?://[^)]+)\)"#, with: "<a href=\"$2\">$1</a>",
            options: .regularExpression)
        return out.replacingOccurrences(of: "\n", with: "<br>")
    }

    static func color(_ severity: IssueSeverity) -> String {
        switch severity {
        case .high: return "#c0392b"
        case .medium: return "#e67e22"
        case .low: return "#2980b9"
        case .info: return "#7f8c8d"
        }
    }

    static func render(_ issues: [Issue], title: String, now: Date) -> String {
        let counts = GulpReport.counts(issues)
        let summary = counts.map {
            "<span class=\"pill\" style=\"background:\(color($0.severity))\">\($0.count) \(escape($0.severity.rawValue))</span>"
        }.joined(separator: " ")
        let rows = issues.map { issue -> String in
            let references =
                issue.references.isEmpty
                ? "" : "<h4>References</h4><div class=\"ref\">\(inline(issue.references))</div>"
            return """
                <section class="issue">
                  <h3><span class="dot" style="background:\(color(issue.severity))"></span>\(escape(issue.name))
                    <span class="meta">\(escape(issue.severity.rawValue)) · \(escape(issue.confidence.rawValue)) · \(escape(issue.status.rawValue))</span></h3>
                  <div class="loc"><code>\(escape(issue.host))\(escape(issue.path))</code>\(issue.insertionPoint.map { " · " + escape($0) } ?? "")</div>
                  <p>\(inline(issue.detail))</p>
                  <h4>Background</h4><p>\(inline(issue.background))</p>
                  <h4>Remediation</h4><p>\(inline(issue.remediation))</p>
                  \(references)
                </section>
                """
        }.joined(separator: "\n")
        return """
            <!doctype html><html lang="en"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>\(escape(title)) — security report</title>
            <style>
              :root { color-scheme: light dark; }
              body { font: 15px/1.5 -apple-system, system-ui, sans-serif; max-width: 48rem; margin: 2rem auto; padding: 0 1rem; }
              h1 { margin-bottom: .2rem; } .sub { color: #888; margin-top: 0; }
              .pill { color: #fff; padding: .15rem .5rem; border-radius: 1rem; font-size: .85rem; white-space: nowrap; }
              .summary { margin: 1rem 0 2rem; }
              .issue { border-top: 1px solid #8884; padding: 1rem 0; }
              .issue h3 { margin: 0 0 .3rem; font-size: 1.1rem; }
              .dot { display: inline-block; width: .7rem; height: .7rem; border-radius: 50%; margin-right: .4rem; }
              .meta { color: #888; font-size: .8rem; font-weight: normal; }
              .loc { color: #666; margin-bottom: .5rem; }
              h4 { margin: .8rem 0 .2rem; font-size: .85rem; text-transform: uppercase; letter-spacing: .03em; color: #888; }
              code { background: #8882; padding: .05rem .3rem; border-radius: .2rem; }
              .ref a { display: block; }
            </style></head><body>
            <h1>\(escape(title))</h1>
            <p class="sub">Security assessment · \(issues.count) issue(s) · \(GulpReport.iso(now))</p>
            <div class="summary">\(summary.isEmpty ? "No issues." : summary)</div>
            \(rows)
            <footer class="sub" style="margin-top:2rem;border-top:1px solid #8884;padding-top:1rem">Generated by Gulp.</footer>
            </body></html>
            """
    }
}

/// Markdown rendering (bug-bounty style).
enum MarkdownReport {
    static func render(_ issues: [Issue], title: String, now: Date) -> String {
        var lines: [String] = [
            "# \(title) — security report", "", "_\(issues.count) issue(s) · \(GulpReport.iso(now))_", "",
        ]
        let counts = GulpReport.counts(issues)
        if !counts.isEmpty {
            lines.append("| Severity | Count |")
            lines.append("|---|---|")
            for entry in counts {
                lines.append("| \(entry.severity.rawValue.capitalized) | \(entry.count) |")
            }
            lines.append("")
        }
        for issue in issues {
            lines.append("## \(issue.name) — \(issue.severity.rawValue.capitalized)")
            lines.append("")
            lines.append(
                "**Location:** `\(issue.host)\(issue.path)`" + (issue.insertionPoint.map { " (\($0))" } ?? "")
            )
            lines.append(
                "**Confidence:** \(issue.confidence.rawValue) · **Status:** \(issue.status.rawValue)")
            lines.append("")
            lines.append(issue.detail)
            lines.append("")
            lines.append("**Background.** \(issue.background)")
            lines.append("")
            lines.append("**Remediation.** \(issue.remediation)")
            if !issue.references.isEmpty {
                lines.append("")
                lines.append("**References.**")
                lines.append(issue.references)
            }
            lines.append("")
            lines.append("---")
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }
}
