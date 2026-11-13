// GulpWorkspace — generate a report from a project's issues (F19, M16). Loads the full issues
// (with evidence) and renders them with GulpReport.

import Foundation
import GulpCore
import GulpReport
import GulpStore

extension ProjectSession {
    /// Render the project's issues as a report (HTML or Markdown).
    public func generateReport(
        _ format: ReportFormat, filter: IssueFilter = IssueFilter(), title: String? = nil
    ) async throws -> String {
        var issues: [Issue] = []
        for summary in try await store.issues(filter) {
            if let full = try await store.issue(summary.id) { issues.append(full) }
        }
        let name = title ?? store.url.deletingPathExtension().lastPathComponent
        return GulpReport.render(issues, title: name, format: format)
    }
}
