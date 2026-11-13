// gulp-cli — generate a report from a project's issues (F19, M16).

import ArgumentParser
import Foundation
import GulpCore
import GulpReport
import GulpStore
import GulpWorkspace

struct ReportCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "report", abstract: "Render the project's issues as an HTML or Markdown report (F19).")
    @Option(help: "Project file.") var project: String
    @Option(help: "html or markdown.") var format = "html"
    @Option(help: "Write to this file instead of stdout.") var out: String?
    @Option(help: "Report title (default: the project name).") var title: String?
    @Option(help: "Only these severities, comma-separated (info,low,medium,high).") var severity: String?

    func run() async throws {
        guard let reportFormat = ReportFormat(rawValue: format) else {
            throw ValidationError("Unknown --format \(format) (html, markdown)")
        }
        let session = try await openSession(project)
        var filter = IssueFilter()
        if let severity {
            filter.severities = Set(
                severity.split(separator: ",").compactMap { IssueSeverity(rawValue: String($0)) })
        }
        let report = try await session.generateReport(reportFormat, filter: filter, title: title)
        if let out {
            try report.write(toFile: out, atomically: true, encoding: .utf8)
            print("report: wrote \(report.utf8.count) bytes to \(out)")
        } else {
            print(report)
        }
        try await session.close()
    }
}
