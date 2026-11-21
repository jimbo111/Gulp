// gulp-cli — top-level issue retest (F30 DRF-009, merged into F21 §2.4). Re-tests a project's active
// issues by re-running their check at the same insertion point (the `session.retestIssue` engine,
// SCN-037): Still-Present stays open, Not-Found flips to Fixed. A previously-Fixed issue that is found
// again is a **regression** — it is reopened, and `--fail-on-regression` makes the run exit non-zero
// (for CI gating). This is the headless surface; the per-issue `gulp scan retest` remains.

import ArgumentParser
import Foundation
import GulpCore
import GulpWorkspace

struct RetestCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "retest",
        abstract: "Re-test a project's active issues and report Fixed / Still-Vulnerable / regressions.")

    @Option(help: "Project file.") var project: String
    @Option(help: "Issue ids (comma-separated); default: every open or fixed active issue.") var ids: String?
    @Flag(help: "Re-test even out of scope (explicit override).") var allowOutOfScope = false
    @Flag(help: "Exit non-zero if any previously-fixed issue is Still-Vulnerable again (CI gate).")
    var failOnRegression = false

    func run() async throws {
        let session = try await openSession(project)
        // Which issues to retest: open OR fixed active issues (fixed ones so regressions are caught).
        let all = try await session.store.issues()
        let active = all.filter { $0.typeID.hasPrefix("active.") }
        let chosen: [Issue]
        if let ids {
            let wanted = Set(ids.split(separator: ",").compactMap { IssueID($0) })
            chosen = active.filter { wanted.contains($0.id) }
        } else {
            chosen = active.filter { $0.status == .open || $0.status == .fixed }
        }

        var fixed = 0, stillVulnerable = 0, inconclusive = 0, regressions = 0
        for issue in chosen {
            let priorStatus = issue.status
            let result = try await session.retestIssue(issue.id, allowOutOfScope: allowOutOfScope)
            switch result.outcome {
            case .fixed:
                fixed += 1
                print("retest #\(issue.id) \(issue.typeID): FIXED — \(result.detail)")
            case .stillPresent:
                stillVulnerable += 1
                if priorStatus == .fixed {
                    // Regression: a fixed issue is vulnerable again. Reopen it.
                    try await session.store.setIssueStatus(.open, for: [issue.id])
                    regressions += 1
                    print("retest #\(issue.id) \(issue.typeID): REGRESSION — was Fixed, now \(result.detail)")
                } else {
                    print("retest #\(issue.id) \(issue.typeID): still-vulnerable — \(result.detail)")
                }
            case .inconclusive:
                inconclusive += 1
                print("retest #\(issue.id) \(issue.typeID): needs-review — \(result.detail)")
            }
        }
        print(
            "retest: \(fixed) fixed, \(stillVulnerable) still-vulnerable, \(regressions) regression(s), "
                + "\(inconclusive) needs-review")
        try await session.close()

        if failOnRegression && regressions > 0 {
            throw ExitCode.failure
        }
    }
}
