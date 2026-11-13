// gulp-cli — the Scanner's issues headless (M10a): list/show/triage/export them, check them against
// an expectation manifest (the M10a DoD), and run the passive checks over a project's history.

import ArgumentParser
import Foundation
import GulpCore
import GulpScanner
import GulpStore
import GulpWorkspace

/// `gulp-cli issues …` (F08 SCN-001…SCN-007).
struct IssuesCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "issues", abstract: "List, show, triage, export or verify a project's issues.",
        subcommands: [List.self, Show.self, Set.self, Export.self, Verify.self, Definitions.self],
        defaultSubcommand: List.self)

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List issues, most severe first.")
        @Option(help: "Project file.") var project: String
        @Option(help: "Severities, comma-separated (high,medium,low,info).") var severity: String?
        @Option(help: "Statuses, comma-separated (open,false_positive,accepted_risk,fixed).") var status:
            String?
        @Option(help: "Host substring.") var host: String?

        func run() async throws {
            var filter = IssueFilter()
            filter.severities = Swift.Set(try parseList(severity, IssueSeverity.init, "severity"))
            filter.statuses = Swift.Set(try parseList(status, IssueStatus.init, "status"))
            filter.host = host
            let session = try await openSession(project)
            let issues = try await session.store.issues(filter)
            print("issues: \(issues.count)")
            for issue in issues {
                print(
                    "\(issue.id)\t\(issue.severity.rawValue)\t\(issue.confidence.rawValue)\t\(issue.status.rawValue)\t"
                        + "\(issue.typeID)\t\(issue.host)\(issue.path)"
                        + (issue.insertionPoint.map { "\t[\($0)]" } ?? "") + "\t×\(issue.evidenceCount)")
            }
            try await session.close()
        }
    }

    struct Show: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show one issue with its evidence.")
        @Option(help: "Project file.") var project: String
        @Argument(help: "Issue id.") var id: Int64

        func run() async throws {
            let session = try await openSession(project)
            guard let issue = try await session.store.issue(id) else {
                throw ValidationError("No issue \(id)")
            }
            print("# \(issue.name)")
            print(
                "\(issue.severity.title) · \(issue.confidence.title) · \(issue.status.title) · \(issue.host)\(issue.path)"
            )
            print(
                "\n\(issue.detail)\n\n## Background\n\(issue.background)\n\n## Remediation\n\(issue.remediation)"
            )
            if !issue.notes.isEmpty { print("\n## Notes\n\(issue.notes)") }
            for evidence in issue.evidence {
                print(
                    "\nevidence: exchange #\(evidence.exchangeID.map(String.init) ?? "-") \(evidence.note ?? "")"
                )
                guard let exchangeID = evidence.exchangeID,
                    let exchange = try await session.store.exchange(id: exchangeID),
                    let wire = exchange.response?.wireBytes
                else { continue }
                for marker in evidence.responseMarkers where marker.end <= wire.count {
                    print("  response[\(marker.start)..<\(marker.end)]: \(wire[marker.range].string())")
                }
                for marker in evidence.requestMarkers where marker.end <= exchange.request.bytes.count {
                    print(
                        "  request[\(marker.start)..<\(marker.end)]: \(exchange.request.bytes[marker.range].string())"
                    )
                }
            }
            try await session.close()
        }
    }

    struct Set: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Change status, override severity/confidence, add notes.")
        @Option(help: "Project file.") var project: String
        @Argument(help: "Issue ids.") var ids: [Int64]
        @Option(help: "open, false_positive, accepted_risk or fixed.") var status: String?
        @Option(help: "Override the severity (or 'check' to restore it).") var severity: String?
        @Option(help: "Override the confidence (or 'check' to restore it).") var confidence: String?
        @Option(help: "Notes (markdown).") var notes: String?

        func run() async throws {
            let session = try await openSession(project)
            if let status {
                guard let value = IssueStatus(rawValue: status) else {
                    throw ValidationError("Unknown --status")
                }
                try await session.store.setIssueStatus(value, for: ids)
            }
            if severity != nil || confidence != nil {
                for id in ids {
                    guard let issue = try await session.store.issue(id) else { continue }
                    let newSeverity: IssueSeverity? =
                        severity == nil
                        ? issue.severityOverride
                        : severity == "check" ? nil : IssueSeverity(rawValue: severity!)
                    let newConfidence: IssueConfidence? =
                        confidence == nil
                        ? issue.confidenceOverride
                        : confidence == "check" ? nil : IssueConfidence(rawValue: confidence!)
                    try await session.store.overrideIssue(
                        id, severity: newSeverity, confidence: newConfidence)
                }
            }
            if let notes { for id in ids { try await session.store.setIssueNotes(id, notes) } }
            try await session.close()
        }
    }

    struct Export: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Export issues as JSON or SARIF (SCN-007).")
        @Option(help: "Project file.") var project: String
        @Option(help: "json or sarif.") var format = "json"
        @Option(help: "Output file (default: stdout).") var out: String?
        @Option(help: "Statuses to include, comma-separated (default: all).") var status: String?

        func run() async throws {
            guard let format = IssueExportFormat(rawValue: format) else {
                throw ValidationError("--format json|sarif")
            }
            var filter = IssueFilter()
            filter.statuses = Swift.Set(try parseList(status, IssueStatus.init, "status"))
            let session = try await openSession(project)
            let data = try await session.exportIssues(format, filter: filter)
            try await session.close()
            if let out {
                try data.write(to: URL(fileURLWithPath: out))
            } else {
                print(String(decoding: data, as: UTF8.self))
            }
        }
    }

    struct Verify: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract:
                "Check the issues against a manifest of routes and the exact issue types each must yield.")
        @Option(help: "Project file.") var project: String
        @Option(help: "Manifest JSON (e.g. Tests/Fixtures/vulnlab-issues.json).") var manifest: String
        @Option(help: "Base URL for http entries.") var httpBase = "http://127.0.0.1:8088"
        @Option(help: "Base URL for https entries.") var httpsBase = "https://localhost:8443"

        func run() async throws {
            guard let data = FileManager.default.contents(atPath: manifest) else {
                throw ValidationError("Cannot read \(manifest)")
            }
            let entries = try JSONDecoder().decode([IssueExpectation].self, from: data)
            let session = try await openSession(project)
            let result = try await session.verifyIssues(
                entries, bases: ["http": httpBase, "https": httpsBase])
            try await session.close()
            for line in result.missing { print("MISSING\t\(line)") }
            for line in result.unexpected { print("UNEXPECTED\t\(line)") }
            print(
                "verify: \(result.routes) routes, \(result.expected) expected issue(s), "
                    + "\(result.missing.count) missing, \(result.unexpected.count) unexpected")
            if !result.passed { throw ExitCode.failure }
        }
    }

    struct Definitions: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "The built-in issue types (SCN-006).")

        func run() async throws {
            for definition in IssueDefinitions.all {
                print(
                    "\(definition.id)\t\(definition.severity.rawValue)\t\(definition.family)\t\(definition.name)"
                )
            }
        }
    }
}

/// Comma-separated values parsed with `make`, or a validation error naming `what`.
func parseList<T>(_ text: String?, _ make: (String) -> T?, _ what: String) throws -> [T] {
    guard let text, !text.isEmpty else { return [] }
    return try text.split(separator: ",").map { token in
        guard let value = make(String(token).trimmingCharacters(in: .whitespaces)) else {
            throw ValidationError("Unknown \(what) \(token)")
        }
        return value
    }
}

/// `gulp-cli scan passive --project p.gulp [--all]` (F08 §3.1, §4).
struct ScanCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "scan", abstract: "Run scans over a project.",
        subcommands: [Passive.self, Active.self, VerifyActive.self, CrawlAudit.self, API.self, Retest.self])

    struct Passive: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Run the passive checks over recorded traffic not yet scanned (or all of it).")
        @Option(help: "Project file.") var project: String
        @Flag(help: "Rescan the whole history.") var all = false
        @Flag(help: "Include out-of-scope traffic.") var allTraffic = false
        @Option(help: "Also scan these tools' traffic, comma-separated (repeater,fuzzer…).") var tools:
            String?
        @Flag(help: "Enable the secret & JS-endpoint recon checks (F27).") var recon = false
        @Option(help: "Load Check Recipes from this JSON file or directory (SCN-060).") var recipes: String?

        func run() async throws {
            let session = try await openSession(project)
            var config = await session.passiveScanConfig()
            if allTraffic { config.allTraffic = true }
            if recon { config.recon = true }
            if let recipes { config.recipes = try loadRecipes(recipes) }
            if let tools { config.extraTools = tools.split(separator: ",").map(String.init) }
            try await session.setPassiveScanConfig(config)
            if all { try await session.passiveScan.rescanAll() }
            await session.passiveScan.drain()
            let scanned = await session.passiveScan.scanned
            let found = await session.passiveScan.newIssues
            print("passive: scanned \(scanned) exchange(s), \(found) new issue(s)")
            try await session.close()
        }
    }
}

/// Load Check Recipes from a JSON file or a directory of `.json` files (SCN-062 library folder).
func loadRecipes(_ path: String) throws -> [CheckRecipe] {
    let fm = FileManager.default
    var isDir: ObjCBool = false
    guard fm.fileExists(atPath: path, isDirectory: &isDir) else {
        throw ValidationError("No recipes at \(path)")
    }
    var files: [String] = []
    if isDir.boolValue {
        files = (try fm.contentsOfDirectory(atPath: path)).filter { $0.hasSuffix(".json") }.map {
            "\(path)/\($0)"
        }
    } else {
        files = [path]
    }
    var recipes: [CheckRecipe] = []
    for file in files {
        guard let data = fm.contents(atPath: file) else { continue }
        recipes += try CheckRecipes.decode(data)
    }
    return recipes
}
