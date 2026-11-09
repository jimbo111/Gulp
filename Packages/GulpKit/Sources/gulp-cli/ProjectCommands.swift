// gulp-cli — `project` subcommands (F21 AUT-004): `import` and `export` are the CLI entry point of the
// shared import/export service (F20 PRJ-012); `info` prints the project's basics.

import ArgumentParser
import Foundation
import GulpCodec
import GulpCore
import GulpStore
import GulpWorkspace

/// `gulp-cli project import|export|info`.
struct ProjectCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "project", abstract: "Import into, export from, or describe a project.",
        subcommands: [Import.self, Export.self, Info.self, Audit.self])

    /// `gulp-cli project import --project p.gulp traffic.har` (HAR, Postman, OpenAPI, XML proxy
    /// history, Caido, sitemap.xml, URL list, or another .gulp).
    struct Import: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract:
                "Import a traffic file (format detected) or merge another .gulp project. Nothing is sent.")

        @Option(help: "Project file (created if missing).")
        var project: String

        @Option(help: "Force a format: \(TrafficFormat.allCases.map(\.rawValue).joined(separator: ", ")).")
        var format: String?

        @Option(help: "Where an OpenAPI document came from (used when it names no absolute server).")
        var baseURL: String?

        @Argument(help: "The file to import.")
        var file: String

        func run() async throws {
            let forced = try format.map { name -> TrafficFormat in
                guard let format = TrafficFormat(rawValue: name) else {
                    throw ValidationError("Unknown format \(name)")
                }
                return format
            }
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            do {
                let report: ImportReport
                if file.hasSuffix(".gulp") {
                    report = try await session.importExport.importProject(at: URL(fileURLWithPath: file))
                } else {
                    guard let data = FileManager.default.contents(atPath: file) else {
                        throw ValidationError("Cannot read \(file)")
                    }
                    report = try await session.importExport.importFile(data, format: forced, baseURL: baseURL)
                }
                print(report.summary)
                for skip in report.skipped { print("  skipped \(skip.item): \(skip.reason)") }
                try await session.close()
            } catch let error as TrafficImportError {
                try? await session.close()
                throw ValidationError(error.message)
            } catch let error as GulpError {
                try? await session.close()
                throw ValidationError(error.message)
            }
        }
    }

    /// `gulp-cli project export --project p.gulp --format har --out traffic.har`.
    struct Export: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Export exchanges as HAR, CSV or a new .gulp file.")

        @Option(help: "Project file.")
        var project: String

        @Option(help: "har, csv or gulp.")
        var format = "har"

        @Option(help: "Output file.")
        var out: String

        @Flag(help: "Only in-scope exchanges.")
        var inScope = false

        @Option(help: "Only these exchange ids (comma-separated).")
        var ids: String?

        func run() async throws {
            guard FileManager.default.fileExists(atPath: project) else {
                throw ValidationError("No project at \(project)")
            }
            let selected = try ids.map { list in
                try list.split(separator: ",").map { item -> ExchangeID in
                    guard let id = ExchangeID(item.trimmingCharacters(in: .whitespaces)) else {
                        throw ValidationError("Bad id \(item)")
                    }
                    return id
                }
            }
            var filter = HistoryFilter()
            filter.inScopeOnly = inScope
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            do {
                switch format {
                case "gulp":
                    let count = try await session.importExport.exportProject(
                        ids: selected, filter: filter, to: URL(fileURLWithPath: out))
                    print("exported \(count) exchange(s) to \(out)")
                case "har", "csv":
                    let data = try await session.importExport.export(
                        ids: selected, filter: filter, as: format == "har" ? .har : .csv)
                    try data.write(to: URL(fileURLWithPath: out))
                    print("exported to \(out) (\(data.count) bytes)")
                default:
                    throw ValidationError("Unknown format \(format) (har, csv or gulp)")
                }
                try await session.close()
            } catch {
                try? await session.close()
                if let error = error as? GulpError { throw ValidationError(error.message) }
                throw error
            }
        }
    }

    /// `gulp-cli project info --project p.gulp`.
    struct Info: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Print a project's name, schema and counts.")

        @Option(help: "Project file.")
        var project: String

        func run() async throws {
            guard FileManager.default.fileExists(atPath: project) else {
                throw ValidationError("No project at \(project)")
            }
            let store = try ProjectStore.open(at: URL(fileURLWithPath: project))
            print("project: \(project)")
            print("name: \(try await store.meta("name") ?? "-")")
            print("schema: \(try await store.meta("schema_version") ?? "?")")
            print("exchanges: \(try await store.count())")
            var inScope = HistoryFilter()
            inScope.inScopeOnly = true
            print("in scope: \(try await store.count(filter: inScope))")
            print("scope rules: \(try await store.scopeRules().count)")
            try await store.close()
        }
    }

    /// `gulp-cli project audit --project p.gulp`: the agent audit log (AUT-023).
    struct Audit: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Print the audit log of agent (MCP) actions.")

        @Option(help: "Project file.")
        var project: String

        @Option(help: "How many of the newest entries.")
        var last = 50

        func run() async throws {
            guard FileManager.default.fileExists(atPath: project) else {
                throw ValidationError("No project at \(project)")
            }
            let store = try ProjectStore.open(at: URL(fileURLWithPath: project))
            for entry in try await store.auditLog(limit: last) {
                let time = ISO8601DateFormatter().string(from: entry.at)
                print(
                    "\(time)\t\(entry.actor)\t\(entry.action)\t\(entry.outcome)\t\(entry.target ?? "-")\t\(entry.detail ?? "")"
                )
            }
            try await store.close()
        }
    }
}
