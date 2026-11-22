// gulp-cli — M9 headless: GulpQL queries (`query`), global search (`search`), the Logger (`logger`),
// saved filters (`filters`), the Notebook (`notebook`), the coverage index (`coverage`) and synthetic
// traffic for performance checks (`seed`).

import ArgumentParser
import Foundation
import GulpCore
import GulpQuery
import GulpStore
import GulpWorkspace

/// Open an existing project for a read-mostly command.
func openSession(_ project: String) async throws -> ProjectSession {
    guard FileManager.default.fileExists(atPath: project) else {
        throw ValidationError("No project at \(project)")
    }
    return try await ProjectSession.open(at: URL(fileURLWithPath: project))
}

/// A GulpQL error as the expression with a caret line under the offending characters.
func describe(_ error: GulpQLError, in text: String) -> String {
    let start = min(error.range.lowerBound, text.count)
    let width = max(1, min(error.range.count, max(1, text.count - start)))
    return "\(text)\n" + String(repeating: " ", count: start) + String(repeating: "^", count: width)
        + "\n\(error.message)"
}

func milliseconds(since start: ContinuousClock.Instant) -> Double {
    let elapsed = ContinuousClock.now - start
    return Double(elapsed.components.seconds) * 1000 + Double(elapsed.components.attoseconds) / 1e15
}

func rowLine(_ row: ExchangeSummary) -> String {
    "\(row.id)\t\(row.source.rawValue)\t\(row.method ?? "-")\t\(row.status.map(String.init) ?? "-")\t\(row.url)"
}

/// `gulp-cli query --project p.gulp 'resp.status >= 500 and req.host ~ "api"'` (HIS-020…024).
struct Query: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run a GulpQL query over a project's traffic; prints the count, time and rows.")

    @Option(help: "Project file.") var project: String
    @Argument(help: "The GulpQL expression.") var expression: String
    @Option(help: "Print this many matching rows (oldest first).") var rows = 0
    @Flag(help: "Print SQLite's plan for the pushed-down part.") var plan = false
    @Flag(help: "Refresh the planner's statistics first.") var analyze = false
    @Option(
        help:
            "Add a column to the printed rows: a GulpQL field, e.g. 'resp.header(\"x-cache\")' (repeatable).")
    var column: [String] = []

    func run() async throws {
        let parsed: GulpQLExpression
        do {
            parsed = try GulpQL.parse(expression)
        } catch {
            throw ValidationError(describe(error, in: expression))
        }
        let session = try await openSession(project)
        if analyze { try await session.store.updateStatistics() }
        let lowering = parsed.sqlLowering()
        let pushdown = lowering.residual == nil ? "full" : lowering.sql == nil ? "none" : "partial"
        var filter = HistoryFilter()
        filter.query = parsed
        let start = ContinuousClock.now
        let ids = try await session.store.matchingIDs(filter: filter, context: await session.queryContext())
        let elapsed = milliseconds(since: start)
        print(String(format: "matched %d in %.0f ms (push-down: %@)", ids.count, elapsed, pushdown))
        if plan {
            print(
                "plan: "
                    + (try await session.store.queryPlan(filter: filter)).replacingOccurrences(
                        of: "\n", with: " | "))
        }
        if rows > 0 {
            let columns: [GulpQLColumn]
            do {
                columns = try column.map { try GulpQLColumn($0) }
            } catch let error as GulpQLError {
                throw ValidationError(error.message)
            }
            let context = await session.queryContext()
            for row in try await session.store.summaries(inOrder: Array(ids.prefix(rows))) {
                var line = rowLine(row)
                if !columns.isEmpty, let exchange = try await session.store.exchange(id: row.id) {
                    line += columns.map { "\t" + ($0.value(for: exchange, context: context) ?? "-") }.joined()
                }
                print(line)
            }
        }
        try await session.close()
    }
}

/// `gulp-cli search --project p.gulp TOKEN` (HIS-050…053).
struct Search: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Search requests and responses (trigram index).")

    @Option(help: "Project file.") var project: String
    @Argument(help: "Text (3+ characters use the index) or, with --regex, a regex.") var text: String
    @Flag(help: "Treat the text as a regex.") var regex = false
    @Flag(help: "Case-sensitive.") var caseSensitive = false
    @Option(help: "both, request or response.") var part = "both"
    @Option(help: "all, headers or body.") var section = "all"
    @Flag(help: "In-scope rows only.") var inScope = false
    @Option(help: "Most hits.") var limit = 200
    @Flag(help: "Rebuild the search index first (e.g. after `seed`).") var reindex = false

    func run() async throws {
        guard let part = SearchQuery.Part(rawValue: part),
            let section = SearchQuery.Section(rawValue: section)
        else {
            throw ValidationError("--part both|request|response, --section all|headers|body")
        }
        var query = SearchQuery(text)
        query.regex = regex
        query.caseSensitive = caseSensitive
        query.part = part
        query.section = section
        query.filter.inScopeOnly = inScope
        query.limit = limit
        let session = try await openSession(project)
        if reindex {
            let began = ContinuousClock.now
            let indexed = try await session.store.rebuildSearchIndex()
            print(String(format: "reindexed %d rows in %.1f s", indexed, milliseconds(since: began) / 1000))
        }
        let start = ContinuousClock.now
        let results = try await session.store.search(query)
        let elapsed = milliseconds(since: start)
        print(
            String(
                format: "hits %d (%@, examined %d) in %.0f ms%@", results.hits.count,
                results.usedIndex ? "index" : "scan", results.examined, elapsed,
                results.truncated ? ", truncated" : ""))
        if let hint = results.hint { print("hint: \(hint)") }
        for hit in results.hits {
            let where_ = (hit.inRequest ? "Q" : "") + (hit.inResponse ? "S" : "")
            print(
                "\(hit.id)\t\(hit.source.rawValue)\t\(hit.status.map(String.init) ?? "-")\t\(where_)\t"
                    + "\(hit.host)\(hit.path)\t\(hit.preview)")
        }
        try await session.close()
    }
}

/// `gulp-cli logger --project p.gulp [--sources proxy,repeater] [--query …]` (HIS-040/041).
struct LoggerCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "logger",
        abstract: "Show the Logger (every tool's traffic); --sources/--query change its settings.")

    @Option(help: "Project file.") var project: String
    @Option(help: "Tools to show, comma-separated (empty: all).") var sources: String?
    @Option(help: "The Logger's GulpQL filter.") var query: String?
    @Option(help: "Print this many rows (newest first).") var rows = 20

    func run() async throws {
        let session = try await openSession(project)
        var settings = await session.loggerSettings()
        if let sources { settings.sources = sources.split(separator: ",").map(String.init) }
        if let query { settings.query = query }
        if sources != nil || query != nil {
            do {
                try await session.setLoggerSettings(settings)
            } catch let error as GulpQLError {
                throw ValidationError(describe(error, in: settings.query))
            }
        }
        let ids = try await session.loggerIDs()
        let shown = settings.sources.isEmpty ? "all tools" : settings.sources.joined(separator: ",")
        print(
            "logger: \(ids.count) rows (\(shown))"
                + (settings.query.isEmpty ? "" : " where \(settings.query)"))
        for row in try await session.store.summaries(inOrder: Array(ids.prefix(rows))) { print(rowLine(row)) }
        try await session.close()
    }
}

/// `gulp-cli filters --project p.gulp [--save NAME --query Q] [--export F] [--import F]` (HIS-026).
struct Filters: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "List, save, export or import saved GulpQL filters.")

    @Option(help: "Project file (saved filters are per user).") var project: String
    @Option(help: "Save a filter under this name (with --query).") var save: String?
    @Option(help: "The filter's GulpQL text.") var query: String?
    @Option(name: .customLong("export"), help: "Write the saved filters to this JSON file.") var exportFile:
        String?
    @Option(name: .customLong("import"), help: "Add filters from this JSON file.") var importFile: String?

    func run() async throws {
        let session = try await openSession(project)
        if let save {
            guard let query else { throw ValidationError("--save needs --query") }
            do {
                try await session.saveFilter(name: save, query: query)
            } catch let error as GulpQLError {
                throw ValidationError(describe(error, in: query))
            }
        }
        if let importFile {
            guard let data = FileManager.default.contents(atPath: importFile) else {
                throw ValidationError("Cannot read \(importFile)")
            }
            print("imported \(try await session.importFilters(data))")
        }
        if let exportFile { try await session.exportFilters().write(to: URL(fileURLWithPath: exportFile)) }
        for filter in await session.filterSettings().saved { print("\(filter.name)\t\(filter.query)") }
        try await session.close()
    }
}

/// `gulp-cli notebook …` (F14).
struct NotebookCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "notebook", abstract: "Save exchanges and notes to the Notebook; list and triage them.",
        subcommands: [Add.self, Note.self, List.self, Update.self])

    struct Add: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Save an exchange (a snapshot).")
        @Option(help: "Project file.") var project: String
        @Option(help: "Exchange id.") var exchange: Int64
        @Option(help: "Title (default: METHOD host/path).") var title: String?
        @Option(help: "Note (markdown).") var note = ""
        @Option(help: "todo, investigating, confirmed, not-an-issue, reported.") var status = "todo"
        @Option(help: "Tags, comma-separated.") var tags = ""

        func run() async throws {
            guard let status = NotebookStatus(rawValue: status) else {
                throw ValidationError("Unknown --status")
            }
            let session = try await openSession(project)
            guard
                let item = try await session.addToNotebook(
                    exchange, title: title, note: note, status: status, tags: splitTags(tags))
            else { throw ValidationError("No exchange \(exchange)") }
            print("item \(item.id): \(item.title)")
            try await session.close()
        }
    }

    struct Note: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Add a free-form note.")
        @Option(help: "Project file.") var project: String
        @Option(help: "Title.") var title: String
        @Option(help: "Note (markdown).") var note = ""
        @Option(help: "Tags, comma-separated.") var tags = ""

        func run() async throws {
            let session = try await openSession(project)
            let item = try await session.addNote(title: title, note: note, tags: splitTags(tags))
            print("item \(item.id): \(item.title)")
            try await session.close()
        }
    }

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List items (filter: status:, tag:, host:, is:).")
        @Option(help: "Project file.") var project: String
        @Option(help: "Filter, e.g. 'status:confirmed tag:xss login'.") var filter = ""
        @Option(help: "Group by status or host.") var group: String?
        @Flag(help: "Also print each item's note and, for a saved exchange, its snapshot's request line.")
        var notes = false

        func run() async throws {
            let session = try await openSession(project)
            let parsed = NotebookFilter(filter)
            func line(_ item: NotebookItem) -> String {
                var text =
                    "\(item.id)\t\(item.status.rawValue)\t\(item.kind.rawValue)\t\(item.location ?? "-")\t\(item.title)"
                    + (item.tags.isEmpty ? "" : "\t[\(item.tags.joined(separator: ","))]")
                guard notes else { return text }
                if let request = item.request {
                    let requestLine = String(
                        decoding: request.prefix { $0 != 0x0D && $0 != 0x0A }, as: UTF8.self)
                    text += "\n    snapshot of #\(item.exchangeID.map(String.init) ?? "-"): \(requestLine)"
                }
                for noteLine in item.note.split(separator: "\n", omittingEmptySubsequences: false) {
                    text += "\n    note: \(noteLine)"
                }
                return text
            }
            if let group {
                guard let grouping = NotebookGrouping(rawValue: group) else {
                    throw ValidationError("--group status|host")
                }
                for (name, items) in try await session.notebookGroups(grouping, filter: parsed) {
                    print("\(name) (\(items.count))")
                    for item in items { print("  " + line(item)) }
                }
            } else {
                for item in try await session.notebook(parsed) { print(line(item)) }
            }
            try await session.close()
        }
    }

    struct Update: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "set", abstract: "Change an item's status, title, note or tags.")
        @Option(help: "Project file.") var project: String
        @Argument(help: "Item id.") var id: Int64
        @Option(help: "New status.") var status: String?
        @Option(help: "New title.") var title: String?
        @Option(help: "New note.") var note: String?
        @Option(help: "New tags, comma-separated.") var tags: String?

        func run() async throws {
            let parsedStatus = try status.map { text -> NotebookStatus in
                guard let value = NotebookStatus(rawValue: text) else {
                    throw ValidationError("Unknown --status")
                }
                return value
            }
            let session = try await openSession(project)
            try await session.store.updateNotebookItem(
                id, NotebookEdit(title: title, status: parsedStatus, note: note, tags: tags.map(splitTags)))
            try await session.close()
        }
    }
}

func splitTags(_ text: String) -> [String] {
    text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
}

/// `gulp-cli coverage --project p.gulp [--untested]` (F04 JRN-001).
struct Coverage: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Show which tools exercised each endpoint.")

    @Option(help: "Project file.") var project: String
    @Flag(help: "Only in-scope endpoints nothing has tested.") var untested = false

    func run() async throws {
        let session = try await openSession(project)
        let endpoints =
            untested ? try await session.coverage.untested() : try await session.coverage.endpoints()
        print("endpoints: \(endpoints.count)")
        for endpoint in endpoints {
            let tools =
                endpoint.tools.keys.sorted().map { "\($0)×\(endpoint.tools[$0]!.count)" }
                + (endpoint.notebookItems > 0 ? ["notebook×\(endpoint.notebookItems)"] : [])
            let standard = endpoint.port == (endpoint.scheme == "https" ? 443 : 80)
            let authority = standard ? endpoint.host : "\(endpoint.host):\(endpoint.port)"
            print(
                "\(endpoint.tested ? "tested" : "observed")\t\(endpoint.inScope ? "in" : "out")\t"
                    + "\(endpoint.methods.sorted().joined(separator: ","))\t\(endpoint.scheme)://\(authority)"
                    + "\(endpoint.path)\t\(tools.joined(separator: " "))")
        }
        try await session.close()
    }
}

/// `gulp-cli seed --project p.gulp --rows 1000000`: synthetic traffic for performance checks.
struct Seed: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Add synthetic exchanges (for performance checks; not searchable until reindexed).")

    @Option(help: "Project file (created if missing).") var project: String
    @Option(help: "How many rows.") var rows = 100_000

    func run() async throws {
        let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
        let start = ContinuousClock.now
        let ids = try await session.store.seedSyntheticExchanges(count: rows)
        print(
            String(
                format: "seeded %d rows (#%lld…#%lld) in %.1f s", rows, ids.lowerBound, ids.upperBound - 1,
                milliseconds(since: start) / 1000))
        try await session.close()
    }
}
