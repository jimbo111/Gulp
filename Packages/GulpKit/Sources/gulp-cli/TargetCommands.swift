// gulp-cli — Target (F04): `scope` edits and tests a project's scope rules, `target` prints its site
// map and analyzes a host. Both drive the same ProjectSession APIs as the app's Target tool.

import ArgumentParser
import Foundation
import GulpCore
import GulpWorkspace

/// `gulp-cli scope --project p.gulp --add https://lab/app --exclude https://lab/app/logout` edits the
/// scope (TGT-020/021); `--test URL` shows the deciding rule; `--export`/`--import` move it as JSON
/// (TGT-025). It always ends by printing the readable summary.
struct Scope: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Show, edit, test, export or import a project's scope.")

    @Option(help: "Project file (created if missing).")
    var project: String

    @Flag(help: "Remove every rule first.")
    var clear = false

    @Option(help: "Add an include rule for this URL's host and path prefix (repeatable).")
    var add: [String] = []

    @Option(help: "Add an exclude rule for this URL's host and path prefix (repeatable).")
    var exclude: [String] = []

    @Option(name: .customLong("import"), help: "Replace the rules with those in this scope JSON file.")
    var importFile: String?

    @Option(name: .customLong("export"), help: "Write the rules to this file as scope JSON.")
    var exportFile: String?

    @Option(help: "Print whether this URL is in scope and which rule decides (repeatable).")
    var test: [String] = []

    func run() async throws {
        let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
        do {
            try await apply(session)
            try await session.close()
        } catch {
            try? await session.close()
            throw error
        }
    }

    private func apply(_ session: ProjectSession) async throws {
        if clear { try await session.setScope([]) }
        if let importFile {
            guard let data = FileManager.default.contents(atPath: importFile) else {
                throw ValidationError("Cannot read \(importFile)")
            }
            do {
                print("imported \(try await session.importScope(data)) rule(s)")
            } catch let error as GulpError {
                throw ValidationError(error.message)
            }
        }
        for url in add where try await session.addToScope(url: url) == nil {
            throw ValidationError("Not an http(s) URL: \(url)")
        }
        for url in exclude where try await session.excludeFromScope(url: url) == nil {
            throw ValidationError("Not an http(s) URL: \(url)")
        }
        let scope = await session.scope()
        for (index, rule) in scope.rules.enumerated() {
            let state = rule.enabled ? "" : " (disabled)"
            let host = rule.hostIsRegex ? "/\(rule.host)/" : rule.host
            let port = rule.port.isEmpty ? "any" : rule.port
            let path = rule.path.isEmpty ? "any" : rule.path
            print(
                "\(index + 1). \(rule.kind.rawValue)\t\(rule.scheme.rawValue)\t\(host)\tport \(port)\tpath \(path)\(state)"
            )
        }
        print(scope.summary)
        for url in test {
            guard let target = HTTPTarget(url: url) else {
                throw ValidationError("Not an http(s) URL: \(url)")
            }
            let path = ScopeService.requestPath(ofURL: url)
            let rule = scope.decidingRule(for: target, path: path)
            let verdict = rule?.kind == .include ? "IN" : "OUT"
            let why = rule.flatMap { r in
                scope.rules.firstIndex(of: r).map { "rule \($0 + 1) (\(r.kind.rawValue))" }
            }
            print("\(verdict)\t\(url)\t\(why ?? "no rule matches")")
        }
        if let exportFile {
            try await session.exportScope().write(to: URL(fileURLWithPath: exportFile))
            print("exported \(scope.rules.count) rule(s) to \(exportFile)")
        }
    }
}

/// `gulp-cli target --project p.gulp` prints the site map (TGT-001): hosts, then path segments,
/// marking inferred nodes (TGT-003), in-scope nodes and request counts. `--analyze URL` runs
/// "Analyze target" on that URL's host (TGT-008).
struct Target: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Print a project's site map or analyze a host.")

    @Option(help: "Project file.")
    var project: String

    @Flag(help: "Only nodes with in-scope traffic.")
    var inScopeOnly = false

    @Flag(help: "Hide inferred nodes (only what was requested).")
    var visitedOnly = false

    @Flag(name: .customLong("hide-404"), help: "Hide nodes whose every response was a 404.")
    var hideNotFound = false

    @Option(help: "Only nodes whose URL contains this text.")
    var search = ""

    @Flag(help: "Fold numeric and UUID path segments into {id}.")
    var grouped = false

    @Option(help: "Analyze this URL's host instead of printing the tree.")
    var analyze: String?

    func run() async throws {
        let url = URL(fileURLWithPath: project)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw ValidationError("No project at \(project)")
        }
        let session = try await ProjectSession.open(at: url)
        if grouped {
            await session.siteMap.setGroupsParameterized(true)
        } else {
            await session.siteMap.rebuild()
        }
        if let analyze {
            guard let target = HTTPTarget(url: analyze) else {
                throw ValidationError("Not an http(s) URL: \(analyze)")
            }
            guard let analysis = try await session.analyzeTarget(SiteMap.hostKey(target)) else {
                try await session.close()
                throw ValidationError("No traffic to \(SiteMap.hostKey(target)) in this project")
            }
            Self.print(analysis)
        } else {
            let map = await session.siteMap.snapshot
            let filter = SiteMapFilter(
                inScopeOnly: inScopeOnly, visitedOnly: visitedOnly, hideNotFound: hideNotFound, search: search
            )
            let visible = map.visible(filter)
            let notes = try await session.siteMapNotes()
            func walk(_ node: SiteMapNode, depth: Int) {
                guard visible.contains(node.id) else { return }
                var line = String(repeating: "  ", count: depth) + node.name
                if !node.exchanges.isEmpty { line += "\t×\(node.exchanges.count)" }
                if !node.visited { line += "\t(inferred)" }
                if node.inScope { line += "\t[in scope]" }
                if let note = notes[node.id] {
                    line +=
                        "\t"
                        + [note.highlight?.rawValue, note.comment, note.notes].compactMap { $0 }.joined(
                            separator: " ")
                }
                Swift.print(line)
                for child in map.children(of: node.id) { walk(child, depth: depth + 1) }
            }
            for host in map.hosts { walk(host, depth: 0) }
            Swift.print("nodes: \(visible.count) shown of \(map.count)")
        }
        try await session.close()
    }

    static func print(_ analysis: TargetAnalysis) {
        Swift.print("requests: \(analysis.requestCount)")
        Swift.print(
            "endpoints: \(analysis.endpointCount) (\(analysis.dynamicEndpointCount) dynamic, "
                + "\(analysis.staticEndpointCount) static); redirects: \(analysis.redirectCount)")
        Swift.print("parameters: \(analysis.parameters.count)")
        for parameter in analysis.parameters {
            let places = parameter.locations.sorted().map(\.rawValue).joined(separator: ",")
            Swift.print(
                "  \(parameter.name)\t\(places)\t×\(parameter.count)\t"
                    + parameter.endpoints.joined(separator: ", "))
        }
        Swift.print("observations: \(analysis.observations.count)")
        for observation in analysis.observations {
            Swift.print(
                "  \(observation.kind.rawValue)\t\(observation.parameter)\t\(observation.endpoint)\t"
                    + observation.detail)
        }
    }
}
