// gulp-cli — JavaScript Recon headless (F27 JSR-003/006/008). Fetch a script, recover its original
// sources from the source map, mine candidate parameter names (feed them to `discover-params`) and
// flag interesting literals.

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpScanner

/// `gulp-cli js-recon --target http://host --path /app.js`
struct JSReconCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "js-recon",
        abstract: "Recover sources from a JS source map, mine parameters, and flag interesting literals.")

    @Option(help: "The server, e.g. http://127.0.0.1:8088.") var target: String
    @Option(help: "The JavaScript path, e.g. /app.js.") var path: String
    @Option(help: "An older version of the asset to diff against (JSR-009).") var baseline: String?

    func run() async throws {
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let host = destination.hostHeader
        let engine = ScopedSender(scope: .pinned(destination))
        defer { Task { await engine.shutdown() } }

        func fetch(_ requestPath: String) async throws -> String? {
            let request = RawRequest(Bytes("GET \(requestPath) HTTP/1.1\r\nHost: \(host)\r\n\r\n"))
            let result = try await engine.send(
                request, to: destination, options: SendOptions(recordAs: .automation))
            return (try? result.exchange.response?.decodedBody()).flatMap { $0 }.map { $0.string() }
        }

        /// Fetch an asset and its source map (if it points at one) and build its recon inventory.
        func inventory(of assetPath: String) async throws -> ReconInventory? {
            guard let js = try await fetch(assetPath) else { return nil }
            var mapData: Data?
            if let mapURL = JSRecon.sourceMapURL(in: js) {
                let mapPath =
                    mapURL.hasPrefix("/") || mapURL.hasPrefix("http")
                    ? mapURL : (assetPath as NSString).deletingLastPathComponent + "/" + mapURL
                mapData = (try await fetch(mapPath))?.data(using: .utf8)
            }
            return JSRecon.inventory(js: js, sourceMap: mapData)
        }

        guard let current = try await inventory(of: path) else {
            throw ValidationError("Couldn't fetch \(path)")
        }

        if let baseline {
            guard let old = try await inventory(of: baseline) else {
                throw ValidationError("Couldn't fetch baseline \(baseline)")
            }
            let diff = JSRecon.diff(from: old, to: current)
            print("js-recon diff \(baseline) → \(path):")
            if diff.isEmpty { print("  no change") }
            for param in diff.addedParameters { print("  + param \(param)") }
            for param in diff.removedParameters { print("  - param \(param)") }
            for literal in diff.addedLiterals { print("  + literal [\(literal.kind)] \(literal.value)") }
            for literal in diff.removedLiterals { print("  - literal [\(literal.kind)] \(literal.value)") }
            for source in diff.addedSources { print("  + source \(source)") }
            for source in diff.removedSources { print("  - source \(source)") }
            return
        }

        if !current.sources.isEmpty {
            print("sources recovered: \(current.sources.count)")
            for source in current.sources { print("  \(source)") }
        }
        print(
            "candidate parameters (\(current.parameters.count)): "
                + current.parameters.prefix(40).joined(separator: ", "))
        print("interesting literals (\(current.literals.count)):")
        for literal in current.literals { print("  [\(literal.kind)] \(literal.value)") }
    }
}
