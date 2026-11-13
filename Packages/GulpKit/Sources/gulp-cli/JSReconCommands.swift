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

    func run() async throws {
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let host =
            destination.port == (destination.scheme == .https ? 443 : 80)
            ? destination.host : "\(destination.host):\(destination.port)"
        let engine = NIOHTTPEngine()
        defer { Task { await engine.shutdown() } }

        func fetch(_ requestPath: String) async -> String? {
            let request = RawRequest(Bytes("GET \(requestPath) HTTP/1.1\r\nHost: \(host)\r\n\r\n"))
            let result = await engine.send(
                request, to: destination, options: SendOptions(recordAs: .automation))
            return (try? result.exchange.response?.decodedBody()).flatMap { $0 }.map { $0.string() }
        }

        guard let js = await fetch(path) else { throw ValidationError("Couldn't fetch \(path)") }

        var mined = JSRecon.mineParameters(from: js)
        var literals = JSRecon.mineLiterals(from: js)

        if let mapURL = JSRecon.sourceMapURL(in: js) {
            let mapPath =
                mapURL.hasPrefix("/") || mapURL.hasPrefix("http")
                ? mapURL : (path as NSString).deletingLastPathComponent + "/" + mapURL
            if let mapBody = await fetch(mapPath), let data = mapBody.data(using: .utf8) {
                let sources = JSRecon.reconstruct(sourceMap: data)
                print("sources recovered from \(mapPath): \(sources.count)")
                for source in sources { print("  \(source.path)") }
                // Mine the recovered sources too.
                for source in sources {
                    mined += JSRecon.mineParameters(from: source.content)
                    literals += JSRecon.mineLiterals(from: source.content)
                }
            }
        }

        let params = Set(mined).sorted()
        print("candidate parameters (\(params.count)): \(params.prefix(40).joined(separator: ", "))")
        var seen = Set<String>()
        let uniqueLiterals = literals.filter { seen.insert("\($0.kind)|\($0.value)").inserted }
        print("interesting literals (\(uniqueLiterals.count)):")
        for literal in uniqueLiterals { print("  [\(literal.kind)] \(literal.value)") }
    }
}
