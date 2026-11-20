// gulp-cli — server-side parameter pollution analysis (F23 ADV-022). Duplicates a request's query
// parameters with a canary and reports how the server resolves the duplicate (first-wins, last-wins,
// concatenation, both) — a mismatch with a front-end/WAF is what enables filter bypasses.

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpScanner

/// `gulp-cli pollute --raw req.txt --target http://host`
struct Pollute: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "pollute",
        abstract: "Report how a server resolves duplicated query parameters (parameter pollution).")

    @Option(help: "A raw request whose query parameters are duplicated.") var raw: String
    @Option(help: "Where the probes go.") var target: String

    func run() async throws {
        guard let data = FileManager.default.contents(atPath: raw) else {
            throw ValidationError("Cannot read \(raw)")
        }
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let base = RawRequest(Bytes([UInt8](data)))
        let rawTarget = base.bytes[base.parsed.target].string()
        guard let queryStart = rawTarget.firstIndex(of: "?") else {
            throw ValidationError("The request has no query parameters to pollute.")
        }
        let pairs = rawTarget[rawTarget.index(after: queryStart)...].split(separator: "&").compactMap {
            pair -> (String, String)? in
            let kv = pair.split(separator: "=", maxSplits: 1)
            guard let name = kv.first else { return nil }
            return (String(name), kv.count > 1 ? String(kv[1]) : "")
        }
        let engine = ScopedSender(scope: .pinned(destination))
        defer { Task { await engine.shutdown() } }
        let options = SendOptions(recordAs: .automation)

        func body(_ request: RawRequest) async throws -> String {
            let result = try await engine.send(request, to: destination, options: options)
            return (try? result.exchange.response?.decodedBody()).flatMap { $0 }?.string() ?? ""
        }

        let baseline = try await body(base)
        print("pollute: \(pairs.count) parameter(s)")
        for (name, value) in pairs {
            let canary = "gp\(UInt16.random(in: 1000...9999))"
            let duplicated = ParamMiner.appendingQuery(base, [(name, canary)])
            let handling = ParamPollution.classify(
                firstValue: value, canary: canary, baseline: baseline, dup: try await body(duplicated))
            let note = ParamPollution.isQuirk(handling) ? " (pollution quirk)" : ""
            print("  \(name): \(handling.rawValue)\(note)")
        }
    }
}
