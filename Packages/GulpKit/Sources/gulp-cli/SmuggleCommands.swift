// gulp-cli — the Smuggling Probe headless (F23 ADV-030/031). Sends byte-exact CL.TE / TE.CL timing
// probes through the raw engine and classifies each vector by its timing differential against a clean
// baseline. Detection only — it never runs a destructive confirmation.

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpScanner

/// `gulp-cli smuggle --raw req.txt --target http://host`
struct Smuggle: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "smuggle",
        abstract: "Probe a target for HTTP request smuggling (CL.TE / TE.CL) via timing differentials.")

    @Option(help: "A raw request file giving the target path and Host.") var raw: String
    @Option(help: "Where the probes go, e.g. http://127.0.0.1:8088.") var target: String
    @Option(help: "Seconds of extra delay that mark a vector vulnerable.") var threshold = 3.0

    func run() async throws {
        guard let data = FileManager.default.contents(atPath: raw) else {
            throw ValidationError("Cannot read \(raw)")
        }
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let base = RawRequest(Bytes([UInt8](data)))
        let engine = ScopedSender(scope: .pinned(destination))
        defer { Task { await engine.shutdown() } }
        var options = SendOptions(recordAs: .automation)
        options.timeouts.total = .seconds(20)

        func time(_ request: RawRequest) async throws -> Double {
            let start = ContinuousClock.now
            _ = try await engine.send(request, to: destination, options: options)
            let elapsed = ContinuousClock.now - start
            return Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        }

        let baseline = try await time(SmugglingProbe.baselineProbe(base: base))
        print(String(format: "baseline: %.2fs", baseline))
        var anyVulnerable = false
        for vector in SmugglingVector.allCases {
            let probe = try await time(SmugglingProbe.timingProbe(vector, base: base))
            let vulnerable = SmugglingProbe.isVulnerable(
                baseline: baseline, probe: probe, threshold: threshold)
            anyVulnerable = anyVulnerable || vulnerable
            print(
                String(
                    format: "%@: probe %.2fs (Δ %.2fs) — %@", vector.rawValue, probe, probe - baseline,
                    vulnerable ? "VULNERABLE" : "no differential"))
        }
        if anyVulnerable {
            print("smuggle: a timing differential was found; confirm manually before exploiting.")
        } else {
            print("smuggle: no smuggling differential detected.")
        }
    }
}
