// gulp-cli — the Sequencer headless (F11). Capture many tokens by sending a base request repeatedly
// (SEQ-001/003) or load a token list from a file (SEQ-002), then run the randomness battery and print
// the verdict, the effective-entropy estimate and the per-test results.

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpSequencer

/// `gulp-cli sequencer --raw req.txt --target http://host --cookie SID --count 2000`
struct SequencerCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sequencer",
        abstract: "Capture tokens (or load a list) and analyze their randomness (F11).")

    @Option(help: "A raw request file whose response carries the token (capture mode).") var raw: String?
    @Option(help: "Where --raw goes, e.g. http://127.0.0.1:8088.") var target: String?
    @Option(help: "The token is the value of this Set-Cookie cookie.") var cookie: String?
    @Option(help: "The token is the first capture group of this regex over the response.") var regex: String?
    @Option(help: "How many tokens to capture.") var count = 2000
    @Option(help: "How many captures run at once.") var concurrency = 20
    @Option(help: "Instead of capturing, load tokens from this file (one per line).") var tokens: String?
    @Option(help: "Family-wise significance level (each test is judged at alpha / number of tests).")
    var alpha = 0.01
    @Flag(help: "Print the report as JSON.") var json = false

    func run() async throws {
        let collected: [String]
        if let tokens {
            guard let data = FileManager.default.contents(atPath: tokens) else {
                throw ValidationError("Cannot read \(tokens)")
            }
            collected = String(decoding: data, as: UTF8.self)
                .split(whereSeparator: \.isNewline).map(String.init)
        } else {
            collected = try await capture()
        }
        guard collected.count >= 2 else {
            throw ValidationError("Need at least 2 tokens (captured \(collected.count))")
        }
        let report = Sequencer.analyze(tokens: collected, alpha: alpha)
        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(report), as: UTF8.self))
            return
        }
        print(
            "sequencer: captured \(report.sampleCount) tokens (\(report.uniqueCount) unique), "
                + "encoding \(report.encoding.rawValue)")
        print("region: \(report.regionSymbolLength) symbols (\(report.regionBits) bits)")
        print("verdict: \(report.summary)")
        for test in report.tests {
            let mark = test.pValue == nil ? "skip" : (test.passed ? "PASS" : "FAIL")
            let p = test.pValue.map { String(format: "p=%.4f", $0) } ?? "-"
            print(
                "  \(test.name.padding(toLength: 26, withPad: " ", startingAt: 0)) \(mark)  \(p)  \(test.note)"
            )
        }
        for warning in report.warnings { print("  warning: \(warning)") }
    }

    private func capture() async throws -> [String] {
        guard let raw, let target else {
            throw ValidationError("Capture needs --raw and --target (or use --tokens)")
        }
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        guard let data = FileManager.default.contents(atPath: raw) else {
            throw ValidationError("Cannot read \(raw)")
        }
        let location: TokenLocation
        if let cookie {
            location = .cookie(cookie)
        } else if let regex {
            location = .regex(regex)
        } else {
            throw ValidationError("Say where the token is with --cookie NAME or --regex PATTERN")
        }
        let request = RawRequest(Bytes([UInt8](data)))
        let options = SendOptions(recordAs: .automation)
        let sender = ScopedSender(scope: .pinned(destination))
        defer { Task { await sender.shutdown() } }
        // One check at the single place the target is chosen; the closure below only ever sends there.
        let engine = try await sender.engine(checkedFor: destination)
        let lanes = max(1, min(concurrency, count))
        let collected = await withTaskGroup(of: [String].self) { group in
            for lane in 0..<lanes {
                group.addTask {
                    var mine: [String] = []
                    for index in stride(from: lane, to: count, by: lanes) {
                        _ = index
                        let result = await engine.send(request, to: destination, options: options)
                        if let bytes = result.exchange.response?.bytes.rawBytes,
                            let token = location.extract(fromResponse: Array(bytes))
                        {
                            mine.append(token)
                        }
                    }
                    return mine
                }
            }
            return await group.reduce(into: [String]()) { $0 += $1 }
        }
        return collected
    }
}
