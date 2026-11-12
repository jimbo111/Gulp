// gulp-cli — the active scanner headless (F08, M11b): `scan active` audits requests (a manifest of
// requests, recorded exchanges, or a raw request file) with a preset config, recording issues in the
// project; `scan verify-active` checks the project's active issues against an expectation manifest
// (exact types per route, nothing on the safe twins) — the M11b DoD.

import ArgumentParser
import Foundation
import GulpCore
import GulpScanner
import GulpStore
import GulpWorkspace

/// One manifest entry: a request to scan and the active issue types it must yield.
struct ActiveExpectation: Decodable {
    var method: String
    var path: String
    var body: String?
    var contentType: String?
    var expect: [String]

    func request(host: String) -> RawRequest {
        var lines = ["\(method) \(path) HTTP/1.1", "Host: \(host)"]
        if let contentType { lines.append("Content-Type: \(contentType)") }
        let payload = body ?? ""
        if body != nil { lines.append("Content-Length: \(payload.utf8.count)") }
        return RawRequest(Bytes(lines.joined(separator: "\r\n") + "\r\n\r\n" + payload))
    }

    var routePath: String { String(path.split(separator: "?", maxSplits: 1).first ?? "") }
}

extension ScanCommand {
    struct Active: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract:
                "Actively scan requests (a manifest, recorded exchanges or a raw request); issues go into the project."
        )
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "A JSON manifest of requests ({method, path, body?, contentType?}) to scan.")
        var manifest: String?
        @Option(help: "Base URL the manifest's paths go to, e.g. http://127.0.0.1:8088.") var base: String?
        @Option(help: "Recorded exchange ids to scan (comma-separated).") var exchanges: String?
        @Option(help: "A raw request file to scan (with --target).") var raw: String?
        @Option(help: "Where --raw goes.") var target: String?
        @Option(help: "passive-only, light, balanced (default), thorough.") var config = "balanced"
        @Option(help: "Seconds to wait for OAST interactions at the end.") var oastGrace: Double?
        @Option(help: "Parallel insertion points.") var concurrency: Int?
        @Flag(help: "Allow payloads that could change data (SCN-038).") var unsafe = false
        @Flag(help: "Scan even out of scope (explicit override).") var allowOutOfScope = false
        @Flag(help: "Print each finding as it arrives.") var verbose = false

        func run() async throws {
            guard let preset = ScanConfig.Preset(rawValue: config) else {
                throw ValidationError("Unknown --config \(config)")
            }
            var scanConfig = ScanConfig.preset(preset)
            if let oastGrace { scanConfig.oastGraceSeconds = oastGrace }
            if let concurrency { scanConfig.concurrency = concurrency }
            scanConfig.unsafe = unsafe
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            var requests: [(request: RawRequest, target: HTTPTarget)] = []
            if let manifest {
                guard let base, let destination = HTTPTarget(url: base) else {
                    throw ValidationError("--manifest needs --base http://host:port")
                }
                guard let data = FileManager.default.contents(atPath: manifest) else {
                    throw ValidationError("Cannot read \(manifest)")
                }
                let entries = try JSONDecoder().decode([ActiveExpectation].self, from: data)
                let host =
                    destination.port == (destination.scheme == .https ? 443 : 80)
                    ? destination.host : "\(destination.host):\(destination.port)"
                requests += entries.map { ($0.request(host: host), destination) }
            }
            if let exchanges {
                requests += try await session.scanRequests(
                    exchanges: exchanges.split(separator: ",").compactMap { Int64($0) })
            }
            if let raw {
                guard let target, let destination = HTTPTarget(url: target),
                    let data = FileManager.default.contents(atPath: raw)
                else { throw ValidationError("--raw needs a readable file and --target") }
                requests.append((RawRequest(Bytes([UInt8](data))), destination))
            }
            guard !requests.isEmpty else {
                throw ValidationError("Nothing to scan: give --manifest, --exchanges or --raw")
            }
            let run = await session.startActiveScan(
                requests, config: scanConfig, allowOutOfScope: allowOutOfScope)
            var summary: ScanSummary?
            for await event in run.events {
                switch event {
                case .finding(let finding) where verbose:
                    print("finding: \(finding.typeID)\t\(finding.path)\t\(finding.insertionPoint ?? "-")")
                case .log(let line): print("log: \(line)")
                case .finished(let done): summary = done
                default: break
                }
            }
            if let summary {
                print(
                    String(
                        format: "scan: %d findings, %d probes, %d out of scope in %.1f s (%@)",
                        summary.findings, summary.probes,
                        summary.outOfScope, summary.seconds, summary.stopReason))
                for (check, count) in summary.perCheck.sorted(by: { $0.key < $1.key }) {
                    print("  \(check): \(count)")
                }
            }
            try await session.close()
        }
    }

    struct VerifyActive: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "verify-active",
            abstract:
                "Check the project's active issues against a manifest: exact types per route, none elsewhere."
        )
        @Option(help: "Project file.") var project: String
        @Option(help: "The manifest (as for scan active).") var manifest: String

        func run() async throws {
            guard let data = FileManager.default.contents(atPath: manifest) else {
                throw ValidationError("Cannot read \(manifest)")
            }
            let entries = try JSONDecoder().decode([ActiveExpectation].self, from: data)
            var expected: [String: Swift.Set<String>] = [:]
            for entry in entries {
                expected[Issue.normalizedPath(entry.routePath), default: []].formUnion(entry.expect)
            }
            let session = try await openSession(project)
            var actual: [String: Swift.Set<String>] = [:]
            for issue in try await session.store.issues() where issue.typeID.hasPrefix("active.") {
                actual[Issue.normalizedPath(issue.path), default: []].insert(issue.typeID)
            }
            var missing: [String] = []
            var unexpected: [String] = []
            for (path, types) in expected {
                let found = actual[path] ?? []
                missing += types.subtracting(found).map { "\(path) \($0)" }
                unexpected += found.subtracting(types).map { "\(path) \($0)" }
            }
            for (path, types) in actual where expected[path] == nil {
                unexpected += types.map { "\(path) \($0)" }
            }
            for line in missing.sorted() { print("missing: \(line)") }
            for line in unexpected.sorted() { print("unexpected: \(line)") }
            let pairs = expected.values.reduce(0) { $0 + $1.count }
            print(
                "verify-active: \(entries.count) routes, \(pairs) expected issue(s), \(missing.count) missing, \(unexpected.count) unexpected"
            )
            try await session.close()
            if !missing.isEmpty || !unexpected.isEmpty { throw ExitCode(1) }
        }
    }
}
