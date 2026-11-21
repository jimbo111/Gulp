// gulp-cli — the active scanner headless (F08, M11b): `scan active` audits requests (a manifest of
// requests, recorded exchanges, or a raw request file) with a preset config, recording issues in the
// project; `scan verify-active` checks the project's active issues against an expectation manifest
// (exact types per route, nothing on the safe twins) — the M11b DoD.

import ArgumentParser
import Foundation
import GulpCore
import GulpCrawler
import GulpHTTP
import GulpScanner
import GulpStore
import GulpWorkspace

/// One manifest entry: a request to scan and the active issue types it must yield.
struct ActiveExpectation: Decodable {
    var method: String
    var path: String
    var body: String?
    var contentType: String?
    /// Extra header lines (`Authorization: Bearer …`).
    var headers: [String]?
    /// A crawl from the lab's index reaches this route with these parameters (crawl-and-audit DoD).
    var crawl: Bool?
    var expect: [String]

    /// A binary body (gRPC-Web frames), base64.
    var bodyBase64: String?

    func request(host: String) -> RawRequest {
        var lines = ["\(method) \(path) HTTP/1.1", "Host: \(host)"]
        if let contentType { lines.append("Content-Type: \(contentType)") }
        lines += headers ?? []
        let payload =
            bodyBase64.flatMap { Data(base64Encoded: $0) }.map { [UInt8]($0) } ?? Array((body ?? "").utf8)
        if body != nil || bodyBase64 != nil { lines.append("Content-Length: \(payload.count)") }
        return RawRequest(Bytes(Array((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8) + payload))
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
        @Option(help: "Enable an opt-in check family (repeatable): \(ActiveChecks.optInFamilies.sorted()).")
        var enableFamily: [String] = []

        func run() async throws {
            guard let preset = ScanConfig.Preset(rawValue: config) else {
                throw ValidationError("Unknown --config \(config)")
            }
            var scanConfig = ScanConfig.preset(preset)
            if let oastGrace { scanConfig.oastGraceSeconds = oastGrace }
            if let concurrency { scanConfig.concurrency = concurrency }
            scanConfig.unsafe = unsafe
            for family in enableFamily {
                guard ActiveChecks.optInFamilies.contains(family) else {
                    throw ValidationError("\(family) isn't an opt-in family")
                }
                scanConfig.disabledFamilies.remove(family)
            }
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
                let host = destination.hostHeader
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
        @Flag(help: "Only the routes marked `crawl` are expected; other manifest routes are ignored.")
        var crawled = false

        func run() async throws {
            guard let data = FileManager.default.contents(atPath: manifest) else {
                throw ValidationError("Cannot read \(manifest)")
            }
            let all = try JSONDecoder().decode([ActiveExpectation].self, from: data)
            let entries = crawled ? all.filter { $0.crawl == true } : all
            let ignored = Swift.Set(
                crawled ? all.filter { $0.crawl != true }.map { Issue.normalizedPath($0.routePath) } : [])
            var expected: [String: Swift.Set<String>] = [:]
            for entry in entries {
                expected[Issue.normalizedPath(entry.routePath), default: []].formUnion(entry.expect)
            }
            let session = try await openSession(project)
            var actual: [String: Swift.Set<String>] = [:]
            for issue in try await session.store.issues() where issue.typeID.hasPrefix("active.") {
                let path = Issue.normalizedPath(issue.path)
                guard expected[path] != nil || !ignored.contains(path) else { continue }
                actual[path, default: []].insert(issue.typeID)
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

extension ScanCommand {
    /// Print a scan summary like `scan active` does.
    static func printSummary(_ summary: ScanSummary) {
        print(
            String(
                format: "scan: %d findings, %d probes, %d out of scope in %.1f s (%@)", summary.findings,
                summary.probes, summary.outOfScope, summary.seconds, summary.stopReason))
        for (check, count) in summary.perCheck.sorted(by: { $0.key < $1.key }) {
            print("  \(check): \(count)")
        }
    }

    static func scanConfig(_ name: String, oastGrace: Double?, unsafe: Bool) throws -> ScanConfig {
        guard let preset = ScanConfig.Preset(rawValue: name) else {
            throw ValidationError("Unknown --config \(name)")
        }
        var config = ScanConfig.preset(preset)
        if let oastGrace { config.oastGraceSeconds = oastGrace }
        config.unsafe = unsafe
        return config
    }

    struct CrawlAudit: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "crawl-audit",
            abstract: "Crawl from seed URLs, then actively scan the distinct requests found (SCN-035).")
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "A start URL (repeatable).") var seed: [String] = []
        @Option(help: "Max pages crawled.") var maxPages = 2_000
        @Option(help: "Submit forms: none, get, all.") var forms = "all"
        @Option(help: "passive-only, light, balanced (default), thorough.") var config = "balanced"
        @Option(help: "Seconds to wait for OAST interactions at the end.") var oastGrace: Double?
        @Flag(help: "Allow payloads that could change data (SCN-038).") var unsafe = false
        @Flag(help: "Crawl and scan out of scope (explicit override).") var allowOutOfScope = false

        func run() async throws {
            guard !seed.isEmpty else { throw ValidationError("Give at least one --seed") }
            let scan = try ScanCommand.scanConfig(config, oastGrace: oastGrace, unsafe: unsafe)
            let formPolicy: FormPolicy = forms == "none" ? .none : forms == "get" ? .get : .all
            let crawl = CrawlConfig(seeds: seed, maxPages: maxPages, forms: formPolicy)
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            let run = await session.startCrawlAndAudit(
                crawl: crawl, scan: scan, allowOutOfScope: allowOutOfScope)
            for await event in run.events {
                switch event {
                case .crawl(.finished(let report)):
                    print("crawl: \(report.pages.count) pages (\(report.stopReason))")
                case .auditStarted(let count): print("audit: \(count) distinct requests")
                case .scan(.finished(let summary)): ScanCommand.printSummary(summary)
                case .scan(.log(let line)): print("log: \(line)")
                default: break
                }
            }
            try await session.close()
        }
    }

    struct API: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "api", abstract: "Scan every operation of an OpenAPI document (ADV-050).")
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "The OpenAPI JSON: a URL (fetched through the engine) or a file.") var spec: String
        @Option(help: "Base URL when the document names no server.") var base: String?
        @Option(help: "passive-only, light, balanced (default), thorough.") var config = "balanced"
        @Option(help: "Seconds to wait for OAST interactions at the end.") var oastGrace: Double?
        @Flag(help: "Allow payloads that could change data (SCN-038).") var unsafe = false
        @Flag(help: "Scan out of scope (explicit override).") var allowOutOfScope = false

        func run() async throws {
            let scan = try ScanCommand.scanConfig(config, oastGrace: oastGrace, unsafe: unsafe)
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            let document: Data
            if spec.hasPrefix("http://") || spec.hasPrefix("https://") {
                guard let target = HTTPTarget(url: spec), let url = URL(string: spec) else {
                    throw ValidationError("Bad --spec URL")
                }
                let path = url.path.isEmpty ? "/" : url.path
                let request = RawRequest(
                    Bytes(
                        "GET \(path) HTTP/1.1\r\nHost: \(url.host ?? target.host)\(url.port.map { ":\($0)" } ?? "")\r\nAccept: application/json\r\n\r\n"
                    ))
                // rules-check: manual send — fetches the spec document at the URL the operator passed.
                let result = await session.http.send(
                    request, to: target, options: SendOptions(recordAs: .scanner))
                guard let body = try? result.exchange.response?.decodedBody() else {
                    throw ValidationError("Couldn't fetch \(spec)")
                }
                document = Data(body.rawBytes)
            } else {
                guard let data = FileManager.default.contents(atPath: spec) else {
                    throw ValidationError("Cannot read \(spec)")
                }
                document = data
            }
            let requests = try session.apiScanRequests(document, baseURL: base ?? spec)
            let coverage = session.apiCoverage(requests, config: scan)
            for item in coverage { print("operation: \(item.operation)\t\(item.points) insertion point(s)") }
            print(
                "api: \(coverage.count) operations, \(coverage.filter { $0.points > 0 }.count) with insertion points"
            )
            let run = await session.startActiveScan(
                requests, config: scan, allowOutOfScope: allowOutOfScope, name: "API scan")
            for await event in run.events {
                if case .finished(let summary) = event { ScanCommand.printSummary(summary) }
            }
            try await session.close()
        }
    }

    struct Retest: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Re-test active issues: re-run their check at the same insertion point (SCN-037).")
        @Option(help: "Project file.") var project: String
        @Option(help: "Issue ids (comma-separated); default: every open active issue.") var ids: String?
        @Flag(help: "Re-test even out of scope (explicit override).") var allowOutOfScope = false

        func run() async throws {
            let session = try await openSession(project)
            let chosen: [IssueID]
            if let ids {
                chosen = ids.split(separator: ",").compactMap { IssueID($0) }
            } else {
                chosen = try await session.store.issues().filter {
                    $0.typeID.hasPrefix("active.") && $0.status == .open
                }
                .map(\.id)
            }
            for id in chosen {
                let result = try await session.retestIssue(id, allowOutOfScope: allowOutOfScope)
                print("retest #\(id): \(result.outcome.rawValue) — \(result.detail)")
            }
            try await session.close()
        }
    }
}
