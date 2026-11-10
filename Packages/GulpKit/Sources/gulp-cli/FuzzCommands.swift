// gulp-cli — the Fuzzer headless (F07): `fuzz` runs an attack in a project (saved with its results),
// `discover` runs content discovery, `wordlists` lists or installs the bundled lists. Both are
// scope-gated like the app (an explicit --allow-out-of-scope overrides).

import ArgumentParser
import Foundation
import GulpCore
import GulpFuzzer
import GulpWorkspace

/// `gulp-cli fuzz --project p.gulp --raw req.txt --target http://host --attack cluster-bomb --set … --set …`.
struct Fuzz: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run a Fuzzer attack (§…§ positions in the request file); results are saved in the project."
    )

    @Option(help: "Project file (created if missing).") var project: String
    @Option(help: "Request file with §…§ positions.") var raw: String
    @Option(help: "Where to send, e.g. http://127.0.0.1:8088.") var target: String
    @Option(help: "sniper, battering-ram, pitchfork or cluster-bomb.") var attack = "sniper"
    @Option(help: "auto, 1.1, 2 or h2c.") var httpVersion = "auto"
    @Option(
        help: """
            A payload set (repeatable, in position order): list:a,b,c | file:PATH | numbers:FROM-TO[:STEP] | \
            null:N | brute:CHARSET:MIN-MAX | recursive:EXTRACT#:INITIAL:COUNT | base
            """)
    var set: [String] = []
    @Option(help: "A processor for set N, N:op (e.g. 1:url-encode, 2:prefix=x, 1:skip=^#) (repeatable).")
    var process: [String] = []
    @Option(help: "A grep-match column (text; prefix re: for a regex) (repeatable).") var match: [String] = []
    @Option(help: "A grep-extract column: between:START|END or regex:PATTERN[:GROUP] (repeatable).")
    var extract: [String] = []
    @Option(help: "Parallel requests.") var concurrency = 10
    @Option(help: "Requests per second cap.") var rps: Double?
    @Option(help: "Delay before each request (ms).") var delay = 0
    @Option(help: "Retries after a network error.") var retries = 0
    @Flag(help: "Stop at the first grep match.") var stopOnMatch = false
    @Option(help: "Stop after this many errors.") var stopAfterErrors: Int?
    @Flag(help: "Send even out-of-scope requests (explicit override).") var allowOutOfScope = false
    @Option(help: "Print this many result rows.") var rows = 0
    @Flag(help: "Print every extracted value.") var printExtracts = false

    func run() async throws {
        guard let data = FileManager.default.contents(atPath: raw) else {
            throw ValidationError("Cannot read \(raw)")
        }
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let type: AttackType
        switch attack {
        case "sniper": type = .sniper
        case "battering-ram": type = .batteringRam
        case "pitchfork": type = .pitchfork
        case "cluster-bomb": type = .clusterBomb
        default: throw ValidationError("Unknown --attack \(attack)")
        }
        var sets = try set.map(Self.parseSet)
        for entry in process {
            let parts = entry.split(separator: ":", maxSplits: 1).map(String.init)
            guard parts.count == 2, let index = Int(parts[0]), sets.indices.contains(index - 1) else {
                throw ValidationError("--process expects N:op for an existing set")
            }
            sets[index - 1].processors.append(try Self.parseProcessor(parts[1]))
        }
        var settings = FuzzSettings()
        switch httpVersion {
        case "auto": settings.httpVersion = .auto
        case "1.1": settings.httpVersion = .http1_1
        case "2": settings.httpVersion = .http2
        case "h2c": settings.httpVersion = .http2PriorKnowledge
        default: throw ValidationError("Unknown --http-version \(httpVersion)")
        }
        settings.concurrency = concurrency
        settings.requestsPerSecond = rps
        settings.delayMs = delay
        settings.retries = retries
        settings.stopOnGrepMatch = stopOnMatch
        settings.stopAfterErrors = stopAfterErrors
        let matches = match.map {
            $0.hasPrefix("re:") ? GrepMatch(String($0.dropFirst(3)), isRegex: true) : GrepMatch($0)
        }
        let extracts = try extract.map(Self.parseExtract)
        let config = FuzzAttackConfig(
            name: URL(fileURLWithPath: raw).lastPathComponent, target: destination, request: [UInt8](data),
            attackType: type,
            sets: sets, matches: matches, extracts: extracts, settings: settings)
        let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
        let run: FuzzRun
        do {
            run = try await session.startAttack(config, allowOutOfScope: allowOutOfScope)
        } catch let error as FuzzTemplateError {
            try? await session.close()
            throw ValidationError(error.message)
        }
        var results: [FuzzResult] = []
        var summary: FuzzSummary?
        for await event in run.events {
            switch event {
            case .result(let result): results.append(result)
            case .finished(let done): summary = done
            }
        }
        results.sort { $0.seq < $1.seq }
        if let summary {
            print(
                String(
                    format: "attack #%lld: sent %d of %d in %.2f s (%.0f req/s), errors %d%@", run.id,
                    summary.sent, summary.planned,
                    summary.seconds, summary.rate, summary.errors,
                    summary.stopReason.map { ", stopped: \($0)" } ?? ""))
        }
        let outOfScope = results.filter { $0.error == "out_of_scope" }.count
        if outOfScope > 0 { print("out of scope (not sent): \(outOfScope)") }
        print(
            "statuses: "
                + Dictionary(grouping: results, by: { $0.status.map(String.init) ?? "-" }).map {
                    "\($0.key)×\($0.value.count)"
                }.sorted().joined(separator: " "))
        for (index, column) in matches.enumerated() {
            print("match \"\(column.pattern)\": \(results.filter { $0.findings.matches[index] }.count) rows")
        }
        for index in extracts.indices {
            let values = results.compactMap { $0.findings.extracts[index] }
            print("extract \(index + 1): \(values.count) values (\(Set(values).count) unique)")
            if printExtracts { for value in values { print("  \(value)") } }
        }
        for result in results.prefix(rows) {
            let payloads = result.payloads.map { $0 ?? "-" }.joined(separator: " | ")
            print(
                "#\(result.seq)\t\(result.status.map(String.init) ?? "-")\t\(result.length)\t\(payloads)\t\(result.error ?? "")"
            )
        }
        try await session.close()
    }

    static func parseSet(_ text: String) throws -> PayloadSet {
        let parts = text.split(separator: ":", maxSplits: 1).map(String.init)
        let rest = parts.count > 1 ? parts[1] : ""
        switch parts[0] {
        case "list":
            return PayloadSet(
                .list(rest.split(separator: ",", omittingEmptySubsequences: false).map(String.init)))
        case "file": return PayloadSet(.file(path: rest))
        case "numbers":
            let pieces = rest.split(separator: ":")
            let range = pieces.first.map { $0.split(separator: "-").compactMap { Int($0) } } ?? []
            guard range.count == 2 else { throw ValidationError("numbers:FROM-TO[:STEP]") }
            let step = pieces.count > 1 ? Int(pieces[1]) ?? 1 : 1
            return PayloadSet(.numbers(from: range[0], to: range[1], step: step, minDigits: 0, hex: false))
        case "null": return PayloadSet(.null(count: Int(rest) ?? 1))
        case "brute":
            let pieces = rest.split(separator: ":")
            let lengths = pieces.count > 1 ? pieces[1].split(separator: "-").compactMap { Int($0) } : []
            guard pieces.count == 2, lengths.count == 2 else {
                throw ValidationError("brute:CHARSET:MIN-MAX")
            }
            return PayloadSet(
                .bruteForce(charset: String(pieces[0]), minLength: lengths[0], maxLength: lengths[1]))
        case "recursive":
            let pieces = rest.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard pieces.count == 3, let index = Int(pieces[0]), let count = Int(pieces[2]) else {
                throw ValidationError("recursive:EXTRACT#:INITIAL:COUNT")
            }
            return PayloadSet(.recursiveGrep(extractIndex: index - 1, initial: pieces[1], count: count))
        case "base": return PayloadSet(.sameAsBase)
        default: throw ValidationError("Unknown payload set \(text)")
        }
    }

    static func parseProcessor(_ text: String) throws -> PayloadProcessor {
        let parts = text.split(separator: "=", maxSplits: 1).map(String.init)
        let value = parts.count > 1 ? parts[1] : ""
        switch parts[0] {
        case "prefix": return .prefix(value)
        case "suffix": return .suffix(value)
        case "skip": return .skipIf(pattern: value)
        case "upper": return .caseRule(.upper)
        case "lower": return .caseRule(.lower)
        case "reverse": return .reverse
        case "tags": return .tags(value)
        default: return .transform(parts[0], [:])
        }
    }

    static func parseExtract(_ text: String) throws -> GrepExtract {
        if text.hasPrefix("between:") {
            let parts = text.dropFirst(8).split(separator: "|", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { throw ValidationError("between:START|END") }
            return .between(start: parts[0], end: parts[1])
        }
        if text.hasPrefix("regex:") {
            let body = String(text.dropFirst(6))
            if let colon = body.lastIndex(of: ":"), let group = Int(body[body.index(after: colon)...]) {
                return .regex(pattern: String(body[..<colon]), group: group)
            }
            return .regex(pattern: body, group: 0)
        }
        throw ValidationError("--extract expects between:START|END or regex:PATTERN[:GROUP]")
    }
}

/// `gulp-cli discover --project p.gulp --url http://127.0.0.1:8088/` (ETL-003).
struct Discover: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Discover content (directory/file brute force); found paths are recorded in the project.")

    @Option(help: "Project file (created if missing).") var project: String
    @Option(help: "Where to start.") var url: String
    @Option(help: "Wordlist (default: the bundled content list).") var wordlist: String?
    @Option(help: "Extensions, comma-separated (added to those seen on the host).") var extensions =
        "php,html,txt,zip,json,js"
    @Option(help: "Recursion depth.") var depth = 2
    @Option(help: "Parallel requests.") var concurrency = 20
    @Option(help: "Requests per second cap.") var rps: Double?
    @Flag(help: "Probe even out-of-scope paths (explicit override).") var allowOutOfScope = false

    func run() async throws {
        guard let words = wordlist ?? BundledWordlists.url("content.txt")?.path else {
            throw ValidationError("No wordlist (give --wordlist)")
        }
        let config = DiscoveryConfig(
            baseURL: url, words: .file(path: words),
            extensions: extensions.split(separator: ",").map(String.init),
            maxDepth: depth, concurrency: concurrency, requestsPerSecond: rps)
        let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
        let (_, events) = try await session.discoverContent(config, allowOutOfScope: allowOutOfScope)
        var found: [DiscoveredPath] = []
        for await event in events {
            switch event {
            case .found(let path): found.append(path)
            case .finished(let sent, let outOfScope, let seconds):
                print(
                    String(
                        format: "discover: %d requests in %.1f s, %d found, %d out of scope", sent, seconds,
                        found.count, outOfScope))
            }
        }
        for line in discoveryTree(found) { print(line) }
        try await session.close()
    }
}

/// `gulp-cli wordlists [--install]` (FUZ-011).
struct Wordlists: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "List the bundled wordlists, or install them.")

    @Flag(help: "Copy them into the user wordlists folder (existing files are kept).") var install = false

    func run() async throws {
        if install {
            let environment = WorkspaceEnvironment.standard
            let copied = try environment.installWordlists()
            print("installed \(copied.count) into \(environment.wordlistsDirectory.path)")
        }
        for (file, label) in BundledWordlists.labels {
            print("\(file)\t\(label)\t\(BundledWordlists.url(file)?.path ?? "-")")
        }
    }
}
