// GulpFuzzer — "Discover content" (F07 ETL-003): directory and file brute force from a URL, as a
// Fuzzer preset rather than a separate engine. Per directory it probes each word, the word as a
// directory, the word with each extension (observed on the host + defaults) and backup variants of
// those files (`~`, `.bak`, `.old`), recursing into the directories it finds (bounded depth).
//
// Soft 404s: before probing a directory, two random paths are requested; a candidate that answers
// like them (same status, same length — allowing for a reflected path) counts as not found. Every
// request (fingerprints included) is scope-checked and rate-limited in `fetch`, just before it goes
// out; probes are sent unrecorded and the caller records only what was found.

import Foundation
import GulpCore
import GulpHTTP

/// A discovery run's settings.
public struct DiscoveryConfig: Sendable, Hashable, Codable {
    /// Where to start (`http://host:port/path/`).
    public var baseURL: String
    /// Words to try.
    public var words: PayloadSource
    /// File extensions to add (without the dot).
    public var extensions: [String]
    /// Backup suffixes tried on each file candidate.
    public var backupSuffixes: [String]
    /// How deep to recurse below the base directory.
    public var maxDepth: Int
    /// Parallel requests.
    public var concurrency: Int
    /// Requests per second cap (nil: none).
    public var requestsPerSecond: Double?
    /// Statuses that count as found.
    public var foundStatuses: Set<Int>
    /// Total timeout per request (s).
    public var timeoutSeconds: Int

    /// Defaults: extensions php/html/txt/zip/bak/json/js, backups ~/.bak/.old, depth 2, 20 lanes.
    public init(
        baseURL: String, words: PayloadSource,
        extensions: [String] = ["php", "html", "txt", "zip", "json", "js"],
        backupSuffixes: [String] = ["~", ".bak", ".old"], maxDepth: Int = 2, concurrency: Int = 20,
        requestsPerSecond: Double? = nil,
        foundStatuses: Set<Int> = [200, 204, 301, 302, 307, 308, 401, 403, 405],
        timeoutSeconds: Int = 15
    ) {
        self.baseURL = baseURL
        self.words = words
        self.extensions = extensions
        self.backupSuffixes = backupSuffixes
        self.maxDepth = maxDepth
        self.concurrency = concurrency
        self.requestsPerSecond = requestsPerSecond
        self.foundStatuses = foundStatuses
        self.timeoutSeconds = timeoutSeconds
    }
}

/// A found path.
public struct DiscoveredPath: Sendable {
    /// The path (`/admin`, `/.old/`, `/.old/config.php~`).
    public var path: String
    /// Status.
    public var status: Int
    /// Response length.
    public var length: Int
    /// It is a directory (recursed into).
    public var isDirectory: Bool
    /// The exchange (unrecorded until the caller records it).
    public var exchange: Exchange
}

/// What discovery reports.
public enum DiscoveryEvent: Sendable {
    /// A path was found.
    case found(DiscoveredPath)
    /// Done (requests sent, requests skipped as out of scope).
    case finished(sent: Int, outOfScope: Int, seconds: Double)
}

/// A content-discovery run.
public actor ContentDiscovery {
    let config: DiscoveryConfig
    let engine: any HTTPEngine
    let inScope: (@Sendable (HTTPTarget, String) async -> Bool)?
    let target: HTTPTarget
    let host: String
    private var queue: [(path: String, depth: Int)] = []
    private var seen: Set<String> = []
    private var sent = 0
    private var outOfScope = 0
    private var nextSlot: ContinuousClock.Instant?
    private var cancelled = false

    /// A run from `config.baseURL`.
    public init(
        config: DiscoveryConfig, engine: any HTTPEngine,
        inScope: (@Sendable (HTTPTarget, String) async -> Bool)?
    )
        throws
    {
        guard let target = HTTPTarget(url: config.baseURL) else {
            throw FuzzTemplateError(message: "not an http(s) URL: \(config.baseURL)")
        }
        self.config = config
        self.engine = engine
        self.inScope = inScope
        self.target = target
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        host = standard ? target.host : "\(target.host):\(target.port)"
    }

    /// Stop after the in-flight requests.
    public func cancel() { cancelled = true }

    /// Run; found paths stream as they are confirmed.
    public func start() -> AsyncStream<DiscoveryEvent> {
        let (stream, continuation) = AsyncStream.makeStream(
            of: DiscoveryEvent.self, bufferingPolicy: .unbounded)
        var start = ScopeService.requestPath(ofURL: config.baseURL)
        if let query = start.firstIndex(of: "?") { start = String(start[..<query]) }
        if !start.hasSuffix("/") { start = String(start[...(start.lastIndex(of: "/") ?? start.startIndex)]) }
        queue = [(start, 0)]
        let started = ContinuousClock.now
        Task {
            while let directory = self.dequeue() {
                await self.probe(directory: directory.path, depth: directory.depth, continuation)
            }
            let elapsed = ContinuousClock.now - started
            let (sent, skipped) = self.counts()
            continuation.yield(
                .finished(
                    sent: sent, outOfScope: skipped,
                    seconds: Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds)
                        / 1e18))
            continuation.finish()
        }
        continuation.onTermination = { [weak self] _ in Task { await self?.cancel() } }
        return stream
    }

    func dequeue() -> (path: String, depth: Int)? {
        guard !cancelled, !queue.isEmpty else { return nil }
        return queue.removeFirst()
    }

    func counts() -> (Int, Int) { (sent, outOfScope) }

    func enqueue(_ path: String, depth: Int) {
        if depth <= config.maxDepth, seen.insert("dir:" + path).inserted { queue.append((path, depth)) }
    }

    func markSeen(_ path: String) -> Bool { seen.insert(path).inserted }

    func didSend() { sent += 1 }
    func skipped() { outOfScope += 1 }
    var isCancelled: Bool { cancelled }

    func reserveSlot() -> ContinuousClock.Instant? {
        guard let rps = config.requestsPerSecond, rps > 0 else { return nil }
        let now = ContinuousClock.now
        let slot = max(now, nextSlot ?? now)
        nextSlot = slot + .nanoseconds(Int64(1_000_000_000 / rps))
        return slot
    }

    /// The candidate paths for a directory.
    nonisolated func candidates(in directory: String) -> [String] {
        var result: [String] = []
        for word in config.words.payloads(base: []).map({ String(decoding: $0, as: UTF8.self) }) {
            let name = word.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            guard !name.isEmpty, !name.contains(" ") else { continue }
            result.append(directory + name)
            result.append(directory + name + "/")
            for ext in config.extensions {
                let file = directory + name + "." + ext
                result.append(file)
                for suffix in config.backupSuffixes { result.append(file + suffix) }
            }
        }
        return result
    }

    /// The soft-404 fingerprint of a directory: what random paths get.
    struct NotFound: Sendable {
        var status: Int?
        var length: Int
        var pathLength: Int
    }

    nonisolated func fingerprint(_ directory: String) async -> [NotFound] {
        var prints: [NotFound] = []
        for suffix in ["", ".html"] {
            let random = String((0..<16).map { _ in "abcdefghijklmnopqrstuvwxyz0123456789".randomElement()! })
            let path = directory + random + suffix
            guard let result = await fetch(path) else { continue }  // out of scope: no fingerprint
            let response = result.exchange.response
            prints.append(
                NotFound(
                    status: response?.parsed.statusCode, length: response?.bytes.count ?? 0,
                    pathLength: path.count))
        }
        return prints
    }

    nonisolated func looksNotFound(_ status: Int, length: Int, path: String, _ prints: [NotFound]) -> Bool {
        prints.contains { print in
            guard print.status == status else { return false }
            let tolerance = max(16, print.length / 20)
            let reflected = print.length + (path.count - print.pathLength)
            return abs(length - print.length) <= tolerance || abs(length - reflected) <= 8
        }
    }

    /// GET `path` — nil, unsent, when it is out of scope. The one place discovery sends: every
    /// request is scope-checked, takes a rate slot and is counted here.
    nonisolated func fetch(_ path: String) async -> ExchangeResult? {
        if let inScope, await !inScope(target, path) {
            await skipped()
            return nil
        }
        if let slot = await reserveSlot() { try? await Task.sleep(until: slot, clock: .continuous) }
        var options = SendOptions(recordAs: .fuzzer)
        options.record = false
        options.timeouts.total = .seconds(config.timeoutSeconds)
        options.applyHooks.remove(.transformTags)
        let request = RawRequest(
            Bytes("GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: Gulp\r\nAccept: */*\r\n\r\n"))
        let result = await engine.send(request, to: target, options: options)
        await didSend()
        return result
    }

    nonisolated func probe(
        directory: String, depth: Int, _ continuation: AsyncStream<DiscoveryEvent>.Continuation
    ) async {
        let prints = await fingerprint(directory)
        let candidates = candidates(in: directory)
        let lanes = max(1, config.concurrency)
        // Work sharing: each lane takes the next candidate.
        let counter = Counter()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<lanes {
                group.addTask {
                    while true {
                        let next = await counter.next()
                        guard next < candidates.count, await !self.isCancelled else { return }
                        await self.check(candidates[next], depth: depth, prints: prints, continuation)
                    }
                }
            }
        }
    }

    nonisolated func check(
        _ path: String, depth: Int, prints: [NotFound],
        _ continuation: AsyncStream<DiscoveryEvent>.Continuation
    ) async {
        guard await markSeen(path), let result = await fetch(path), let response = result.exchange.response
        else { return }
        let status = response.parsed.statusCode
        guard config.foundStatuses.contains(status),
            !looksNotFound(status, length: response.bytes.count, path: path, prints)
        else { return }
        // A directory: the slash form answered, or the bare name redirects to it.
        let location = response.headerValue("location")?.string() ?? ""
        let isDirectory =
            path.hasSuffix("/") || ((300..<400).contains(status) && location.hasSuffix(path + "/"))
        if path.hasSuffix("/") { await enqueue(path, depth: depth + 1) }
        continuation.yield(
            .found(
                DiscoveredPath(
                    path: path, status: status, length: response.bytes.count, isDirectory: isDirectory,
                    exchange: result.exchange)))
    }
}

/// Hands out indices to lanes.
actor Counter {
    private var value = 0

    func next() -> Int {
        defer { value += 1 }
        return value
    }
}

/// Found paths as an indented tree (ETL-003's path tree), e.g. `/.old/` above `  config.php~`.
public func discoveryTree(_ paths: [DiscoveredPath]) -> [String] {
    paths.sorted { $0.path < $1.path }.map { found in
        let trimmed = found.path.hasSuffix("/") ? String(found.path.dropLast()) : found.path
        let parts = trimmed.split(separator: "/", omittingEmptySubsequences: true)
        let indent = String(repeating: "  ", count: max(0, parts.count - 1))
        let name =
            (parts.last.map(String.init) ?? "/") + (found.path.hasSuffix("/") && found.path != "/" ? "/" : "")
        return "\(indent)\(name)\t\(found.status)\t\(found.length)"
    }
}
