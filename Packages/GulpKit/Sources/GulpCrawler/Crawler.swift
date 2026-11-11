// GulpCrawler — the static crawl (F09 CRL-001…CRL-010). A frontier of discovered requests (links
// first, heuristic URL strings last; dedup by normalized URL; depth, page, per-directory and
// similar-page caps), lanes that send through the engine (recorded as Crawler traffic, so the site
// map fills; governed by the shared limiter), strict scope, form submission per policy, robots and
// sitemap hints, parameter discovery, a cookie jar and a re-authentication hook point (CRL-006,
// wired to session rules in M12a). Pausable, resumable, cancellable; events stream out.

import Foundation
import GulpCore
import GulpHTTP

/// Crawl settings (CRL-001, CRL-003, CRL-004, CRL-005, CRL-007, CRL-008).
public struct CrawlConfig: Sendable, Codable, Hashable {
    /// Start URLs.
    public var seeds: [String]
    /// Links followed from a seed (a seed is depth 0).
    public var maxDepth: Int
    /// Pages fetched in all (robots/sitemap fetches included).
    public var maxPages: Int
    /// Pages fetched per directory (0: unlimited).
    public var maxPerDirectory: Int
    /// Wall-clock limit in seconds (0: unlimited).
    public var maxSeconds: Double
    /// Pages with the same HTML structure whose links are followed (CRL-007; 0: unlimited).
    public var similarPages: Int
    /// Parallel requests (the shared limiter caps them further).
    public var concurrency: Int
    /// Which forms are submitted.
    public var forms: FormPolicy
    /// Form values and the destructive-action guard.
    public var filler: FormFiller
    /// Read `/robots.txt` and `/sitemap.xml` for hints.
    public var useRobotsAndSitemap: Bool
    /// Skip paths robots.txt disallows (off by default for authorized testing; CRL-005).
    public var obeyRobots: Bool
    /// Dedup normalization.
    public var normalization: NormalizationOptions
    /// Skip URLs matching this (case-insensitive regex) besides the destructive guard.
    public var exclude: String
    /// Request timeout in seconds.
    public var timeoutSeconds: Int
    /// The `User-Agent` sent.
    public var userAgent: String

    /// A configuration with conservative limits.
    public init(
        seeds: [String], maxDepth: Int = 10, maxPages: Int = 1_000, maxPerDirectory: Int = 200,
        maxSeconds: Double = 0, similarPages: Int = 20, concurrency: Int = 8, forms: FormPolicy = .get,
        filler: FormFiller = FormFiller(), useRobotsAndSitemap: Bool = true, obeyRobots: Bool = false,
        normalization: NormalizationOptions = NormalizationOptions(), exclude: String = "",
        timeoutSeconds: Int = 30, userAgent: String = "Mozilla/5.0 (compatible; Gulp crawler)"
    ) {
        self.seeds = seeds
        self.maxDepth = maxDepth
        self.maxPages = maxPages
        self.maxPerDirectory = maxPerDirectory
        self.maxSeconds = maxSeconds
        self.similarPages = similarPages
        self.concurrency = concurrency
        self.forms = forms
        self.filler = filler
        self.useRobotsAndSitemap = useRobotsAndSitemap
        self.obeyRobots = obeyRobots
        self.normalization = normalization
        self.exclude = exclude
        self.timeoutSeconds = timeoutSeconds
        self.userAgent = userAgent
    }
}

/// The re-authentication hook point (CRL-006). M11a crawls unauthenticated; F15 (M12a) supplies an
/// implementation backed by session rules and macros.
public protocol CrawlSessionHandler: Sendable {
    /// Whether this response shows the session was lost (the configurable logout signal).
    func isLoggedOut(_ exchange: Exchange) async -> Bool
    /// Log in again; false when it failed.
    func reauthenticate() async -> Bool
}

/// One fetched page.
public struct CrawledPage: Sendable, Hashable, Codable {
    /// Method.
    public var method: String
    /// URL.
    public var url: String
    /// Status (nil on a network error).
    public var status: Int?
    /// The recorded exchange (0 if none).
    public var exchangeID: Int64
    /// Depth from its seed.
    public var depth: Int
    /// Where the request came from.
    public var source: LinkSource
}

/// A parameter seen during the crawl (CRL-009).
public struct CrawlParameter: Sendable, Hashable, Codable {
    /// Name.
    public var name: String
    /// `query` or `body`.
    public var location: String
    /// Endpoint (method + path) it was seen on.
    public var endpoints: Set<String>
    /// Up to 10 distinct values.
    public var values: Set<String>
}

/// The crawl report (CRL-010).
public struct CrawlReport: Sendable, Hashable, Codable {
    /// Pages fetched, in order.
    public var pages: [CrawledPage] = []
    /// Distinct forms found (by action + method + field names).
    public var forms: [HTMLForm] = []
    /// Forms submitted.
    public var formsSubmitted = 0
    /// Parameters seen.
    public var parameters: [CrawlParameter] = []
    /// Network errors: URL and reason.
    public var errors: [String] = []
    /// Re-authentication events.
    public var authEvents: [String] = []
    /// URLs not fetched because they are out of scope.
    public var outOfScope: [String] = []
    /// URLs skipped by the destructive guard, the exclude pattern or robots.
    public var excluded: [String] = []
    /// Why the crawl ended (`done`, `max pages`, `max time`, `cancelled`, `session not established`).
    public var stopReason = "done"
    /// Wall-clock seconds.
    public var seconds = 0.0

    /// An empty report.
    public init() {}
}

/// Live crawl events.
public enum CrawlEvent: Sendable {
    /// A page was fetched.
    case page(CrawledPage)
    /// A new form was found.
    case form(HTMLForm)
    /// A URL was not fetched (reason: `out_of_scope`, `excluded`, `robots`, `budget`).
    case skipped(url: String, reason: String)
    /// A re-authentication event.
    case auth(String)
    /// The crawl ended.
    case finished(CrawlReport)
}

/// A request waiting in the frontier.
struct FrontierItem: Sendable {
    var method: String
    var url: CrawlURL
    var body: String?
    var depth: Int
    var source: LinkSource
    var referer: String?
}

/// Sends a request and returns the result (the workspace passes the engine, recorded as Crawler).
public typealias CrawlSender = @Sendable (RawRequest, HTTPTarget) async -> ExchangeResult

/// A static crawl.
public actor Crawler {
    /// The configuration.
    public let config: CrawlConfig
    private let send: CrawlSender
    private let inScope: @Sendable (HTTPTarget, String) async -> Bool
    private let session: (any CrawlSessionHandler)?
    private var high: [FrontierItem] = []
    private var low: [FrontierItem] = []
    private var seen: Set<String> = []
    private var perDirectory: [String: Int] = [:]
    private var structures: [Int: Int] = [:]
    private var formKeys: Set<String> = []
    private var parameters: [String: CrawlParameter] = [:]
    private var cookies: [String: [String: String]] = [:]
    private var robots: [String: RobotsHints] = [:]
    private var report = CrawlReport()
    private var fetched = 0
    private var inFlight = 0
    private var paused = false
    private var stopReason: String?
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var failedLogins = 0
    private var started = ContinuousClock.now
    private var task: Task<Void, Never>?
    private var excludeRegex: NSRegularExpression?

    /// A crawl sending through `send`; `inScope` decides every request (CRL-001: strict).
    public init(
        config: CrawlConfig, send: @escaping CrawlSender,
        inScope: @escaping @Sendable (HTTPTarget, String) async -> Bool,
        session: (any CrawlSessionHandler)? = nil
    ) {
        self.config = config
        self.send = send
        self.inScope = inScope
        self.session = session
        excludeRegex =
            config.exclude.isEmpty
            ? nil : try? NSRegularExpression(pattern: config.exclude, options: [.caseInsensitive])
    }

    // MARK: control

    /// Start; events stream until the crawl ends.
    public func start() -> AsyncStream<CrawlEvent> {
        let (stream, continuation) = AsyncStream.makeStream(of: CrawlEvent.self, bufferingPolicy: .unbounded)
        started = .now
        task = Task {
            await self.seed(continuation)
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<max(1, self.config.concurrency) {
                    group.addTask { await self.lane(continuation) }
                }
            }
            let report = await self.finish()
            continuation.yield(.finished(report))
            continuation.finish()
        }
        continuation.onTermination = { [weak self] _ in Task { await self?.cancel() } }
        return stream
    }

    /// Pause after the requests in flight.
    public func pause() { paused = true }

    /// Resume.
    public func resume() {
        paused = false
        wakeAll()
    }

    /// Stop.
    public func cancel() {
        if stopReason == nil { stopReason = "cancelled" }
        resume()
        task?.cancel()
    }

    /// Whether the crawl is paused.
    public var isPaused: Bool { paused }

    /// Progress: pages fetched, queued, in flight.
    public var progress: (fetched: Int, queued: Int, inFlight: Int) {
        (fetched, high.count + low.count, inFlight)
    }

    private func wakeAll() {
        let woken = waiters
        waiters = []
        for waiter in woken { waiter.resume() }
    }

    func finish() -> CrawlReport {
        report.stopReason = stopReason ?? "done"
        let elapsed = ContinuousClock.now - started
        report.seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        report.parameters = parameters.values.sorted { ($0.location, $0.name) < ($1.location, $1.name) }
        return report
    }

    // MARK: frontier

    /// Seeds, then robots.txt and sitemap.xml per seed origin (CRL-005).
    func seed(_ continuation: AsyncStream<CrawlEvent>.Continuation) async {
        var origins: [CrawlURL] = []
        for seed in config.seeds {
            guard let url = CrawlURL(seed) else {
                report.errors.append("\(seed): not an http(s) URL")
                continue
            }
            await enqueue(FrontierItem(method: "GET", url: url, depth: 0, source: .anchor), continuation)
            if !origins.contains(where: {
                $0.scheme == url.scheme && $0.host == url.host && $0.port == url.port
            }) {
                origins.append(url)
            }
        }
        guard config.useRobotsAndSitemap else { return }
        for origin in origins {
            var robotsURL = origin
            robotsURL.path = "/robots.txt"
            robotsURL.query = nil
            if let text = await fetchText(robotsURL, continuation), !text.isEmpty {
                let hints = RobotsHints(text)
                robots[origin.authority + origin.scheme.rawValue] = hints
                for path in hints.hintPaths {
                    var url = origin
                    url.path = path
                    url.query = nil
                    await enqueue(
                        FrontierItem(method: "GET", url: url, depth: 1, source: .robots), continuation)
                }
                for sitemap in hints.sitemaps { await addSitemap(sitemap, origin: origin, continuation) }
            }
            var sitemapURL = origin
            sitemapURL.path = "/sitemap.xml"
            sitemapURL.query = nil
            await addSitemap(sitemapURL.string, origin: origin, continuation)
        }
    }

    func addSitemap(_ address: String, origin: CrawlURL, _ continuation: AsyncStream<CrawlEvent>.Continuation)
        async
    {
        guard let url = CrawlURL(address), let text = await fetchText(url, continuation) else { return }
        for loc in PageParser.sitemapURLs(text) {
            guard let page = CrawlURL(loc) else { continue }
            await enqueue(FrontierItem(method: "GET", url: page, depth: 1, source: .sitemap), continuation)
        }
    }

    /// Fetch a hint file (counted as a page; scope applies). Nil unless it returned 200.
    func fetchText(_ url: CrawlURL, _ continuation: AsyncStream<CrawlEvent>.Continuation) async -> String? {
        let key = "GET " + url.key(config.normalization)
        guard seen.insert(key).inserted, await inScope(url.target, url.requestTarget),
            fetched < config.maxPages
        else {
            return nil
        }
        fetched += 1
        let result = await send(
            request(for: FrontierItem(method: "GET", url: url, depth: 0, source: .robots)), url.target)
        let source: LinkSource = url.path.hasSuffix(".txt") ? .robots : .sitemap
        continuation.yield(
            .page(record(FrontierItem(method: "GET", url: url, depth: 0, source: source), result)))
        guard let response = result.exchange.response, response.parsed.statusCode == 200,
            let body = (try? response.decodedBody(limit: PageParser.maxBody)) ?? nil
        else { return nil }
        return String(decoding: body.rawBytes, as: UTF8.self)
    }

    /// Add a request unless seen, out of scope, excluded or over a budget.
    func enqueue(_ item: FrontierItem, _ continuation: AsyncStream<CrawlEvent>.Continuation) async {
        let key = item.method + " " + item.url.key(config.normalization) + (item.body.map { " " + $0 } ?? "")
        guard seen.insert(key).inserted else { return }
        let text = item.url.string
        noteParameters(item)
        if config.filler.isDestructive(item.url.requestTarget)
            || excludeRegex.map({ regex in
                regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
            }) == true
        {
            report.excluded.append(text)
            continuation.yield(.skipped(url: text, reason: "excluded"))
            return
        }
        guard await inScope(item.url.target, item.url.requestTarget) else {
            report.outOfScope.append(text)
            continuation.yield(.skipped(url: text, reason: "out_of_scope"))
            return
        }
        if config.obeyRobots,
            robots[item.url.authority + item.url.scheme.rawValue]?.disallows(item.url.path) == true
        {
            report.excluded.append(text)
            continuation.yield(.skipped(url: text, reason: "robots"))
            return
        }
        guard item.depth <= config.maxDepth else {
            continuation.yield(.skipped(url: text, reason: "budget"))
            return
        }
        if config.maxPerDirectory > 0 {
            let directory = item.url.authority + item.url.directory
            guard perDirectory[directory, default: 0] < config.maxPerDirectory else {
                continuation.yield(.skipped(url: text, reason: "budget"))
                return
            }
            perDirectory[directory, default: 0] += 1
        }
        if item.source == .heuristic { low.append(item) } else { high.append(item) }
        wakeAll()
    }

    func noteParameters(_ item: FrontierItem) {
        let endpoint = item.method + " " + item.url.authority + item.url.path
        func note(_ name: String, _ value: String, _ location: String) {
            let key = location + ":" + name
            var parameter =
                parameters[key] ?? CrawlParameter(name: name, location: location, endpoints: [], values: [])
            parameter.endpoints.insert(endpoint)
            if parameter.values.count < 10 { parameter.values.insert(value) }
            parameters[key] = parameter
        }
        for (name, value) in item.url.parameters { note(name, value, "query") }
        if let body = item.body, let parsed = CrawlURL("http://x/?" + body) {
            for (name, value) in parsed.parameters { note(name, value, "body") }
        }
    }

    /// The next request, waiting while paused or while requests in flight may still add work. Nil
    /// when the crawl is over for this lane.
    func next() async -> FrontierItem? {
        while true {
            if stopReason != nil || Task.isCancelled { return nil }
            if config.maxSeconds > 0, ContinuousClock.now - started > .seconds(config.maxSeconds) {
                stopReason = "max time"
                wakeAll()
                return nil
            }
            if !paused {
                let empty = high.isEmpty && low.isEmpty
                if fetched >= config.maxPages {
                    if !empty { stopReason = "max pages" }
                    wakeAll()
                    return nil
                }
                if !empty {
                    let item = high.isEmpty ? low.removeFirst() : high.removeFirst()
                    fetched += 1
                    inFlight += 1
                    return item
                }
                if inFlight == 0 {
                    wakeAll()
                    return nil
                }
            }
            await withCheckedContinuation { waiters.append($0) }
        }
    }

    func done() {
        inFlight -= 1
        wakeAll()
    }

    // MARK: fetching

    nonisolated func lane(_ continuation: AsyncStream<CrawlEvent>.Continuation) async {
        while let item = await next() {
            await fetch(item, continuation)
            await done()
        }
    }

    func request(for item: FrontierItem) -> RawRequest {
        var lines = [
            "\(item.method) \(item.url.requestTarget) HTTP/1.1", "Host: \(item.url.authority)",
            "User-Agent: \(config.userAgent)",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ]
        if let referer = item.referer { lines.append("Referer: \(referer)") }
        if let jar = cookies[item.url.host], !jar.isEmpty {
            lines.append(
                "Cookie: "
                    + jar.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "; "))
        }
        var body: [UInt8] = []
        if let text = item.body {
            body = Array(text.utf8)
            lines.append("Content-Type: application/x-www-form-urlencoded")
            lines.append("Content-Length: \(body.count)")
        }
        return RawRequest(Bytes(Array((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8) + body))
    }

    func fetch(_ item: FrontierItem, _ continuation: AsyncStream<CrawlEvent>.Continuation) async {
        var result = await send(request(for: item), item.url.target)
        // CRL-006: a lost session → log in again and retry once.
        if let session, await session.isLoggedOut(result.exchange) {
            report.authEvents.append("logged out at \(item.url.string)")
            continuation.yield(.auth("logged out at \(item.url.string)"))
            if await session.reauthenticate() {
                failedLogins = 0
                report.authEvents.append("re-authenticated")
                continuation.yield(.auth("re-authenticated"))
                result = await send(request(for: item), item.url.target)
            } else {
                failedLogins += 1
                report.authEvents.append("re-authentication failed")
                continuation.yield(.auth("re-authentication failed"))
                if failedLogins >= 3 {
                    stopReason = "session not established"
                    wakeAll()
                }
            }
        }
        let page = record(item, result)
        continuation.yield(.page(page))
        guard let response = result.exchange.response else { return }
        storeCookies(response, host: item.url.host)
        let parsed = PageParser.parse(response, pageURL: item.url.string)
        // CRL-007: past N pages with the same structure, stop following their links.
        if let hash = parsed.structureHash, config.similarPages > 0 {
            structures[hash, default: 0] += 1
            if structures[hash, default: 0] > config.similarPages { return }
        }
        let depth = item.depth + 1
        for link in parsed.links {
            guard let url = CrawlURL(link.url) else { continue }
            await enqueue(
                FrontierItem(
                    method: "GET", url: url, depth: depth, source: link.source, referer: item.url.string),
                continuation)
        }
        for form in parsed.forms {
            let formKey =
                form.method + " " + form.action + " " + form.fields.map(\.name).joined(separator: ",")
            if formKeys.insert(formKey).inserted {
                report.forms.append(form)
                continuation.yield(.form(form))
            }
            guard config.filler.shouldSubmit(form, policy: config.forms), var url = CrawlURL(form.action)
            else { continue }
            let encoded = FormFiller.encode(config.filler.values(for: form))
            if form.method == "GET" {
                url.query = encoded.isEmpty ? nil : encoded
                await enqueue(
                    FrontierItem(
                        method: "GET", url: url, depth: depth, source: .form, referer: item.url.string),
                    continuation)
            } else {
                await enqueue(
                    FrontierItem(
                        method: "POST", url: url, body: encoded, depth: depth, source: .form,
                        referer: item.url.string),
                    continuation)
            }
            if form.method == "GET" || config.forms == .all { report.formsSubmitted += 1 }
        }
    }

    @discardableResult
    func record(_ item: FrontierItem, _ result: ExchangeResult) -> CrawledPage {
        let page = CrawledPage(
            method: item.method, url: item.url.string, status: result.exchange.response?.parsed.statusCode,
            exchangeID: result.exchange.id, depth: item.depth, source: item.source)
        report.pages.append(page)
        if let error = result.error { report.errors.append("\(item.url.string): \(error.code)") }
        return page
    }

    func storeCookies(_ response: RawResponse, host: String) {
        for field in response.parsed.headers
        where response.bytes[field.name].string().lowercased() == "set-cookie" {
            let value = response.bytes[field.value].string()
            let pair = value.split(separator: ";", maxSplits: 1).first ?? ""
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let name = parts[0].trimmingCharacters(in: .whitespaces)
            let cookieValue = parts[1].trimmingCharacters(in: .whitespaces)
            if value.lowercased().contains("max-age=0") || cookieValue.isEmpty {
                cookies[host]?[name] = nil
            } else {
                cookies[host, default: [:]][name] = cookieValue
            }
        }
    }
}
