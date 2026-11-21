// gulp-cli — M11a headless: `crawl` (static crawler, F09), `oast` (Beacon/interactsh, F10) and
// `governor` (the shared limiter's settings and the panic stop, F03 §3.4 / F20 GOV-001). The
// `governor` drills run two active tools at once in one session — the shared limiter is per process
// — and print measurements the M11a DoD checks.

import ArgumentParser
import Foundation
import GulpCore
import GulpCrawler
import GulpFuzzer
import GulpHTTP
import GulpOAST
import GulpStore
import GulpWorkspace

/// Print the OAST interactions `exchange` caused, after polling for up to `wait` seconds.
func printOASTInteractions(_ session: ProjectSession, exchange: ExchangeID, wait: Double) async {
    await session.oast.drain(timeout: .seconds(wait), quiet: .seconds(min(2, wait)))
    let interactions = (try? await session.store.oastInteractions(forExchange: exchange)) ?? []
    print("oast: \(interactions.count) interaction(s) for exchange #\(exchange)")
    for interaction in interactions {
        print(
            "  \(interaction.proto)\t\(interaction.remoteAddress)\t\(interaction.uniqueID)\t\(interaction.summary)"
        )
    }
}

/// `gulp-cli crawl --project p.gulp --seed http://host/ …` (F09 static mode).
struct CrawlCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "crawl",
        abstract: "Crawl from seed URLs (static mode); pages are recorded and fill the site map.")

    @Option(help: "Project file (created if missing).") var project: String
    @Option(help: "A start URL (repeatable).") var seed: [String] = []
    @Option(help: "Max link depth from a seed.") var maxDepth = 10
    @Option(help: "Max pages.") var maxPages = 1_000
    @Option(help: "Max pages per directory (0: unlimited).") var maxPerDirectory = 200
    @Option(help: "Max seconds (0: unlimited).") var maxSeconds: Double = 0
    @Option(help: "Parallel requests.") var concurrency = 8
    @Option(help: "Forms: none, get (default) or all (\"submit forms\" mode: POST forms too).") var forms =
        "get"
    @Flag(help: "Skip paths robots.txt disallows (off by default for authorized testing).") var obeyRobots =
        false
    @Flag(help: "Don't read robots.txt and sitemap.xml.") var noHints = false
    @Option(help: "Skip URLs matching this regex.") var exclude = ""
    @Flag(help: "Crawl even out of scope (explicit override).") var allowOutOfScope = false
    @Flag(help: "Print every page fetched.") var pages = false

    func run() async throws {
        guard !seed.isEmpty else { throw ValidationError("Give at least one --seed") }
        guard let policy = FormPolicy(rawValue: forms) else {
            throw ValidationError("Unknown --forms \(forms)")
        }
        var config = CrawlConfig(
            seeds: seed, maxDepth: maxDepth, maxPages: maxPages, maxPerDirectory: maxPerDirectory,
            maxSeconds: maxSeconds,
            concurrency: concurrency, forms: policy, useRobotsAndSitemap: !noHints, obeyRobots: obeyRobots)
        config.exclude = exclude
        let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
        let run = await session.startCrawl(config, allowOutOfScope: allowOutOfScope)
        var report = CrawlReport()
        for await event in run.events {
            switch event {
            case .page(let page) where pages:
                print(
                    "\(page.status.map(String.init) ?? "-")\t\(page.method)\t\(page.url)\t\(page.source.rawValue)"
                )
            case .finished(let done): report = done
            default: break
            }
        }
        print(Self.summary(report))
        for url in report.outOfScope { print("out of scope: \(url)") }
        for url in report.excluded { print("excluded: \(url)") }
        for form in report.forms {
            print("form: \(form.method) \(form.action) [\(form.fields.map(\.name).joined(separator: ","))]")
        }
        for parameter in report.parameters {
            print(
                "parameter: \(parameter.location) \(parameter.name) (\(parameter.endpoints.count) endpoint(s))"
            )
        }
        for error in report.errors { print("error: \(error)") }
        try await session.close()
    }

    static func summary(_ report: CrawlReport) -> String {
        String(
            format:
                "crawl: %d pages, %d forms (%d submitted), %d parameters, %d errors, %d out of scope, %d excluded in %.2f s (%@)",
            report.pages.count, report.forms.count, report.formsSubmitted, report.parameters.count,
            report.errors.count,
            report.outOfScope.count, report.excluded.count, report.seconds, report.stopReason)
    }
}

/// `gulp-cli oast …` (F10).
struct OASTCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "oast",
        abstract:
            "Configure OAST (dev Beacon or interactsh), mint payloads, test the loop, list interactions.",
        subcommands: [Configure.self, Payload.self, Test.self, List.self])

    struct Configure: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Set the OAST server (off by default) and register.")
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "Server URL, e.g. http://127.0.0.1:8090 (the dev Beacon) or an interactsh server.")
        var server: String?
        @Option(help: "Payload domain (default: the server's host; the dev Beacon uses oast.test).")
        var domain = ""
        @Option(
            help: "Where \"test\" connects for payload hosts (host:port) when the domain doesn't resolve.")
        var connectTo: String?
        @Option(
            help:
                "The server's token (kept in the secret store: the Keychain on macOS, a 0600 file elsewhere; or GULP_OAST_TOKEN)."
        )
        var token: String?
        @Option(help: "Background poll interval in seconds.") var poll: Double = 5
        @Flag(help: "Confirm that a public, third-party server will see the interactions.") var thirdParty =
            false
        @Flag(help: "Turn OAST off.") var off = false

        func run() async throws {
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            var settings = session.settings.get(OASTSettings.self)
            if off {
                settings.enabled = false
            } else {
                guard let server else { throw ValidationError("Give --server (or --off)") }
                settings = OASTSettings(
                    enabled: true, serverURL: server, domain: domain, pollSeconds: poll, connectTo: connectTo,
                    thirdPartyAcknowledged: thirdParty || settings.thirdPartyAcknowledged)
                if !settings.isLocal && !settings.thirdPartyAcknowledged {
                    try await session.close()
                    throw ValidationError(
                        "\(server) is not a local server: interactions will be visible to its operator. Re-run with --third-party to confirm."
                    )
                }
            }
            do {
                try await session.configureOAST(settings, token: token)
            } catch {
                try? await session.close()
                throw ValidationError("OAST: \(error)")
            }
            let health = await session.oast.currentHealth
            print(
                off ? "oast: off" : "oast: registered with \(health.server), payload domain \(health.domain)")
            try await session.close()
        }
    }

    struct Payload: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Mint a payload for manual use (BCN-007).")
        @Option(help: "Project file.") var project: String
        @Option(help: "A note stored with it.") var note: String?

        func run() async throws {
            let session = try await openSession(project)
            let payload = try await session.oast.mint(OASTContext(tool: "manual", note: note))
            print(
                "host: \(payload.host)\nhttp: \(payload.httpURL)\nhttps: \(payload.httpsURL)\nemail: \(payload.email)"
            )
            try await session.close()
        }
    }

    struct Test: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract:
                "Test Beacon (BCN-006): send a payload to the server from Gulp and wait for the interaction.")
        @Option(help: "Project file.") var project: String
        @Option(help: "Seconds to wait.") var wait: Double = 15

        func run() async throws {
            let session = try await openSession(project)
            let result = try await session.oast.test(timeout: .seconds(wait))
            let health = await session.oast.currentHealth
            if result.ok {
                print(
                    String(
                        format: "oast test: ok in %.2f s (%@) via %@", result.seconds,
                        result.protocols.joined(separator: ","), result.payload.host))
            } else {
                print("oast test: failed — \(result.problem ?? "no interaction")")
            }
            print(
                "health: registered \(health.registered), \(health.payloads) payload(s), \(health.interactions) interaction(s), last poll \(health.lastPoll.map { "\($0)" } ?? "never")"
            )
            try await session.close()
            if !result.ok { throw ExitCode(2) }
        }
    }

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List stored interactions, newest first.")
        @Option(help: "Project file.") var project: String

        func run() async throws {
            let session = try await openSession(project)
            let interactions = try await session.store.oastInteractions()
            print("interactions: \(interactions.count)")
            for item in interactions {
                let origin =
                    item.payload.map {
                        "\($0.context.tool) exchange #\($0.exchangeID.map(String.init) ?? "-")"
                    } ?? "unknown payload"
                print(
                    "\(item.id)\t\(item.proto)\t\(item.remoteAddress)\t\(item.uniqueID)\t\(origin)\t\(item.summary)"
                )
            }
            try await session.close()
        }
    }
}

/// `gulp-cli governor …`: limiter settings and the drills (F03 tests 6–7, F20 test 5).
struct GovernorCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "governor",
        abstract: "Network caps for active tools, and drills that measure them and the panic stop.",
        subcommands: [Set.self, CapsDrill.self, BackoffDrill.self, PanicDrill.self])

    struct Set: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Show or change the project's network caps.")
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "Global requests/second (0: none).") var globalRps: Double?
        @Option(help: "Per-host requests/second (0: none).") var hostRps: Double?
        @Option(help: "Global concurrency for active tools (0: unlimited).") var globalConcurrency: Int?
        @Option(help: "Per-host concurrency for active tools (0 blocks the host).") var hostConcurrency: Int?
        @Option(help: "Adaptive backoff: on or off.") var backoff: String?

        func run() async throws {
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            var settings = session.settings.get(NetworkSettings.self)
            if let globalRps { settings.rates.globalPerSecond = globalRps }
            if let hostRps { settings.rates.perHostPerSecond = hostRps }
            if let globalConcurrency {
                settings.concurrency.global = globalConcurrency == 0 ? nil : globalConcurrency
            }
            if let hostConcurrency { settings.concurrency.perHost = hostConcurrency }
            if let backoff { settings.concurrency.adaptiveBackoff = backoff == "on" }
            try await session.setNetworkSettings(settings)
            print(
                "network: \(settings.rates.globalPerSecond) req/s global, \(settings.rates.perHostPerSecond) req/s per host, "
                    + "concurrency \(settings.concurrency.global.map(String.init) ?? "∞") global / "
                    + "\(settings.concurrency.perHost.map(String.init) ?? "∞") per host, backoff \(settings.concurrency.adaptiveBackoff ? "on" : "off")"
            )
            try await session.close()
        }
    }

    /// Samples the limiter every 50 ms: the max requests granted in any 1-second window and the peak
    /// concurrency per host.
    actor Sampler {
        var samples: [(at: ContinuousClock.Instant, granted: Int)] = []
        func add(_ granted: Int) { samples.append((.now, granted)) }
        /// The highest number of grants within any window of `window` (requests per window).
        func maxRate(window: Duration = .seconds(1)) -> Int {
            var best = 0
            var start = 0
            for end in samples.indices {
                while samples[end].at - samples[start].at > window { start += 1 }
                best = max(best, samples[end].granted - samples[start].granted)
            }
            return best
        }
        /// Grants per `bucket`, in order.
        func rates(bucket: Duration) -> [Double] {
            guard let first = samples.first else { return [] }
            var out: [Double] = []
            var bucketStart = first
            for sample in samples where sample.at - bucketStart.at >= bucket {
                let seconds =
                    Double((sample.at - bucketStart.at).components.attoseconds) / 1e18
                    + Double((sample.at - bucketStart.at).components.seconds)
                out.append(Double(sample.granted - bucketStart.granted) / seconds)
                bucketStart = sample
            }
            return out
        }
    }

    static func sample(
        _ session: ProjectSession, into sampler: Sampler, while running: @escaping @Sendable () async -> Bool
    ) -> Task<Void, Never> {
        Task {
            while await running() {
                await sampler.add(await session.http.resources.granted)
                try? await Task.sleep(for: .milliseconds(50))
            }
            await sampler.add(await session.http.resources.granted)
        }
    }

    static func fuzzConfig(
        _ target: HTTPTarget, path: String, payloads: [String], concurrency: Int, rps: Double?
    ) -> FuzzAttackConfig {
        var settings = FuzzSettings()
        settings.concurrency = concurrency
        settings.requestsPerSecond = rps
        settings.timeoutSeconds = 30
        let request = Array("GET \(path) HTTP/1.1\r\nHost: \(target.host):\(target.port)\r\n\r\n".utf8)
        return FuzzAttackConfig(
            name: "drill", target: target, request: request, attackType: .sniper,
            sets: [PayloadSet(.list(payloads))],
            settings: settings)
    }

    struct CapsDrill: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract:
                "F03 test 6: a 2,000 req/s fuzz plus a crawl under a global rate cap; then both on slow pages under a per-host concurrency budget."
        )
        @Option(help: "Project file (scope must include the target).") var project: String
        @Option(help: "Target origin, e.g. http://127.0.0.1:8088.") var target: String
        @Option(help: "Global requests/second cap.") var globalRps: Double = 1_000
        @Option(help: "Per-host concurrency budget.") var hostConcurrency = 50
        @Option(help: "Fuzz requests in the rate phase.") var requests = 5_000

        func run() async throws {
            guard let destination = HTTPTarget(url: target) else { throw ValidationError("Invalid --target") }
            let session = try await openSession(project)
            var settings = session.settings.get(NetworkSettings.self)
            settings.rates.globalPerSecond = globalRps
            settings.concurrency.perHost = hostConcurrency
            settings.concurrency.adaptiveBackoff = false
            try await session.setNetworkSettings(settings)

            // Rate: a fuzz asking for 2,000 req/s with 64 lanes, and a crawl of the same host, at once.
            let fuzz = try await session.startAttack(
                GovernorCommand.fuzzConfig(
                    destination, path: "/echo?n=§x§", payloads: (1...requests).map(String.init),
                    concurrency: 64, rps: 2_000))
            let crawl = await session.startCrawl(CrawlConfig(seeds: [target + "/"], concurrency: 8))
            let sampler = Sampler()
            let done = Done()
            let sampling = GovernorCommand.sample(session, into: sampler) { await !done.value }
            async let fuzzed: Int = {
                var n = 0; for await event in fuzz.events { if case .result = event { n += 1 } }; return n
            }()
            async let crawled: Int = {
                var n = 0; for await event in crawl.events { if case .page = event { n += 1 } }; return n
            }()
            let (fuzzCount, crawlCount) = await (fuzzed, crawled)
            await done.set()
            await sampling.value
            let rate = await sampler.maxRate()
            print("caps: rate phase: fuzz \(fuzzCount) requests, crawl \(crawlCount) pages")
            print("caps: max \(rate) requests in any 1 s (cap \(Int(globalRps)))")

            // Concurrency: 100 fuzz lanes and a 30-lane crawl of slow pages want 130 in flight at once.
            await session.http.resources.resetPeaks()
            let slowFuzz = try await session.startAttack(
                GovernorCommand.fuzzConfig(
                    destination, path: "/slow?ms=400&n=§x§", payloads: (1...400).map(String.init),
                    concurrency: 100, rps: nil))
            let slowCrawl = await session.startCrawl(
                CrawlConfig(seeds: [target + "/crawl/slow/"], concurrency: 30, useRobotsAndSitemap: false))
            let overlap = Flag()
            let watching = Task {
                // Both tools have requests in flight at the same moment.
                while await !overlap.value {
                    let fuzzBusy = await slowFuzz.attack.progress.sent < 400
                    let crawlBusy = await slowCrawl.crawler.progress.inFlight > 0
                    if fuzzBusy && crawlBusy { await overlap.set() }
                    try? await Task.sleep(for: .milliseconds(20))
                }
            }
            async let slowFuzzed: Int = {
                var n = 0; for await event in slowFuzz.events { if case .result = event { n += 1 } }; return n
            }()
            async let slowCrawled: Int = {
                var n = 0; for await event in slowCrawl.events { if case .page = event { n += 1 } }; return n
            }()
            let (slowFuzzCount, slowCrawlCount) = await (slowFuzzed, slowCrawled)
            await overlap.set()
            await watching.value
            let peaks = await session.http.resources.peaks
            let peak = peaks.byHost[destination.host.lowercased()] ?? 0
            print(
                "caps: concurrency phase: fuzz \(slowFuzzCount) requests, crawl \(slowCrawlCount) pages, both in flight at once: \(await overlap.value)"
            )
            print("caps: peak in flight to \(destination.host): \(peak) (budget \(hostConcurrency))")
            try await session.close()
        }
    }

    struct BackoffDrill: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract:
                "F03 test 7: a 503 burst drives a host's rate down and flips the throttled badge, then it recovers."
        )
        @Option(help: "Project file (scope must include the target).") var project: String
        @Option(help: "Target origin, e.g. http://127.0.0.1:8088.") var target: String
        @Option(help: "The fuzz's own rate (requests/second).") var rps: Double = 300

        func run() async throws {
            guard let destination = HTTPTarget(url: target) else { throw ValidationError("Invalid --target") }
            let session = try await openSession(project)
            var settings = session.settings.get(NetworkSettings.self)
            settings.concurrency.adaptiveBackoff = true
            settings.rates = .none
            try await session.setNetworkSettings(settings)
            // 1.5 s of 200s, a 2 s burst of 503s, then 200s again (time-boxed by VulnLab, so a backed-off
            // rate doesn't stretch the burst).
            let key = UUID().uuidString
            let fuzz = try await session.startAttack(
                GovernorCommand.fuzzConfig(
                    destination, path: "/lab/burst?key=\(key)&ok=1500&bad=2000&n=§x§",
                    payloads: (1...Int(rps * 9)).map(String.init), concurrency: 20, rps: rps))
            let sampler = Sampler()
            let done = Done()
            let throttled = Flag()
            let sampling = GovernorCommand.sample(session, into: sampler) { await !done.value }
            let watching = Task {
                while await !done.value {
                    if await !session.http.resources.throttledHosts.isEmpty { await throttled.set() }
                    try? await Task.sleep(for: .milliseconds(50))
                }
            }
            for await _ in fuzz.events {}
            await done.set()
            await sampling.value
            await watching.value
            let rates = await sampler.rates(bucket: .milliseconds(500)).map { Int($0) }
            let stillThrottled = await !session.http.resources.throttledHosts.isEmpty
            let first = rates.prefix(2).max() ?? 0
            let lowest = rates.dropFirst(2).min() ?? 0
            let last = rates.suffix(2).max() ?? 0
            print("backoff: rate per 0.5 s: \(rates.map(String.init).joined(separator: " "))")
            print("backoff: before \(first)/s, lowest \(lowest)/s, at the end \(last)/s")
            print(
                "backoff: throttled badge seen \(await throttled.value), throttled at the end \(stillThrottled)"
            )
            try await session.close()
        }
    }

    struct PanicDrill: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract:
                "F20 test 5: the panic stop during a crawl + fuzz leaves zero requests in flight; resume finishes both."
        )
        @Option(help: "Project file (scope must include the target).") var project: String
        @Option(help: "Target origin, e.g. http://127.0.0.1:8088.") var target: String

        func run() async throws {
            guard let destination = HTTPTarget(url: target) else { throw ValidationError("Invalid --target") }
            let session = try await openSession(project)
            let fuzz = try await session.startAttack(
                GovernorCommand.fuzzConfig(
                    destination, path: "/slow?ms=300&n=§x§", payloads: (1...300).map(String.init),
                    concurrency: 20, rps: nil))
            // Slow pages, so the crawl is still running when the panic stop hits.
            let crawl = await session.startCrawl(
                CrawlConfig(seeds: [target + "/crawl/slow/"], concurrency: 8, useRobotsAndSitemap: false))
            async let fuzzed: (Int, Int) = {
                var results = 0
                var errors = 0
                for await event in fuzz.events {
                    if case .result(let result) = event {
                        results += 1
                        if result.error != nil { errors += 1 }
                    }
                }
                return (results, errors)
            }()
            async let crawled: Int = {
                var n = 0; for await event in crawl.events { if case .page = event { n += 1 } }; return n
            }()
            try await Task.sleep(for: .milliseconds(800))
            let before = await session.http.resources.inFlightCount.global
            let report = await session.panicStop()
            try await Task.sleep(for: .milliseconds(100))  // one limiter tick
            let after = await session.http.resources.inFlightCount.global
            let progress = await fuzz.attack.progress.sent
            try await Task.sleep(for: .seconds(1))
            let still = await session.http.resources.inFlightCount.global
            let progressLater = await fuzz.attack.progress.sent
            let crawlerPaused = await crawl.crawler.isPaused
            print(
                "panic: \(before) in flight before; cut \(report.cut); \(after) in flight after one tick; \(still) a second later"
            )
            print("panic: paused \(report.tasks.count) task(s): \(report.tasks.joined(separator: ", "))")
            print(
                "panic: fuzz sent \(progress) then \(progressLater) while paused; crawler paused \(crawlerPaused)"
            )
            await session.resumeAll()
            let (results, errors) = await fuzzed
            let pages = await crawled
            print("panic: resumed; fuzz \(results) of 300 results (\(errors) errors), crawl \(pages) pages")
            try await session.close()
        }
    }

    actor Done {
        var value = false
        func set() { value = true }
    }

    actor Flag {
        var value = false
        func set() { value = true }
    }
}
