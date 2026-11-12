// GulpWorkspace — "Crawl and audit" (F09 + F08 SCN-035, M11c) and "scan the whole API" (ADV-050).
// Crawl and audit runs a static crawl, picks the distinct requests it made (one per method, normalized
// path and parameter names; static assets skipped), then actively scans them with the same scope,
// limiter and issue recording as any scan. The API scan builds one request per operation of an
// OpenAPI document and scans them all, reporting which operations were covered.

import Foundation
import GulpCodec
import GulpCore
import GulpCrawler
import GulpScanner

/// Events of a crawl-and-audit task.
public enum CrawlAuditEvent: Sendable {
    /// A crawl event.
    case crawl(CrawlEvent)
    /// The crawl ended; this many distinct requests will be audited.
    case auditStarted(requests: Int)
    /// A scan event (findings are already recorded as issues).
    case scan(ScanEvent)
}

/// A started crawl-and-audit task.
public struct CrawlAuditRun: Sendable {
    /// Events: crawl events, `.auditStarted`, then scan events ending with `.scan(.finished)`.
    public let events: AsyncStream<CrawlAuditEvent>
    /// Stop the crawl or the scan, whichever is running.
    public let cancel: @Sendable () async -> Void
}

/// One API operation and whether a scan covered it.
public struct APIScanCoverage: Sendable, Hashable {
    /// `GET /api/users/{id}` as built.
    public var operation: String
    /// Insertion points tested.
    public var points: Int
}

/// Picks the requests worth auditing from crawled exchanges.
public enum AuditSelection {
    /// File extensions that are never audited (static assets).
    public static let staticExtensions: Set<String> = [
        "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "css", "woff", "woff2", "ttf", "eot", "map", "mp4",
        "mp3", "pdf", "zip",
    ]

    /// Distinct requests among `exchanges`: one per method, normalized path and sorted parameter
    /// names; static assets and failed exchanges are dropped.
    public static func distinct(_ exchanges: [Exchange]) -> [(request: RawRequest, target: HTTPTarget)] {
        var seen: Set<String> = []
        var picked: [(request: RawRequest, target: HTTPTarget)] = []
        for exchange in exchanges where exchange.response != nil {
            let derived = DerivedFields(target: exchange.target, request: exchange.request, response: nil)
            let path = derived.path ?? "/"
            let ext = path.split(separator: ".").last.map { $0.lowercased() } ?? ""
            guard !(path.contains(".") && staticExtensions.contains(ext)) else { continue }
            let names = InsertionPoints.derive(exchange.request).filter {
                $0.kind != .header && $0.kind != .cookie
            }
            .map(\.label).sorted()
            let key = [
                derived.method ?? "GET", Issue.origin(exchange.target), Issue.normalizedPath(path),
                names.joined(separator: ","),
            ].joined(separator: " ")
            guard seen.insert(key).inserted else { continue }
            picked.append((exchange.request, exchange.target))
        }
        return picked
    }
}

/// Holds the running crawler or scan so the task can be cancelled from outside.
actor CrawlAuditHandle {
    var crawler: Crawler?
    var scan: ActiveScan?
    var cancelled = false

    func set(_ crawler: Crawler) { self.crawler = crawler }
    func set(_ scan: ActiveScan) { self.scan = scan }

    func cancel() async {
        cancelled = true
        await crawler?.cancel()
        await scan?.cancel()
    }
}

extension ProjectSession {
    /// Crawl from `crawl`'s seeds, then actively scan the distinct requests the crawl made
    /// (SCN-035's "Crawl and audit").
    public func startCrawlAndAudit(
        crawl: CrawlConfig, scan config: ScanConfig, allowOutOfScope: Bool = false
    ) async -> CrawlAuditRun {
        let handle = CrawlAuditHandle()
        let (events, continuation) = AsyncStream.makeStream(
            of: CrawlAuditEvent.self, bufferingPolicy: .unbounded)
        let crawlRun = await startCrawl(crawl, allowOutOfScope: allowOutOfScope)
        await handle.set(crawlRun.crawler)
        let store = self.store
        Task {
            var ids: [ExchangeID] = []
            for await event in crawlRun.events {
                if case .page(let page) = event, page.exchangeID != 0 { ids.append(page.exchangeID) }
                continuation.yield(.crawl(event))
            }
            guard await !handle.cancelled else {
                continuation.finish()
                return
            }
            await store.writer.flush()
            let exchanges = (try? await store.exchanges(ids: ids)) ?? []
            let requests = AuditSelection.distinct(exchanges)
            continuation.yield(.auditStarted(requests: requests.count))
            let scanRun = await self.startActiveScan(
                requests, config: config, allowOutOfScope: allowOutOfScope,
                name: "Crawl and audit (\(crawl.seeds.first ?? ""))")
            await handle.set(scanRun.scan)
            for await event in scanRun.events { continuation.yield(.scan(event)) }
            continuation.finish()
        }
        return CrawlAuditRun(events: events, cancel: { await handle.cancel() })
    }

    /// Requests for every operation of an OpenAPI document (ADV-050), ready to scan.
    public nonisolated func apiScanRequests(_ document: Data, baseURL: String?) throws -> [(
        request: RawRequest, target: HTTPTarget
    )] {
        try OpenAPIImport.read(document, baseURL: baseURL).exchanges.map { ($0.request, $0.target) }
    }

    /// Each operation's label and how many insertion points a scan with `config` tests in it.
    public nonisolated func apiCoverage(
        _ requests: [(request: RawRequest, target: HTTPTarget)], config: ScanConfig
    )
        -> [APIScanCoverage]
    {
        requests.map { item in
            let derived = DerivedFields(target: item.target, request: item.request, response: nil)
            return APIScanCoverage(
                operation: "\(derived.method ?? "GET") \(derived.path ?? "/")",
                points: InsertionPoints.derive(item.request, policy: config.insertion).count)
        }
    }
}
