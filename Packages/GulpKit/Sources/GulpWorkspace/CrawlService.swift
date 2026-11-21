// GulpWorkspace — crawls in a project (F09 CRL-001…CRL-010, static mode). The crawl sends through the
// session's engine as Crawler traffic (recorded, so the site map fills; governed by the shared
// limiter, so the panic stop pauses it), and every request passes ScopeGuard (strict: an empty
// scope allows nothing) unless the user overrides it for this crawl.

import Foundation
import GulpCore
import GulpCrawler
import GulpHTTP

/// A started crawl.
public struct CrawlRun: Sendable {
    /// Pause/resume/cancel, progress.
    public let crawler: Crawler
    /// Events, then `.finished` with the report.
    public let events: AsyncStream<CrawlEvent>
}

extension ProjectSession {
    /// Start a static crawl (CRL-001). `session` is the CRL-006 hook (session rules land in M12a).
    public func startCrawl(
        _ config: CrawlConfig, allowOutOfScope: Bool = false, session: (any CrawlSessionHandler)? = nil
    ) async -> CrawlRun {
        let engine = http
        let timeout = config.timeoutSeconds
        let send: CrawlSender = { request, target in
            var options = SendOptions(recordAs: .crawler)
            options.timeouts.total = .seconds(timeout)
            return await engine.send(request, to: target, options: options)
        }
        let scopeGuard = self.scopeGuard
        let inScope: @Sendable (HTTPTarget, String) async -> Bool
        if allowOutOfScope {
            inScope = { @Sendable _, _ in true }
        } else {
            inScope = { @Sendable target, path in await scopeGuard.permits(target, path: path) }
        }
        let crawler = Crawler(config: config, send: send, inScope: inScope, session: session)
        let source = await crawler.start()
        let (events, continuation) = AsyncStream.makeStream(of: CrawlEvent.self, bufferingPolicy: .unbounded)
        let tasks = activeTasks
        let taskID = UUID()
        await tasks.add(
            ActiveTask(
                id: taskID, kind: "crawler", name: config.seeds.first ?? "crawl",
                pause: { await crawler.pause() },
                resume: { await crawler.resume() }, cancel: { await crawler.cancel() }))
        let writer = store.writer
        Task {
            for await event in source {
                if case .finished = event { await writer.flush() }
                continuation.yield(event)
            }
            await tasks.remove(taskID)
            continuation.finish()
        }
        continuation.onTermination = { _ in Task { await crawler.cancel() } }
        return CrawlRun(crawler: crawler, events: events)
    }
}
