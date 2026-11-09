// GulpWorkspace — the live site map of a project (F04 TGT-001…TGT-003): rebuilt from the store on
// open (and when scope changes, so in-scope flags follow), then extended as exchanges are recorded;
// inferred nodes come from the links in responses (LinkExtractor).

import Foundation
import GulpCore
import GulpStore

/// The site map of one project.
public actor SiteMapService {
    private var map: SiteMap
    private var lastID: ExchangeID = 0
    private let storeProvider: @Sendable () async -> ProjectStore
    private var watchers: [UUID: AsyncStream<Void>.Continuation] = [:]
    /// The last queued operation. Rebuilds and catch-ups run one at a time, in order: an actor only
    /// keeps them from running *simultaneously* — at every `await` on the store another call could
    /// otherwise interleave, and a rebuild that started earlier would overwrite a catch-up's newer
    /// map (actor reentrancy).
    private var tail: Task<Void, Never>?

    init(groupParameterized: Bool = false, store: @escaping @Sendable () async -> ProjectStore) {
        map = SiteMap(groupsParameterizedSegments: groupParameterized)
        storeProvider = store
    }

    /// The current map.
    public var snapshot: SiteMap { map }

    /// A stream that ticks whenever the map changes.
    public func changes() -> AsyncStream<Void> {
        let (stream, continuation) = AsyncStream.makeStream(
            of: Void.self, bufferingPolicy: .bufferingNewest(1))
        let id = UUID()
        watchers[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { await self?.removeWatcher(id) } }
        return stream
    }

    private func removeWatcher(_ id: UUID) { watchers[id] = nil }

    /// Fold numeric/UUID segments into `{id}` (TGT-006); rebuilds.
    public func setGroupsParameterized(_ on: Bool) async {
        await serially { service in
            guard on != service.map.groupsParameterizedSegments else { return }
            service.map = SiteMap(groupsParameterizedSegments: on)
            service.lastID = 0
            await service.performRebuild()
        }
    }

    /// Rebuild from the store: every exchange (visited) and links in recent textual responses
    /// (inferred).
    public func rebuild() async {
        await serially { await $0.performRebuild() }
    }

    /// Add exchanges recorded since the last update (called on `exchangeRecorded`).
    public func catchUp() async {
        await serially { await $0.performCatchUp() }
    }

    /// Wait until no operation is running (e.g. before the store it reads is closed).
    public func idle() async {
        await tail?.value
    }

    /// Run `operation` after every operation queued before it; cancelling the caller cancels it.
    private func serially(_ operation: @escaping @Sendable (isolated SiteMapService) async -> Void) async {
        let previous = tail
        let task = Task {
            await previous?.value
            await operation(self)
        }
        tail = task
        await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }
    }

    private func performRebuild() async {
        let store = await storeProvider()
        var fresh = SiteMap(groupsParameterizedSegments: map.groupsParameterizedSegments)
        var after: ExchangeID = 0
        while !Task.isCancelled, let page = try? await store.siteMapEntries(after: after),
            let last = page.last
        {
            for entry in page { fresh.add(entry) }
            after = last.id
            await Task.yield()
        }
        for id in (try? await store.textualResponseIDs()) ?? [] {
            if Task.isCancelled { return }
            guard let exchange = try? await store.exchange(id: id) else { continue }
            for url in Self.links(of: exchange) { fresh.addInferred(url: url) }
        }
        map = fresh
        lastID = after
        notify()
    }

    private func performCatchUp() async {
        let store = await storeProvider()
        var changed = false
        while !Task.isCancelled, let page = try? await store.siteMapEntries(after: lastID, limit: 1_000),
            let last = page.last
        {
            for entry in page {
                map.add(entry)
                if let exchange = try? await store.exchange(id: entry.id) {
                    for url in Self.links(of: exchange) { map.addInferred(url: url) }
                }
            }
            lastID = last.id
            changed = true
        }
        if changed { notify() }
    }

    static func links(of exchange: Exchange) -> [String] {
        guard let response = exchange.response else { return [] }
        let target = exchange.target
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        let page =
            "\(target.scheme.rawValue)://\(target.host)\(standard ? "" : ":\(target.port)")"
            + (exchange.derived.path ?? "/")
        return LinkExtractor.urls(in: response, pageURL: page)
    }

    private func notify() {
        for watcher in watchers.values { watcher.yield() }
    }
}

extension ProjectSession {
    /// Keep the site map current: rebuild now, add new exchanges as they are recorded, rebuild on
    /// scope changes (so in-scope flags follow). Runs until the project closes.
    func startSiteMap() {
        let siteMap = self.siteMap
        let events = self.events
        let task = Task {
            let deliveries = await events.subscribe()  // before the rebuild, so nothing is missed
            await siteMap.rebuild()
            for await delivery in deliveries {
                if Task.isCancelled { break }
                switch delivery.event {
                case .exchangeRecorded, .exchangeUpdated: await siteMap.catchUp()
                case .scopeChanged, nil: await siteMap.rebuild()  // nil: missed events, start over
                default: break
                }
            }
        }
        backgroundTasks.append(task)
    }
}

extension ProjectSession {
    /// The endpoints table for a site-map node (TGT-002): every exchange at it or below it.
    public func siteMapEndpoints(_ nodeID: String) async throws -> [ExchangeSummary] {
        let ids = await siteMap.snapshot.exchanges(under: nodeID)
        return try await store.summaries(ids: ids)
    }

    /// "Delete branch" (TGT-004): delete every exchange at `nodeID` or below it, then rebuild.
    /// Returns how many were deleted.
    @discardableResult
    public func deleteSiteMapBranch(_ nodeID: String) async throws -> Int {
        let ids = await siteMap.snapshot.exchanges(under: nodeID)
        try await store.delete(ids)
        await siteMap.rebuild()
        return ids.count
    }

    /// Every site-map annotation (TGT-007), by node id.
    public func siteMapNotes() async throws -> [String: SiteMapNote] {
        try await store.siteMapNotes()
    }

    /// Store a site-map annotation or host notes (TGT-007); an empty note removes it.
    public func setSiteMapNote(_ note: SiteMapNote) async throws {
        try await store.setSiteMapNote(note)
    }

    /// "Analyze target" for the host of `nodeID` (TGT-008), over its newest 5,000 exchanges.
    /// Nil if the node isn't in the map.
    public func analyzeTarget(_ nodeID: String) async throws -> TargetAnalysis? {
        let map = await siteMap.snapshot
        guard map.node(nodeID) != nil else { return nil }
        let hostKey = map.hosts.first { nodeID == $0.id || nodeID.hasPrefix($0.id + "/") }?.id ?? nodeID
        guard let target = HTTPTarget(url: hostKey) else { return nil }
        return TargetAnalysis.analyze(try await store.exchanges(to: target))
    }
}
