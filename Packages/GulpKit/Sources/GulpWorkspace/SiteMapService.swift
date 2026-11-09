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
        guard on != map.groupsParameterizedSegments else { return }
        map = SiteMap(groupsParameterizedSegments: on)
        lastID = 0
        await rebuild()
    }

    /// Rebuild from the store: every exchange (visited) and links in recent textual responses
    /// (inferred).
    public func rebuild() async {
        let store = await storeProvider()
        var fresh = SiteMap(groupsParameterizedSegments: map.groupsParameterizedSegments)
        var after: ExchangeID = 0
        while let page = try? await store.siteMapEntries(after: after), let last = page.last {
            for entry in page { fresh.add(entry) }
            after = last.id
            await Task.yield()
        }
        for id in (try? await store.textualResponseIDs()) ?? [] {
            guard let exchange = try? await store.exchange(id: id) else { continue }
            for url in Self.links(of: exchange) { fresh.addInferred(url: url) }
        }
        map = fresh
        lastID = after
        notify()
    }

    /// Add exchanges recorded since the last update (called on `exchangeRecorded`).
    public func catchUp() async {
        let store = await storeProvider()
        var changed = false
        while let page = try? await store.siteMapEntries(after: lastID, limit: 1_000), let last = page.last {
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
        Task {
            await siteMap.rebuild()
            for await delivery in await events.subscribe() {
                switch delivery.event {
                case .exchangeRecorded, .exchangeUpdated: await siteMap.catchUp()
                case .scopeChanged, nil: await siteMap.rebuild()  // nil: missed events, start over
                default: break
                }
            }
        }
    }
}
