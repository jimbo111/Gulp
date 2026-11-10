// GulpFeatures — the HTTP History view model (F05 HIS-001…HIS-006). Main-actor UI state over the
// async store: the main thread never waits on the database (CLAUDE.md §4); rows arrive by page, and
// live traffic is coalesced into at most one refresh per 100 ms.

#if canImport(AppKit)
import Foundation
import GulpCodec
import GulpCore
import GulpStore
import GulpWorkspace
import Observation

/// State and actions behind the History table and message viewer.
@MainActor
@Observable
public final class HistoryModel {
    /// Rows matching the current filter.
    public private(set) var rowCount = 0
    /// Bumped whenever visible rows may have changed; the table reloads on change.
    public private(set) var revision = 0
    /// The full exchange of the (first) selected row, for the message viewer.
    public private(set) var selected: Exchange?
    /// Ids of the selected rows.
    public private(set) var selectedIDs: [ExchangeID] = []
    /// "Send to Repeater" (F06 REP-001, ⌘R); set by the view that knows the session.
    @ObservationIgnored public var sendToRepeater: (@MainActor ([ExchangeID]) -> Void)?
    /// "Send to Comparer" (F13 CMP-001): the selected rows' responses.
    @ObservationIgnored public var sendToComparer: (@MainActor ([ExchangeID]) -> Void)?
    /// "Send to Decoder" (F12 DEC-004): the first selected row's request.
    @ObservationIgnored public var sendToDecoder: (@MainActor (ExchangeID) -> Void)?
    /// "Send to Fuzzer" (F07): the first selected row's request.
    @ObservationIgnored public var sendToFuzzer: (@MainActor (ExchangeID) -> Void)?
    /// Keep the newest row in view as traffic arrives (HIS-002).
    public var autoScroll = true
    /// Quick filters (HIS-006).
    public var filter = HistoryFilter() {
        didSet { reset() }
    }
    /// Sort (HIS-001).
    public var sort = HistorySort.idAscending {
        didSet { reset() }
    }

    @ObservationIgnored private var cache = HistoryPageCache()
    @ObservationIgnored private let store: ProjectStore
    @ObservationIgnored private var listener: Task<Void, Never>?
    @ObservationIgnored private var pendingRefresh: Task<Void, Never>?
    /// Bumped whenever cached pages are dropped, so loads started before that are discarded.
    @ObservationIgnored private var cacheGeneration = 0

    /// A model over `store`, live-updated from `events`.
    public init(store: ProjectStore, events: EventBus) {
        self.store = store
        // Ends (and drops the subscription) on the first event after the model is released.
        listener = Task { [weak self] in
            for await delivery in await events.subscribe() {
                guard let self else { return }
                switch delivery.event {
                case .exchangeRecorded, .exchangeUpdated, nil:  // nil = lagged: re-query
                    self.scheduleRefresh()
                default:
                    break
                }
            }
        }
        reset()
    }

    /// The row at `index`, or nil while its page loads (HIS-002: only visible pages are loaded).
    public func row(_ index: Int) -> ExchangeSummary? {
        if let row = cache.row(index) { return row }
        let page = cache.page(for: index)
        if cache.beginLoading(page) { load(page) }
        return nil
    }

    /// The ids of table rows `rows` in the current filter and sort, read from the store, so bulk
    /// actions also cover rows whose pages are not loaded (Select All on 10k rows, HIS-004).
    public func ids(forRows rows: IndexSet) async -> [ExchangeID] {
        let store = self.store
        let filter = self.filter
        let sort = self.sort
        var ids: [ExchangeID] = []
        for range in rows.rangeView {
            let page = try? await store.summaries(
                filter: filter, sort: sort, offset: range.lowerBound, limit: range.count)
            ids += (page ?? []).map(\.id)
        }
        return ids
    }

    /// The row at `index` only if its page is already loaded (never triggers a load).
    public func loadedRow(_ index: Int) -> ExchangeSummary? {
        cache.row(index)
    }

    /// Select rows; loads the first selected exchange for the viewer (HIS-003).
    public func select(_ ids: [ExchangeID]) {
        selectedIDs = ids
        guard let first = ids.first else {
            selected = nil
            return
        }
        let store = self.store
        Task {
            let exchange = try? await store.exchange(id: first)
            if self.selectedIDs.first == first { self.selected = exchange }
        }
    }

    /// Set or clear the highlight of rows (HIS-005).
    public func highlight(_ ids: [ExchangeID], _ color: Highlight?) {
        mutate { store in try await store.setHighlight(color, for: ids) }
    }

    /// Set or clear the comment of rows (HIS-005).
    public func comment(_ ids: [ExchangeID], _ text: String?) {
        mutate { store in try await store.setComment(text, for: ids) }
    }

    /// Delete rows (HIS-004).
    public func delete(_ ids: [ExchangeID]) {
        mutate { store in try await store.delete(ids) }
    }

    /// The URLs of rows, one per line (HIS-004 "copy URLs").
    public func urls(_ ids: [ExchangeID]) async -> String {
        var lines: [String] = []
        for id in ids {
            if let exchange = try? await store.exchange(id: id) {
                let summary = ExchangeSummaryURL(exchange: exchange)
                lines.append(summary.url)
            }
        }
        return lines.joined(separator: "\n")
    }

    /// The rows' requests as runnable code (Copy as, ETL-008), separated by blank lines.
    public func copyAs(_ ids: [ExchangeID], format: RequestExportFormat) async -> String {
        var snippets: [String] = []
        for id in ids {
            if let exchange = try? await store.exchange(id: id) {
                let snippet = RequestExport.export(exchange.request, target: exchange.target, as: format)
                snippets.append(snippet)
            }
        }
        return snippets.joined(separator: "\n\n")
    }

    // MARK: loading

    private func reset() {
        invalidateCache()
        refreshCount()
    }

    private func invalidateCache() {
        cache.invalidate()
        cacheGeneration += 1
    }

    private func mutate(_ change: @escaping @Sendable (ProjectStore) async throws -> Void) {
        let store = self.store
        Task {
            try? await change(store)
            self.invalidateCache()
            self.refreshCount()
        }
    }

    private func scheduleRefresh() {
        guard pendingRefresh == nil else { return }
        pendingRefresh = Task {
            try? await Task.sleep(for: .milliseconds(100))
            self.pendingRefresh = nil
            self.refreshCount()
        }
    }

    private func refreshCount() {
        let store = self.store
        let filter = self.filter
        Task {
            let count = (try? await store.count(filter: filter)) ?? 0
            guard filter == self.filter else { return }  // a newer filter is already loading
            // New rows only append at the end when sorted oldest-first; any other order can shift
            // every cached page, so drop them all (HIS-002 live updates).
            if self.sort != .idAscending, count != self.rowCount { self.invalidateCache() }
            self.cache.setTotalCount(count)
            self.rowCount = count
            self.revision += 1
        }
    }

    private func load(_ page: Int) {
        let source = { () -> HistorySource in
            var source = HistorySource(store: self.store)
            source.filter = self.filter
            source.sort = self.sort
            return source
        }()
        let pageSize = cache.pageSize
        let generation = cacheGeneration
        Task {
            let rows = try? await source.load(page: page, pageSize: pageSize)
            // A page loaded before an edit, delete or filter change would show stale rows.
            guard generation == self.cacheGeneration else { return }
            guard let rows else {
                self.cache.cancelLoading(page)  // let a later scroll retry it
                return
            }
            self.cache.store(rows, page: page)
            self.revision += 1
        }
    }
}

/// The display URL of a full exchange (same format as `ExchangeSummary.url`).
struct ExchangeSummaryURL {
    let url: String

    init(exchange: Exchange) {
        let target = exchange.target
        let defaultPort = target.scheme == .https ? 443 : 80
        let authority = target.port == defaultPort ? target.host : "\(target.host):\(target.port)"
        let path = exchange.derived.path ?? "/"
        let query = exchange.derived.query.map { "?\($0)" } ?? ""
        url = "\(target.scheme.rawValue)://\(authority)\(path)\(query)"
    }
}
#endif
