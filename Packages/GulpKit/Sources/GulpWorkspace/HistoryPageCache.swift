// GulpWorkspace — paged, virtualized History data (F05 HIS-002). The table asks for row N; rows come
// from fixed-size pages loaded asynchronously from the store, and only a bounded number of pages is
// kept. Platform-independent so it is tested on Linux; the macOS table view drives it.

import GulpCore
import GulpStore

/// A bounded cache of History pages for one filter/sort.
public struct HistoryPageCache: Sendable {
    /// Rows per page.
    public let pageSize: Int
    /// Pages kept in memory; the least recently used beyond this are dropped.
    public let maxPages: Int
    /// Total rows matching the current query (the table's row count).
    public private(set) var totalCount = 0

    private var pages: [Int: [ExchangeSummary]] = [:]
    private var lastUse: [Int: UInt64] = [:]
    private var clock: UInt64 = 0
    private var requested: Set<Int> = []

    /// Create an empty cache.
    public init(pageSize: Int = 200, maxPages: Int = 20) {
        self.pageSize = max(1, pageSize)
        self.maxPages = max(1, maxPages)
    }

    /// The row at `index` if its page is loaded. A miss means: show a placeholder and load
    /// `page(for: index)`.
    public mutating func row(_ index: Int) -> ExchangeSummary? {
        guard index >= 0, index < totalCount else { return nil }
        let page = index / pageSize
        guard let rows = pages[page] else { return nil }
        clock += 1
        lastUse[page] = clock
        let offset = index % pageSize
        return offset < rows.count ? rows[offset] : nil
    }

    /// The page holding `index`.
    public func page(for index: Int) -> Int { max(0, index) / pageSize }

    /// Mark `page` as being loaded; false if it is already loaded or in flight (load it only once).
    public mutating func beginLoading(_ page: Int) -> Bool {
        guard pages[page] == nil, !requested.contains(page) else { return false }
        requested.insert(page)
        return true
    }

    /// Forget that `page` is loading (the load failed or was superseded), so it can be asked again.
    public mutating func cancelLoading(_ page: Int) {
        requested.remove(page)
    }

    /// Store a loaded page, evicting the least recently used pages over the limit.
    public mutating func store(_ rows: [ExchangeSummary], page: Int) {
        requested.remove(page)
        pages[page] = rows
        clock += 1
        lastUse[page] = clock
        while pages.count > maxPages, let oldest = lastUse.min(by: { $0.value < $1.value })?.key {
            pages[oldest] = nil
            lastUse[oldest] = nil
        }
    }

    /// New total row count (after a filter change or new traffic). Pages past the end are dropped,
    /// and the last page is reloaded if it was partial, so appended rows appear.
    public mutating func setTotalCount(_ count: Int) {
        totalCount = max(0, count)
        let lastPage = totalCount == 0 ? -1 : (totalCount - 1) / pageSize
        for page in Array(pages.keys) where page > lastPage || (pages[page]?.count ?? 0) < pageSize {
            pages[page] = nil
            lastUse[page] = nil
        }
    }

    /// Drop everything (filter or sort changed, or rows were edited/deleted).
    public mutating func invalidate() {
        pages = [:]
        lastUse = [:]
        requested = []
    }

    /// Number of loaded pages (for tests and diagnostics).
    public var loadedPageCount: Int { pages.count }
}

/// Loads History pages and counts from a project store (the async half of the table's data source).
public struct HistorySource: Sendable {
    /// The project store.
    public let store: ProjectStore
    /// Current filter.
    public var filter = HistoryFilter()
    /// Current sort.
    public var sort = HistorySort.idAscending

    /// Create a source over `store`.
    public init(store: ProjectStore) {
        self.store = store
    }

    /// Rows of `page`.
    public func load(page: Int, pageSize: Int) async throws -> [ExchangeSummary] {
        try await store.summaries(filter: filter, sort: sort, offset: page * pageSize, limit: pageSize)
    }

    /// Rows matching the filter.
    public func count() async throws -> Int {
        try await store.count(filter: filter)
    }
}
