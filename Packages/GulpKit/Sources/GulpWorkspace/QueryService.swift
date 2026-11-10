// GulpWorkspace — GulpQL for a project session (F05): queries with the project's scope as context,
// saved filters and recents with export/import (HIS-026), and the Logger's settings (HIS-040/041).
// UI-free, so it is tested on Linux.

import Foundation
import GulpCore
import GulpQuery
import GulpStore

/// A named GulpQL filter (HIS-026).
public struct SavedFilter: Sendable, Codable, Hashable, Identifiable {
    /// Stable id.
    public var id: UUID
    /// The name shown in menus.
    public var name: String
    /// The GulpQL text.
    public var query: String

    /// A filter.
    public init(id: UUID = UUID(), name: String, query: String) {
        self.id = id
        self.name = name
        self.query = query
    }
}

/// Saved filters and recently used ones; user-level, so they follow the user across projects.
public struct FilterSettings: SettingsGroup, Hashable {
    /// Storage key.
    public static let key = "history.filters"
    /// None saved.
    public static let defaultValue = FilterSettings(saved: [], recents: [])
    /// At most this many recents are kept.
    public static let maxRecents = 20

    /// Named filters.
    public var saved: [SavedFilter]
    /// Recently applied filter texts, newest first.
    public var recents: [String]

    /// Settings.
    public init(saved: [SavedFilter], recents: [String]) {
        self.saved = saved
        self.recents = recents
    }
}

/// The Logger (HIS-040/041): one table of every tool's traffic, with its own filter.
public struct LoggerSettings: SettingsGroup, Hashable {
    /// Storage key.
    public static let key = "tools.logger"
    /// Capturing everything.
    public static let defaultValue = LoggerSettings()

    /// Live capture: when off, the Logger keeps its rows but stops appending (traffic is still
    /// recorded in the project).
    public var capture = true
    /// Tools to show (`proxy`, `repeater`…); empty shows every tool.
    public var sources: [String] = []
    /// The Logger's own GulpQL filter.
    public var query = ""

    /// Defaults.
    public init() {}

    /// The History filter these settings select (sources as `source in […]` and the query).
    public func filter() throws(GulpQLError) -> HistoryFilter {
        var filter = HistoryFilter()
        var expression = try GulpQL.parse(query)
        if !sources.isEmpty {
            let only = GulpQLExpression.compare(
                GulpQLField("source"), .in, .list(sources.map { .string($0.lowercased()) }))
            expression = expression == .constant(true) ? only : .and(only, expression)
        }
        filter.query = expression == .constant(true) ? nil : expression
        return filter
    }
}

/// The interchange format for shared filters (HIS-026).
struct SharedFilters: Codable {
    var gulpFilters = 1
    var filters: [Entry]

    struct Entry: Codable {
        var name: String
        var query: String
    }
}

extension ProjectSession {
    /// The GulpQL context for this project: the current scope (bodies are decoded by the store).
    public func queryContext() async -> GulpQLContext {
        GulpQLContext(scope: await scope())
    }

    /// Ids of the exchanges matching `text` within `base` (HIS-020…024), in `sort` order.
    public func query(
        _ text: String, base: HistoryFilter = HistoryFilter(), sort: HistorySort = .idAscending,
        limit: Int = 1_000_000
    ) async throws -> [ExchangeID] {
        var filter = base
        let expression = try GulpQL.parse(text)
        filter.query = expression == .constant(true) ? base.query : expression
        return try await store.matchingIDs(
            filter: filter, sort: sort, limit: limit, context: await queryContext())
    }

    /// The saved filters and recents.
    public func filterSettings() -> FilterSettings { settings.get(FilterSettings.self) }

    /// Save (or replace by name) a filter; the text must parse.
    @discardableResult
    public func saveFilter(name: String, query: String) async throws -> SavedFilter {
        _ = try GulpQL.parse(query)
        var current = filterSettings()
        let filter = SavedFilter(
            id: current.saved.first { $0.name == name }?.id ?? UUID(), name: name, query: query)
        current.saved.removeAll { $0.name == name }
        current.saved.append(filter)
        try await settings.set(current, scope: .user)
        return filter
    }

    /// Delete a saved filter.
    public func deleteFilter(_ id: UUID) async throws {
        var current = filterSettings()
        current.saved.removeAll { $0.id == id }
        try await settings.set(current, scope: .user)
    }

    /// Remember a filter the user applied (newest first, deduplicated, capped).
    public func rememberFilter(_ query: String) async throws {
        let text = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        var current = filterSettings()
        current.recents.removeAll { $0 == text }
        current.recents.insert(text, at: 0)
        if current.recents.count > FilterSettings.maxRecents {
            current.recents.removeLast(current.recents.count - FilterSettings.maxRecents)
        }
        try await settings.set(current, scope: .user)
    }

    /// The saved filters as a shareable JSON file (HIS-026).
    public func exportFilters() throws -> Data {
        let shared = SharedFilters(
            filters: filterSettings().saved.map { .init(name: $0.name, query: $0.query) })
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(shared)
    }

    /// Import shared filters; ones that don't parse or already exist (same name and text) are
    /// skipped. Returns how many were added.
    @discardableResult
    public func importFilters(_ data: Data) async throws -> Int {
        let shared = try JSONDecoder().decode(SharedFilters.self, from: data)
        var current = filterSettings()
        var added = 0
        for entry in shared.filters where (try? GulpQL.parse(entry.query)) != nil {
            if current.saved.contains(where: { $0.name == entry.name && $0.query == entry.query }) {
                continue
            }
            var name = entry.name
            var suffix = 2
            while current.saved.contains(where: { $0.name == name }) {
                name = "\(entry.name) (\(suffix))"
                suffix += 1
            }
            current.saved.append(SavedFilter(name: name, query: entry.query))
            added += 1
        }
        try await settings.set(current, scope: .user)
        return added
    }

    /// The Logger's settings (HIS-040/041).
    public func loggerSettings() -> LoggerSettings { settings.get(LoggerSettings.self) }

    /// Change the Logger's settings (stored with the project); the query must parse.
    public func setLoggerSettings(_ value: LoggerSettings) async throws {
        _ = try value.filter()
        try await settings.set(value, scope: .project)
    }

    /// The Logger's rows: every tool's traffic through its settings, newest first.
    public func loggerIDs(limit: Int = 1_000_000) async throws -> [ExchangeID] {
        let filter = try loggerSettings().filter()
        return try await store.matchingIDs(
            filter: filter, sort: HistorySort(column: .id, ascending: false), limit: limit,
            context: await queryContext())
    }
}
