// GulpWorkspace — the coverage index (F04 JRN-001): per endpoint, which tools have exercised it and
// when, derived from `exchanges.source`. Built once from a grouped store query, then extended from
// the last row id seen, and rebuilt when scope changes (in-scope flags follow). "Touched" is not
// "tested": proxy/browser/crawler traffic only observes an endpoint; Repeater, Fuzzer, Scanner and
// automation test it. Source-agnostic: new tools show up as they record traffic.

import Foundation
import GulpCore
import GulpStore

/// How a tool's traffic counts toward coverage.
public enum CoverageCategory: String, Sendable, Hashable, CaseIterable {
    /// Seen passing by (proxy, browser, crawler, session handling).
    case observed
    /// Sent deliberately by a person or an agent (Repeater, Fuzzer, Sequencer, automation, AI,
    /// extensions).
    case manual
    /// Sent by the Scanner (populates from M10a/M11b).
    case scanner

    /// The category of a tool (`exchanges.source`).
    public static func of(_ source: String) -> CoverageCategory {
        guard let tool = ToolSource(rawValue: source) else { return .observed }
        switch tool {
        case .proxy, .browser, .crawler, .session: return .observed
        case .scanner: return .scanner
        case .repeater, .fuzzer, .sequencer, .automation, .ai, .extension: return .manual
        }
    }
}

/// One tool's activity on an endpoint.
public struct ToolCoverage: Sendable, Hashable {
    /// Exchanges.
    public var count: Int
    /// The newest.
    public var last: Date
}

/// Coverage of one endpoint (scheme, host, port, path without the query).
public struct EndpointCoverage: Sendable, Hashable, Identifiable {
    /// `scheme://host:port/path`.
    public var id: String { "\(scheme)://\(host):\(port)\(path)" }
    /// Scheme.
    public var scheme: String
    /// Host.
    public var host: String
    /// Port.
    public var port: Int
    /// Path.
    public var path: String
    /// Methods seen.
    public var methods: Set<String>
    /// In scope.
    public var inScope: Bool
    /// Activity per tool (`proxy`, `repeater`…).
    public var tools: [String: ToolCoverage]
    /// Notebook items saved from this endpoint.
    public var notebookItems: Int

    /// Exercised by something other than observation (or noted in the Notebook).
    public var tested: Bool {
        notebookItems > 0 || tools.keys.contains { CoverageCategory.of($0) != .observed }
    }

    /// The newest deliberate test.
    public var lastTested: Date? {
        tools.filter { CoverageCategory.of($0.key) != .observed }.map(\.value.last).max()
    }
}

/// The coverage index of one project.
public actor CoverageService {
    private var entries: [String: EndpointCoverage] = [:]
    private var lastID: ExchangeID = 0
    private let storeProvider: @Sendable () async -> ProjectStore
    /// Updates run one at a time (actor reentrancy: two overlapping reads would otherwise both
    /// start from the same `lastID` and count rows twice).
    private var tail: Task<Void, any Error>?
    /// Bumped by `invalidate`; an update that started before it discards its result.
    private var generation = 0

    init(store: @escaping @Sendable () async -> ProjectStore) {
        storeProvider = store
    }

    /// Forget everything (scope changed, project replaced); the next read rebuilds.
    public func invalidate() {
        entries = [:]
        lastID = 0
        generation += 1
    }

    /// Every endpoint, sorted by host then path (brought up to date first).
    public func endpoints() async throws -> [EndpointCoverage] {
        try await update()
        let store = await storeProvider()
        var result = entries
        for endpoint in try await store.notebookEndpoints() {
            let key = Self.key(
                endpoint.target.scheme.rawValue, endpoint.target.host, endpoint.target.port, endpoint.path)
            result[key]?.notebookItems += 1
        }
        return result.values.sorted { ($0.host, $0.path, $0.port) < ($1.host, $1.path, $1.port) }
    }

    /// In-scope endpoints nothing has tested yet (F04 JRN-002's "untested" filter).
    public func untested(inScopeOnly: Bool = true) async throws -> [EndpointCoverage] {
        try await endpoints().filter { !$0.tested && (!inScopeOnly || $0.inScope) }
    }

    func update() async throws {
        let previous = tail
        let next = Task {
            _ = try? await previous?.value
            try await self.performUpdate()
        }
        tail = next
        try await next.value
    }

    private func performUpdate() async throws {
        let started = generation
        let store = await storeProvider()
        let (rows, newest) = try await store.coverageRows(after: lastID)
        guard started == generation else { return }  // invalidated meanwhile: the next read rebuilds
        for row in rows {
            let key = Self.key(row.scheme, row.host, row.port, row.path)
            var entry =
                entries[key]
                ?? EndpointCoverage(
                    scheme: row.scheme, host: row.host, port: row.port, path: row.path, methods: [],
                    inScope: false, tools: [:], notebookItems: 0)
            entry.methods.insert(row.method)
            entry.inScope = entry.inScope || row.inScope
            let previous = entry.tools[row.source]
            entry.tools[row.source] = ToolCoverage(
                count: (previous?.count ?? 0) + row.count, last: max(previous?.last ?? .distantPast, row.last)
            )
            entries[key] = entry
        }
        lastID = max(lastID, newest)
    }

    static func key(_ scheme: String, _ host: String, _ port: Int, _ path: String) -> String {
        "\(scheme)://\(host.lowercased()):\(port)\(path)"
    }
}
