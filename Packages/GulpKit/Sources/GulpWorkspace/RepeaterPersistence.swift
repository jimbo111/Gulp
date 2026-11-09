// GulpWorkspace — Repeater tabs stored in the project (F06 REP-004/REP-005): `RepeaterPersistence`
// on top of GulpStore's repeater rows, following Save As like the recorder does.

import Foundation
import GulpCore
import GulpRepeater
import GulpStore

/// The project file a session currently writes to (Save As switches it).
actor CurrentStore {
    private(set) var store: ProjectStore

    init(_ store: ProjectStore) {
        self.store = store
    }

    func set(_ store: ProjectStore) {
        self.store = store
    }
}

/// Stores Repeater tabs in the session's current project file.
final class StoreRepeaterPersistence: RepeaterPersistence {
    private let current: CurrentStore

    init(_ current: CurrentStore) {
        self.current = current
    }

    private var store: ProjectStore {
        get async { await current.store }
    }

    func loadTabs() async throws -> [RepeaterTab] {
        let decoder = JSONDecoder()
        return try await store.repeaterTabs().compactMap { row in
            guard let target = try? decoder.decode(HTTPTarget.self, from: Data(row.targetJSON.utf8)) else {
                return nil
            }
            let options = (try? decoder.decode(RepeaterOptions.self, from: Data(row.optionsJSON.utf8)))
            return RepeaterTab(
                id: row.id, title: row.title, groupID: row.groupID, ordinal: row.ordinal, target: target,
                options: options ?? RepeaterOptions(), draft: row.draft)
        }
    }

    func saveTab(_ tab: RepeaterTab) async throws -> Int64 {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let row = RepeaterTabRow(
            id: tab.id, title: tab.title, groupID: tab.groupID, ordinal: tab.ordinal,
            targetJSON: String(decoding: try encoder.encode(tab.target), as: UTF8.self),
            optionsJSON: String(decoding: try encoder.encode(tab.options), as: UTF8.self), draft: tab.draft)
        return try await store.saveRepeaterTab(row)
    }

    func deleteTab(_ id: Int64) async throws {
        try await store.deleteRepeaterTab(id)
    }

    func history(of tab: Int64) async throws -> [ExchangeID] {
        try await store.repeaterHistory(tab: tab)
    }

    func appendHistory(tab: Int64, exchange: ExchangeID) async throws {
        try await store.appendRepeaterHistory(tab: tab, exchange: exchange)
    }

    func exchange(_ id: ExchangeID) async throws -> Exchange? {
        try await store.exchange(id: id)
    }
}

extension ProjectSession {
    /// "Send to Repeater" (F06 REP-001, ⌘R): a tab per exchange, prefilled with its exact request
    /// bytes and target (an edited request is sent as edited). Announces each tab on `events`.
    @discardableResult
    public func sendToRepeater(_ ids: [ExchangeID]) async -> [RepeaterTab] {
        var opened: [RepeaterTab] = []
        for id in ids {
            guard let exchange = try? await store.exchange(id: id) else { continue }
            let path = exchange.request.bytes[exchange.request.parsed.target].string()
            let method = exchange.request.bytes[exchange.request.parsed.method].string()
            let title = "\(method) \(path.split(separator: "?").first.map(String.init) ?? path)"
            var options = RepeaterOptions()
            if exchange.httpVersion == .http2 { options.version = .http2 }
            let tab = await repeater.openTab(
                request: exchange.request, target: exchange.target, title: String(title.prefix(40)),
                options: options)
            opened.append(tab)
            await events.publish(.repeaterTabOpened(tab.id))
        }
        return opened
    }
}

extension ProjectSession {
    /// The ids of tabs "Send to Repeater" opens, as they open (the window switches to the Repeater).
    public func repeaterTabsOpened() async -> AsyncStream<Int64> {
        let deliveries = await events.subscribe()
        return AsyncStream { continuation in
            let task = Task {
                for await delivery in deliveries {
                    if case .repeaterTabOpened(let id) = delivery.event { continuation.yield(id) }
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

extension ProjectSession {
    /// PRX-035: open a WebSocket Repeater tab (REP-012) for a recorded connection — its draft is
    /// the connection's upgrade request, and `message` (a recorded message id) prefills the message
    /// editor. Nil when the connection's upgrade exchange isn't in the project.
    @discardableResult
    public func sendWebSocketToRepeater(connection: Int64, message: Int64? = nil) async -> RepeaterTab? {
        guard let summary = try? await store.webSocketConnections().first(where: { $0.id == connection }),
            let upgradeID = summary.upgradeExchangeID,
            let upgrade = try? await store.exchange(id: upgradeID)
        else { return nil }
        var options = RepeaterOptions()
        options.isWebSocket = true
        if let message,
            let record = try? await store.webSocketMessages(connection: connection).first(where: {
                $0.id == message
            })
        {
            options.webSocketMessage = String(decoding: record.payload, as: UTF8.self)
        }
        let path = upgrade.request.bytes[upgrade.request.parsed.target].string()
        let tab = await repeater.openTab(
            request: upgrade.request, target: upgrade.target, title: "WS \(path)".prefix(40).description,
            options: options)
        await events.publish(.repeaterTabOpened(tab.id))
        return tab
    }
}
