// GulpRepeater — Repeater tabs and sends (F06 REP-001…REP-007, REP-016), UI-free. `RepeaterService`
// owns the tabs of one project: drafts are saved (debounced ≈500 ms) through `RepeaterPersistence`,
// every send goes through the shared HTTP engine (recorded as `.repeater`) and is appended to the
// tab's history; a send can stream (REP-016) and be cancelled. Storage is behind a protocol so this
// module depends only on GulpCore and GulpHTTP (doc 01); GulpWorkspace implements it on GulpStore.

import GulpCore
import GulpHTTP

/// Namespace and module marker for the `GulpRepeater` module.
public enum GulpRepeater {
    /// The module's name, used in diagnostics.
    public static let moduleName = "GulpRepeater"
}

/// A tab's send options (REP-003, REP-006, REP-007), stored with the tab.
public struct RepeaterOptions: Sendable, Codable, Hashable {
    /// HTTP version preference.
    public enum Version: String, Sendable, Codable, Hashable, CaseIterable {
        case auto, http1_1, http2, http2PriorKnowledge
    }
    /// Redirect following (REP-006).
    public enum Redirects: String, Sendable, Codable, Hashable, CaseIterable {
        case never, onSite, inScope, always
    }

    /// HTTP version preference.
    public var version = Version.auto
    /// Recompute Content-Length from the body (default on, REP-003).
    public var updateContentLength = true
    /// Redirect following.
    public var redirects = Redirects.never
    /// Maximum redirect hops.
    public var maxRedirects = 10
    /// Open a new connection for every send instead of reusing one (REP-007).
    public var newConnection = false
    /// Check the server certificate.
    public var validateCertificates = false
    /// Total timeout in seconds.
    public var timeoutSeconds = 60

    /// Defaults.
    public init() {}

    /// The engine options for a send.
    public var sendOptions: SendOptions {
        var options = SendOptions(recordAs: .repeater)
        options.httpVersion =
            switch version {
            case .auto: .auto
            case .http1_1: .http1_1
            case .http2: .http2
            case .http2PriorKnowledge: .http2PriorKnowledge
            }
        options.updateContentLength = updateContentLength
        let mode: RedirectPolicy.Mode =
            switch redirects {
            case .never: .never
            case .onSite: .onSite
            case .inScope: .inScope
            case .always: .always
            }
        options.followRedirects = RedirectPolicy(mode: mode, maxHops: maxRedirects)
        options.connection = newConnection ? .new : .reuse
        options.tls.validateCertificates = validateCertificates
        options.timeouts.total = .seconds(timeoutSeconds)
        return options
    }
}

/// One Repeater tab (REP-001, REP-005).
public struct RepeaterTab: Sendable, Codable, Hashable, Identifiable {
    /// Stable id (the store's row id).
    public var id: Int64
    /// Title shown on the tab.
    public var title: String
    /// Group, if any (REP-010).
    public var groupID: Int64?
    /// Position in the tab bar.
    public var ordinal: Int
    /// Where sends go (REP-003).
    public var target: HTTPTarget
    /// Send options.
    public var options: RepeaterOptions
    /// The request as edited (exact bytes).
    public var draft: [UInt8]

    /// A tab.
    public init(
        id: Int64 = 0, title: String, groupID: Int64? = nil, ordinal: Int = 0, target: HTTPTarget,
        options: RepeaterOptions = RepeaterOptions(), draft: [UInt8]
    ) {
        self.id = id
        self.title = title
        self.groupID = groupID
        self.ordinal = ordinal
        self.target = target
        self.options = options
        self.draft = draft
    }
}

/// Where Repeater tabs and their history are kept (implemented by GulpWorkspace on GulpStore).
public protocol RepeaterPersistence: Sendable {
    /// All tabs, in tab-bar order.
    func loadTabs() async throws -> [RepeaterTab]
    /// Insert (`id == 0`) or update a tab; returns its id.
    func saveTab(_ tab: RepeaterTab) async throws -> Int64
    /// Delete a tab and its history rows (the exchanges stay).
    func deleteTab(_ id: Int64) async throws
    /// The exchanges sent from a tab, oldest first.
    func history(of tab: Int64) async throws -> [ExchangeID]
    /// Append a send to a tab's history.
    func appendHistory(tab: Int64, exchange: ExchangeID) async throws
    /// A recorded exchange.
    func exchange(_ id: ExchangeID) async throws -> Exchange?
}

/// The outcome of one Repeater send.
public struct RepeaterSendResult: Sendable {
    /// The final exchange (after redirects, if followed).
    public var exchange: Exchange
    /// Earlier redirect hops, in order (REP-006).
    public var redirectChain: [Exchange]
    /// The network error, if any (also recorded in `exchange.state`).
    public var error: GulpNetworkError?
}

/// The Repeater of one project.
public actor RepeaterService {
    /// Delay before a draft edit is written (REP-005 persistence; spec §4: ≈500 ms).
    public static let draftSaveDelay = Duration.milliseconds(500)

    private let engine: any HTTPEngine
    private let persistence: (any RepeaterPersistence)?
    private var tabs: [RepeaterTab] = []
    private var histories: [Int64: [ExchangeID]] = [:]
    private var sending: [Int64: Task<RepeaterSendResult, Never>] = [:]
    private var pendingSaves: [Int64: Task<Void, Never>] = [:]
    private var closed: [RepeaterTab] = []
    private var nextLocalID: Int64 = -1

    /// A Repeater sending through `engine`; tabs persist through `persistence` when given.
    public init(engine: any HTTPEngine, persistence: (any RepeaterPersistence)? = nil) {
        self.engine = engine
        self.persistence = persistence
    }

    /// Load the project's tabs (call once after opening).
    public func load() async throws {
        guard let persistence else { return }
        tabs = try await persistence.loadTabs()
        for tab in tabs { histories[tab.id] = try await persistence.history(of: tab.id) }
    }

    /// The tabs, in order.
    public var allTabs: [RepeaterTab] { tabs }

    /// One tab.
    public func tab(_ id: Int64) -> RepeaterTab? { tabs.first { $0.id == id } }

    /// Open a tab prefilled with `request` (REP-001, "Send to Repeater").
    @discardableResult
    public func openTab(
        request: RawRequest, target: HTTPTarget, title: String? = nil,
        options: RepeaterOptions = RepeaterOptions()
    ) async -> RepeaterTab {
        var tab = RepeaterTab(
            title: title ?? "\(tabs.count + 1)", ordinal: (tabs.map(\.ordinal).max() ?? -1) + 1,
            target: target, options: options, draft: request.bytes.rawBytes)
        tab.id = await store(tab)
        tabs.append(tab)
        histories[tab.id] = []
        return tab
    }

    /// Replace a tab's draft bytes; written after `draftSaveDelay` without further edits.
    public func updateDraft(_ id: Int64, bytes: [UInt8]) {
        modify(id) { $0.draft = bytes }
    }

    /// Change a tab's target (REP-003).
    public func setTarget(_ id: Int64, _ target: HTTPTarget) {
        modify(id) { $0.target = target }
    }

    /// Change a tab's options.
    public func setOptions(_ id: Int64, _ options: RepeaterOptions) {
        modify(id) { $0.options = options }
    }

    /// Rename a tab (REP-005).
    public func rename(_ id: Int64, to title: String) {
        modify(id) { $0.title = title }
    }

    /// Move a tab to `position` in the tab bar (REP-005).
    public func move(_ id: Int64, to position: Int) {
        guard let from = tabs.firstIndex(where: { $0.id == id }) else { return }
        let tab = tabs.remove(at: from)
        tabs.insert(tab, at: max(0, min(position, tabs.count)))
        for index in tabs.indices where tabs[index].ordinal != index {
            tabs[index].ordinal = index
            scheduleSave(tabs[index].id)
        }
    }

    /// Close a tab (⌘W): a send in flight is cancelled; it can be reopened (⌘⇧T) until the project
    /// closes (REP-005).
    public func close(_ id: Int64) async {
        guard let index = tabs.firstIndex(where: { $0.id == id }) else { return }
        cancel(id)
        pendingSaves.removeValue(forKey: id)?.cancel()
        let tab = tabs.remove(at: index)
        closed.append(tab)
        try? await persistence?.deleteTab(id)
    }

    /// Reopen the most recently closed tab (⌘⇧T), with a new id (its history went with it).
    @discardableResult
    public func reopenClosed() async -> RepeaterTab? {
        guard var tab = closed.popLast() else { return nil }
        tab.id = 0
        tab.ordinal = (tabs.map(\.ordinal).max() ?? -1) + 1
        tab.id = await store(tab)
        tabs.append(tab)
        histories[tab.id] = []
        return tab
    }

    /// The exchanges sent from a tab, oldest first (REP-004).
    public func history(_ id: Int64) -> [ExchangeID] { histories[id] ?? [] }

    /// Whether a tab is sending.
    public func isSending(_ id: Int64) -> Bool { sending[id] != nil }

    /// Send a tab's draft (REP-002). `onBytes` receives a streamed response as it arrives
    /// (REP-016). The exchange (and redirect hops) are recorded by the engine and appended to the
    /// tab's history — also when cancelled, with what was received.
    public func send(
        _ id: Int64, onBytes: (@Sendable ([UInt8]) -> Void)? = nil
    ) async -> RepeaterSendResult? {
        guard let tab = tab(id) else { return nil }
        cancel(id)
        var options = tab.options.sendOptions
        options.onResponseBytes = onBytes
        let engine = self.engine
        let request = RawRequest(Bytes(tab.draft))
        let task = Task {
            let result = await engine.send(request, to: tab.target, options: options)
            return RepeaterSendResult(
                exchange: result.exchange, redirectChain: result.redirectChain, error: result.error)
        }
        sending[id] = task
        let result = await task.value
        if sending[id] == task { sending[id] = nil }
        for exchange in result.redirectChain + [result.exchange] where exchange.id != 0 {
            histories[id, default: []].append(exchange.id)
            try? await persistence?.appendHistory(tab: id, exchange: exchange.id)
        }
        return result
    }

    /// Cancel a tab's send in flight (the Stop button, REP-016).
    public func cancel(_ id: Int64) {
        sending.removeValue(forKey: id)?.cancel()
    }

    /// Write every pending draft now (before the project closes).
    public func flush() async {
        let ids = Array(pendingSaves.keys)
        for id in ids {
            pendingSaves.removeValue(forKey: id)?.cancel()
            if let tab = tab(id) { _ = await store(tab) }
        }
    }

    // MARK: internals

    private func modify(_ id: Int64, _ change: (inout RepeaterTab) -> Void) {
        guard let index = tabs.firstIndex(where: { $0.id == id }) else { return }
        change(&tabs[index])
        scheduleSave(id)
    }

    private func scheduleSave(_ id: Int64) {
        guard persistence != nil else { return }
        pendingSaves[id]?.cancel()
        pendingSaves[id] = Task { [weak self] in
            try? await Task.sleep(for: Self.draftSaveDelay)
            guard !Task.isCancelled else { return }
            await self?.saveNow(id)
        }
    }

    private func saveNow(_ id: Int64) async {
        pendingSaves[id] = nil
        guard let tab = tab(id) else { return }
        _ = await store(tab)
    }

    /// Persist `tab`; returns its id (a negative local id without persistence or on failure).
    private func store(_ tab: RepeaterTab) async -> Int64 {
        if let persistence, let id = try? await persistence.saveTab(tab) { return id }
        if tab.id != 0 { return tab.id }
        defer { nextLocalID -= 1 }
        return nextLocalID
    }
}
