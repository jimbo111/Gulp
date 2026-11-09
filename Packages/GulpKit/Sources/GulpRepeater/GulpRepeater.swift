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
    /// The tab is a WebSocket tab (REP-012): its draft is the upgrade request.
    public var isWebSocket = false
    /// A WebSocket tab's message editor contents.
    public var webSocketMessage = ""
    /// Evaluate Transform Tags (`«op{…}»`, F12 DEC-022) before sending; off sends the text literally.
    public var transformTags = true

    /// Defaults.
    public init() {}

    private enum CodingKeys: String, CodingKey {
        case version, updateContentLength, redirects, maxRedirects, newConnection, validateCertificates
        case timeoutSeconds, isWebSocket, webSocketMessage, transformTags
    }

    /// Decode, defaulting fields that tabs saved by older versions don't have.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let defaults = RepeaterOptions()
        version = try c.decodeIfPresent(Version.self, forKey: .version) ?? defaults.version
        updateContentLength =
            try c.decodeIfPresent(Bool.self, forKey: .updateContentLength) ?? defaults.updateContentLength
        redirects = try c.decodeIfPresent(Redirects.self, forKey: .redirects) ?? defaults.redirects
        maxRedirects = try c.decodeIfPresent(Int.self, forKey: .maxRedirects) ?? defaults.maxRedirects
        newConnection = try c.decodeIfPresent(Bool.self, forKey: .newConnection) ?? defaults.newConnection
        validateCertificates =
            try c.decodeIfPresent(Bool.self, forKey: .validateCertificates) ?? defaults.validateCertificates
        timeoutSeconds = try c.decodeIfPresent(Int.self, forKey: .timeoutSeconds) ?? defaults.timeoutSeconds
        isWebSocket = try c.decodeIfPresent(Bool.self, forKey: .isWebSocket) ?? false
        webSocketMessage = try c.decodeIfPresent(String.self, forKey: .webSocketMessage) ?? ""
        transformTags = try c.decodeIfPresent(Bool.self, forKey: .transformTags) ?? defaults.transformTags
    }

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
        if !transformTags { options.applyHooks.remove(.transformTags) }
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

/// A group of Repeater tabs sent together (REP-010), e.g. for a race.
public struct RepeaterGroup: Sendable, Codable, Hashable, Identifiable {
    /// How the group's requests go out (F03 HTTP-030…HTTP-034).
    public enum Mode: String, Sendable, Codable, Hashable, CaseIterable {
        case sequential, separate, parallel, singlePacket

        /// The engine's group mode.
        public var engineMode: GroupSendMode {
            switch self {
            case .sequential: .sequentialSingleConnection
            case .separate: .sequentialSeparateConnections
            case .parallel: .parallel
            case .singlePacket: .singlePacket
            }
        }
    }

    /// Stable id (the store's row id).
    public var id: Int64
    /// Name shown on the group.
    public var name: String
    /// Label color name.
    public var color: String
    /// Send mode.
    public var mode: Mode

    /// A group.
    public init(id: Int64 = 0, name: String, color: String = "blue", mode: Mode = .singlePacket) {
        self.id = id
        self.name = name
        self.color = color
        self.mode = mode
    }
}

/// One row of a group send's results (REP-010).
public struct RepeaterGroupResult: Sendable, Identifiable {
    /// The tab the request came from.
    public var tabID: Int64
    /// The recorded exchange.
    public var exchange: Exchange
    /// The error, if any.
    public var error: GulpNetworkError?

    /// Row identity (the tab).
    public var id: Int64 { tabID }
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
    /// All groups.
    func loadGroups() async throws -> [RepeaterGroup]
    /// Insert (`id == 0`) or update a group; returns its id.
    func saveGroup(_ group: RepeaterGroup) async throws -> Int64
    /// Delete a group (its tabs stay, ungrouped).
    func deleteGroup(_ id: Int64) async throws
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

/// One message in a WebSocket tab's log (REP-012).
public struct RepeaterWSEntry: Sendable, Hashable, Identifiable {
    /// Position in the log.
    public var id: Int
    /// Sent by the tab (`toServer`) or received (`toClient`).
    public var direction: WSDirection
    /// Opcode (1 text, 2 binary, 8 close, 9 ping, 10 pong).
    public var opcode: UInt8
    /// The payload.
    public var payload: [UInt8]

    /// An entry.
    public init(id: Int, direction: WSDirection, opcode: UInt8, payload: [UInt8]) {
        self.id = id
        self.direction = direction
        self.opcode = opcode
        self.payload = payload
    }
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
    private var groups: [RepeaterGroup] = []
    private var sockets: [Int64: WebSocketSession] = [:]
    private var socketLogs: [Int64: [RepeaterWSEntry]] = [:]
    private var socketWatchers: [Int64: AsyncStream<RepeaterWSEntry>.Continuation] = [:]
    private let scope: (@Sendable () async -> ScopeService)?

    /// A Repeater sending through `engine`; tabs persist through `persistence` when given. `scope`
    /// supplies the project's scope for the `in-scope` redirect mode (REP-006).
    public init(
        engine: any HTTPEngine, persistence: (any RepeaterPersistence)? = nil,
        scope: (@Sendable () async -> ScopeService)? = nil
    ) {
        self.engine = engine
        self.persistence = persistence
        self.scope = scope
    }

    /// Load the project's tabs (call once after opening).
    public func load() async throws {
        guard let persistence else { return }
        tabs = try await persistence.loadTabs()
        for tab in tabs { histories[tab.id] = try await persistence.history(of: tab.id) }
        groups = try await persistence.loadGroups()
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
        await disconnectWebSocket(id)
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
        if options.followRedirects.mode == .inScope { options.scope = await scope?() }
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

    // MARK: groups (REP-010)

    /// The groups.
    public var allGroups: [RepeaterGroup] { groups }

    /// Create a group from `tabs` (moving them out of any other group).
    @discardableResult
    public func createGroup(
        name: String, tabs members: [Int64], mode: RepeaterGroup.Mode = .singlePacket
    ) async -> RepeaterGroup {
        var group = RepeaterGroup(name: name, mode: mode)
        if let persistence, let id = try? await persistence.saveGroup(group) {
            group.id = id
        } else {
            group.id = nextLocalID
            nextLocalID -= 1
        }
        groups.append(group)
        for id in members { assign(id, to: group.id) }
        return group
    }

    /// Put a tab in a group, or take it out (nil).
    public func assign(_ id: Int64, to group: Int64?) {
        modify(id) { $0.groupID = group }
    }

    /// Change a group's name, color or mode.
    public func update(_ group: RepeaterGroup) async {
        guard let index = groups.firstIndex(where: { $0.id == group.id }) else { return }
        groups[index] = group
        _ = try? await persistence?.saveGroup(group)
    }

    /// Delete a group; its tabs stay, ungrouped.
    public func deleteGroup(_ id: Int64) async {
        groups.removeAll { $0.id == id }
        for tab in tabs where tab.groupID == id { assign(tab.id, to: nil) }
        try? await persistence?.deleteGroup(id)
    }

    /// The tabs in a group, in tab-bar order.
    public func members(of group: Int64) -> [RepeaterTab] { tabs.filter { $0.groupID == group } }

    /// "Send group" (REP-010): every member's draft goes out per the group's mode (single-packet
    /// for races); each result is appended to its own tab's history.
    public func sendGroup(_ id: Int64) async -> [RepeaterGroupResult] {
        guard let group = groups.first(where: { $0.id == id }) else { return [] }
        let members = members(of: id).filter { !$0.options.isWebSocket }
        guard let first = members.first else { return [] }
        var options = first.options.sendOptions
        options.followRedirects = .never
        let items = members.map { GroupItem(request: RawRequest(Bytes($0.draft)), target: $0.target) }
        let results = await engine.sendGroup(items, mode: group.mode.engineMode, options: options)
        var rows: [RepeaterGroupResult] = []
        for (tab, result) in zip(members, results) {
            if result.exchange.id != 0 {
                histories[tab.id, default: []].append(result.exchange.id)
                try? await persistence?.appendHistory(tab: tab.id, exchange: result.exchange.id)
            }
            rows.append(RepeaterGroupResult(tabID: tab.id, exchange: result.exchange, error: result.error))
        }
        return rows
    }

    // MARK: WebSocket tabs (REP-012)

    /// Open (or re-open) a WebSocket tab's session: its draft is sent as the upgrade request and
    /// recorded in the tab's history. The returned stream yields every log entry — sent and
    /// received — until the session ends.
    public func connectWebSocket(_ id: Int64) async throws -> AsyncStream<RepeaterWSEntry> {
        guard let tab = tab(id) else { throw GulpError(message: "No such Repeater tab") }
        await disconnectWebSocket(id)
        var options = tab.options.sendOptions
        options.followRedirects = .never
        let session = try await engine.openWebSocket(
            RawRequest(Bytes(tab.draft)), to: tab.target, options: options)
        if session.upgrade.id != 0 {
            histories[id, default: []].append(session.upgrade.id)
            try? await persistence?.appendHistory(tab: id, exchange: session.upgrade.id)
        }
        sockets[id] = session
        socketLogs[id] = []
        let (stream, watcher) = AsyncStream.makeStream(of: RepeaterWSEntry.self)
        socketWatchers[id] = watcher
        Task { [weak self] in
            for await message in session.messages {
                await self?.log(
                    id, session: session, direction: .toClient, opcode: message.opcode, message.payload)
            }
            await self?.ended(id, session: session)
        }
        return stream
    }

    /// Send a message on a WebSocket tab's open session.
    public func sendWebSocket(_ id: Int64, _ opcode: WSOpcode, _ payload: [UInt8]) async throws {
        guard let session = sockets[id], session.isOpen else {
            throw GulpError(
                message: "The WebSocket is not connected", recoverySuggestion: "Connect it first.")
        }
        try await session.send(opcode, payload)
        log(id, session: session, direction: .toServer, opcode: opcode.rawValue, payload)
    }

    /// Close a WebSocket tab's session.
    public func disconnectWebSocket(_ id: Int64) async {
        guard let session = sockets.removeValue(forKey: id) else { return }
        await session.close()
        socketWatchers.removeValue(forKey: id)?.finish()
    }

    /// Whether a WebSocket tab's session is open.
    public func isWebSocketOpen(_ id: Int64) -> Bool { sockets[id]?.isOpen ?? false }

    /// A WebSocket tab's log for its current (or last) session.
    public func webSocketLog(_ id: Int64) -> [RepeaterWSEntry] { socketLogs[id] ?? [] }

    private func log(
        _ id: Int64, session: WebSocketSession, direction: WSDirection, opcode: UInt8, _ payload: [UInt8]
    ) {
        guard sockets[id] === session else { return }  // a reconnect replaced this session
        var entries = socketLogs[id] ?? []
        let entry = RepeaterWSEntry(id: entries.count, direction: direction, opcode: opcode, payload: payload)
        entries.append(entry)
        socketLogs[id] = entries
        socketWatchers[id]?.yield(entry)
    }

    private func ended(_ id: Int64, session: WebSocketSession) {
        guard sockets[id] === session else { return }
        sockets[id] = nil
        socketWatchers.removeValue(forKey: id)?.finish()
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
