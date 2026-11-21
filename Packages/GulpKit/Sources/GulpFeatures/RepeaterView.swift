// GulpFeatures — the Repeater tool (F06 REP-001…REP-007, REP-016): a tab bar of requests, each with
// its target, version and options; Send (⌘↩) / Cancel; the response with status, length and time,
// the redirect chain, a streamed response as it arrives with its Events tab; and the tab's history
// (◀ ▶, ⌘[ ⌘]). The logic lives in `RepeaterService` (GulpRepeater, tested on Linux); this file
// only shows it.

#if canImport(AppKit)
import AppKit
import GulpCodec
import GulpCore
import GulpHTTP
import GulpRepeater
import GulpUI
import GulpWorkspace
import Observation
import SwiftUI

/// State behind the Repeater screen.
@MainActor
@Observable
public final class RepeaterModel {
    /// The tabs, in order.
    public private(set) var tabs: [RepeaterTab] = []
    /// The tab shown.
    public var selectedID: Int64? {
        didSet { if oldValue != selectedID { loadSelection() } }
    }
    /// The selected tab's request, as edited (saved to the tab here and in the service).
    public var draft: [UInt8] = [] {
        didSet {
            guard !loading, draft != oldValue, let id = selectedID else { return }
            if let index = tabs.firstIndex(where: { $0.id == id }) { tabs[index].draft = draft }
            let repeater = session.repeater
            let bytes = draft
            Task { await repeater.updateDraft(id, bytes: bytes) }
        }
    }
    /// The target field (`https://host:port`).
    public var targetText = ""
    /// Why the target field can't be used, if it can't.
    public private(set) var targetError: String?
    /// Tabs with a send in flight.
    public private(set) var sendingTabs: Set<Int64> = []
    /// The selected tab's sends, oldest first.
    public private(set) var history: [ExchangeID] = []
    /// Which of `history` is shown.
    public private(set) var historyIndex: Int?
    /// The exchange shown.
    public private(set) var shown: Exchange?
    /// The redirect hops before `shown` (from the last send).
    public private(set) var chain: [Exchange] = []
    /// The first `liveLimit` bytes of a streamed response as it arrives (REP-016), refreshed at most
    /// every 100 ms.
    public private(set) var live: [UInt8] = []
    /// How many bytes of the streamed response have arrived so far.
    public private(set) var liveTotal = 0
    /// A WebSocket tab's message log for its current session (REP-012).
    public private(set) var webSocketLog: [RepeaterWSEntry] = []
    /// Whether the selected WebSocket tab is connected.
    public private(set) var webSocketConnected = false
    /// Why the last WebSocket connect or send failed.
    public private(set) var webSocketError: String?
    /// The groups (REP-010).
    public private(set) var groups: [RepeaterGroup] = []
    /// The last group send's results, shown in a sheet.
    public var groupResults: [RepeaterGroupResult]?
    /// A group send is in flight.
    public private(set) var sendingGroup = false
    /// A send waiting on "Target is out of scope. Send anyway?" (TGT-023).
    public var scopeConfirmation: ScopeConfirmation?
    /// The selected tab's target is outside the project's scope (a warning badge).
    public private(set) var targetOutOfScope = false

    /// A send held for the out-of-scope confirmation.
    public enum ScopeConfirmation: Equatable, Identifiable {
        /// One tab.
        case tab(Int64, host: String)
        /// A group.
        case group(Int64)

        public var id: String {
            switch self {
            case .tab(let id, _): "tab-\(id)"
            case .group(let id): "group-\(id)"
            }
        }

        /// The host named in "don't ask again", for a single tab.
        public var host: String? {
            if case .tab(_, let host) = self { host } else { nil }
        }
    }

    @ObservationIgnored private let session: ProjectSession
    @ObservationIgnored private var loading = false
    @ObservationIgnored private var listener: Task<Void, Never>?
    @ObservationIgnored private var webSocketWatch: Task<Void, Never>?
    /// The streamed response shown live: its tab, the bytes not yet published, and the 100 ms tick
    /// that publishes them (CLAUDE.md §4).
    @ObservationIgnored private var liveTab: Int64?
    @ObservationIgnored private var livePending: [UInt8] = []
    @ObservationIgnored private var livePendingTotal = 0
    @ObservationIgnored private var liveTicker: Task<Void, Never>?

    /// The live view keeps at most this many bytes (what `MessageViewer` displays anyway).
    static let liveLimit = MessageViewer.displayLimit

    /// The Repeater of `session`. Follows "Send to Repeater" until `stop()`.
    public init(session: ProjectSession) {
        self.session = session
        listener = Task { [weak self] in
            guard let opened = await self?.session.repeaterTabsOpened() else { return }
            for await id in opened {
                guard let self else { return }
                await self.reload(select: id)
            }
        }
        // Opened by "Send to Repeater": the newest tab (just appended) is the one to show.
        Task { await reload(select: await session.repeater.allTabs.last?.id) }
    }

    /// Stop following the session (its window is closing).
    public func stop() {
        listener?.cancel()
        webSocketWatch?.cancel()
        endLive()
    }

    /// The selected tab.
    public var selected: RepeaterTab? { tabs.first { $0.id == selectedID } }

    /// Whether the selected tab is sending.
    public var isSending: Bool { selectedID.map { sendingTabs.contains($0) } ?? false }

    /// The selected tab's options (writes are saved).
    public var options: RepeaterOptions {
        get { selected?.options ?? RepeaterOptions() }
        set {
            guard let id = selectedID, let index = tabs.firstIndex(where: { $0.id == id }) else { return }
            tabs[index].options = newValue
            let repeater = session.repeater
            Task { await repeater.setOptions(id, newValue) }
        }
    }

    // MARK: gRPC (F33 GRP-004)

    /// The draft is a gRPC, gRPC-Web or Connect request.
    public var draftIsRPC: Bool { RPC.detect(RawRequest(Bytes(draft))) != nil }

    /// Edit message `index` of the draft by field path (`message=hi`, `3.1=x`) or with a whole JSON
    /// message, re-encoding it (raw bytes stay the truth: only this edit re-encodes). gRPC drafts get
    /// HTTP/2 when the version is Auto. Returns the error to show, or nil.
    public func editRPC(message index: Int, fields: [(path: String, value: String)], json: String?) -> String?
    {
        do {
            let edited = try session.editRPCRequest(
                RawRequest(Bytes(draft)), message: index, fields: fields, json: json)
            draft = edited.bytes.rawBytes
            if options.version == .auto, let target = HTTPTarget(url: targetText) {
                options.version = session.rpcRepeaterOptions(for: edited, target: target).version
            }
            return nil
        } catch {
            return "\(error)"
        }
    }

    // MARK: tabs (REP-001, REP-005)

    /// Reload the tabs from the service, selecting `id` (or keeping the selection).
    func reload(select id: Int64?) async {
        tabs = await session.repeater.allTabs
        groups = await session.repeater.allGroups
        if let id {
            selectedID = id
        } else if selectedID == nil || selected == nil {
            selectedID = tabs.first?.id
        }
    }

    /// A blank WebSocket tab (REP-012).
    public func newWebSocketTab() {
        let request = RawRequest(
            Bytes(
                "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"))
        let target = HTTPTarget(scheme: .https, host: "example.com", port: 443)
        var options = RepeaterOptions()
        options.isWebSocket = true
        Task {
            let tab = await session.repeater.openTab(
                request: request, target: target, title: "WS", options: options)
            await reload(select: tab.id)
        }
    }

    /// The selected WebSocket tab's message editor (saved with the tab).
    public var webSocketMessage: String {
        get { options.webSocketMessage }
        set {
            var changed = options
            changed.webSocketMessage = newValue
            options = changed
        }
    }

    /// Connect (or reconnect) the selected WebSocket tab: its request is the upgrade.
    public func connectWebSocket() {
        guard let id = selectedID else { return }
        commitTarget()
        guard targetError == nil else { return }
        webSocketError = nil
        webSocketLog = []
        webSocketWatch?.cancel()
        let repeater = session.repeater
        webSocketWatch = Task { [weak self] in
            do {
                let entries = try await repeater.connectWebSocket(id)
                self?.webSocketConnected = true
                self?.history = await repeater.history(id)
                for await entry in entries where self?.selectedID == id {
                    self?.webSocketLog.append(entry)
                }
            } catch {
                self?.webSocketError = ProjectSession.describe(error)
            }
            if self?.selectedID == id { self?.webSocketConnected = false }
        }
    }

    /// Close the selected WebSocket tab's session.
    public func disconnectWebSocket() {
        guard let id = selectedID else { return }
        let repeater = session.repeater
        Task { await repeater.disconnectWebSocket(id) }
    }

    /// Send the message editor's text on the selected WebSocket tab.
    public func sendWebSocketMessage(binary: Bool = false) {
        guard let id = selectedID else { return }
        let payload = Array(webSocketMessage.utf8)
        let repeater = session.repeater
        Task {
            do {
                try await repeater.sendWebSocket(id, binary ? .binary : .text, payload)
                webSocketError = nil
            } catch {
                webSocketError = ProjectSession.describe(error)
            }
        }
    }

    /// A blank tab.
    public func newTab() {
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        let target = HTTPTarget(scheme: .https, host: "example.com", port: 443)
        Task {
            let tab = await session.repeater.openTab(request: request, target: target)
            await reload(select: tab.id)
        }
    }

    /// Close a tab (a send in flight is cancelled).
    public func close(_ id: Int64) {
        Task {
            await session.repeater.close(id)
            if selectedID == id { selectedID = nil }
            await reload(select: nil)
        }
    }

    /// Reopen the last closed tab (⌘⇧T).
    public func reopenClosed() {
        Task {
            if let tab = await session.repeater.reopenClosed() { await reload(select: tab.id) }
        }
    }

    /// Rename a tab.
    public func rename(_ id: Int64, to title: String) {
        let trimmed = title.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        Task {
            await session.repeater.rename(id, to: trimmed)
            await reload(select: selectedID)
        }
    }

    /// Move a tab to `position`.
    public func move(_ id: Int64, to position: Int) {
        Task {
            await session.repeater.move(id, to: position)
            await reload(select: selectedID)
        }
    }

    // MARK: groups (REP-010)

    /// The selected tab's group.
    public var selectedGroup: RepeaterGroup? {
        guard let id = selected?.groupID else { return nil }
        return groups.first { $0.id == id }
    }

    /// The group of `tab`, if any.
    public func group(of tab: RepeaterTab) -> RepeaterGroup? {
        tab.groupID.flatMap { id in groups.first { $0.id == id } }
    }

    /// How many tabs a group has.
    public func memberCount(_ group: RepeaterGroup) -> Int { tabs.filter { $0.groupID == group.id }.count }

    /// Start a new group holding `tab`.
    public func newGroup(with tab: Int64) {
        let name = "Group \(groups.count + 1)"
        Task {
            await session.repeater.createGroup(name: name, tabs: [tab])
            await reload(select: selectedID)
        }
    }

    /// Put `tab` in `group` (nil takes it out).
    public func assign(_ tab: Int64, to group: Int64?) {
        Task {
            await session.repeater.assign(tab, to: group)
            await reload(select: selectedID)
        }
    }

    /// Change the selected group's send mode.
    public func setGroupMode(_ mode: RepeaterGroup.Mode) {
        guard var group = selectedGroup else { return }
        group.mode = mode
        if let index = groups.firstIndex(where: { $0.id == group.id }) { groups[index] = group }
        let changed = group
        Task { await session.repeater.update(changed) }
    }

    /// "Send group": the selected tab's group goes out in its mode; results show in a sheet. An
    /// out-of-scope member asks first (TGT-023).
    public func sendGroup() {
        guard let group = selectedGroup, !sendingGroup else { return }
        Task {
            if await session.scopeDecision(forRepeaterGroup: group.id) == .confirm {
                scopeConfirmation = .group(group.id)
            } else {
                performGroupSend(group.id)
            }
        }
    }

    /// Answer the out-of-scope confirmation for `pending`: send (optionally never asking again for
    /// that host) or drop the send. (The alert passes its own copy: SwiftUI may clear
    /// `scopeConfirmation` before or after the button's action runs.)
    public func confirmScope(_ pending: ScopeConfirmation, send: Bool, dontAskAgain: Bool = false) {
        scopeConfirmation = nil
        guard send else { return }
        switch pending {
        case .tab(let id, let host):
            Task {
                if dontAskAgain { await session.allowOutOfScopeSends(to: host) }
                performSend(id)
            }
        case .group(let id):
            performGroupSend(id)
        }
    }

    private func performGroupSend(_ groupID: Int64) {
        guard let group = groups.first(where: { $0.id == groupID }), !sendingGroup else { return }
        sendingGroup = true
        let repeater = session.repeater
        Task {
            let results = await repeater.sendGroup(group.id)
            sendingGroup = false
            groupResults = results
            if let id = selectedID { history = await repeater.history(id) }
        }
    }

    /// A tab's title (for the results table).
    public func title(of tab: Int64) -> String { tabs.first { $0.id == tab }?.title ?? "#\(tab)" }

    // MARK: target (REP-003)

    /// Apply the target field.
    public func commitTarget() {
        guard let id = selectedID else { return }
        guard let target = HTTPTarget(url: targetText.trimmingCharacters(in: .whitespaces)) else {
            targetError = "Use scheme://host[:port], e.g. https://example.com"
            return
        }
        targetError = nil
        if let index = tabs.firstIndex(where: { $0.id == id }) { tabs[index].target = target }
        Task {
            await session.repeater.setTarget(id, target)
            await refreshScopeBadge()
        }
    }

    /// Recompute the out-of-scope badge for the selected tab.
    func refreshScopeBadge() async {
        guard let id = selectedID, let target = selected?.target else { return }
        let decision = await session.scopeDecision(for: target, request: draft)
        if selectedID == id { targetOutOfScope = decision == .confirm }
    }

    // MARK: sending (REP-002, REP-016)

    /// Send the selected tab (⌘↩). An out-of-scope target asks first (TGT-023).
    public func send() {
        guard let id = selectedID, !sendingTabs.contains(id) else { return }
        commitTarget()
        guard targetError == nil else { return }
        guard let target = selected?.target else { return }
        let request = draft
        Task {
            if await session.scopeDecision(for: target, request: request) == .confirm {
                scopeConfirmation = .tab(id, host: target.host)
            } else {
                performSend(id)
            }
        }
    }

    private func performSend(_ id: Int64) {
        guard !sendingTabs.contains(id) else { return }
        sendingTabs.insert(id)
        beginLive(for: id)
        let repeater = session.repeater
        // Chunks arrive in order on one stream; the main actor only buffers them, and the 100 ms
        // tick publishes.
        let (chunks, delivery) = AsyncStream.makeStream(of: [UInt8].self)
        Task { [weak self] in
            for await bytes in chunks {
                guard let self else { return }
                self.received(bytes, for: id)
            }
        }
        Task {
            let result = await repeater.send(id) { bytes in delivery.yield(bytes) }
            delivery.finish()
            sendingTabs.remove(id)
            if liveTab == id { endLive() }
            guard selectedID == id else { return }
            history = await repeater.history(id)
            if let result {
                shown = result.exchange
                chain = result.redirectChain
                historyIndex = history.isEmpty ? nil : history.count - 1
            }
        }
    }

    /// Stop the selected tab's send; what arrived is kept in its history.
    public func cancel() {
        guard let id = selectedID else { return }
        let repeater = session.repeater
        Task { await repeater.cancel(id) }
    }

    /// Whether the live view belongs to the selected tab.
    public var showsLive: Bool { isSending && liveTab == selectedID }

    /// Start showing tab `id`'s streamed response.
    func beginLive(for id: Int64) {
        endLive()
        liveTab = id
        liveTicker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(100))
                guard let self else { return }
                self.publishLive()
            }
        }
    }

    /// Buffer a streamed chunk; only the first `liveLimit` bytes are kept.
    func received(_ bytes: [UInt8], for id: Int64) {
        guard liveTab == id else { return }
        livePendingTotal += bytes.count
        let room = Self.liveLimit - live.count - livePending.count
        if room > 0 { livePending += bytes.prefix(room) }
    }

    private func publishLive() {
        if !livePending.isEmpty {
            live += livePending
            livePending = []
        }
        if liveTotal != livePendingTotal { liveTotal = livePendingTotal }
    }

    /// Drop the live view (the send finished, or another began).
    func endLive() {
        liveTicker?.cancel()
        liveTicker = nil
        liveTab = nil
        livePending = []
        livePendingTotal = 0
        live = []
        liveTotal = 0
    }

    // MARK: history (REP-004)

    /// Show the previous (-1) or next (+1) send.
    public func step(_ delta: Int) {
        guard let index = historyIndex else { return }
        show(at: index + delta)
    }

    /// Whether `step(delta)` has somewhere to go.
    public func canStep(_ delta: Int) -> Bool {
        guard let index = historyIndex else { return false }
        return history.indices.contains(index + delta)
    }

    /// Show one hop of the last send's redirect chain (or the final response for nil).
    public func showHop(_ exchange: Exchange) {
        shown = exchange
    }

    private func show(at index: Int) {
        guard history.indices.contains(index) else { return }
        historyIndex = index
        chain = []
        let id = history[index]
        let session = self.session
        Task {
            let store = await session.store
            shown = try? await store.exchange(id: id)
        }
    }

    private func loadSelection() {
        loading = true
        defer { loading = false }
        guard let tab = selected else {
            draft = []
            targetText = ""
            history = []
            historyIndex = nil
            shown = nil
            chain = []
            return
        }
        draft = tab.draft
        webSocketWatch?.cancel()
        webSocketWatch = nil
        webSocketError = nil
        let selectedTab = tab.id
        let repeater = session.repeater
        Task {
            webSocketLog = await repeater.webSocketLog(selectedTab)
            webSocketConnected = await repeater.isWebSocketOpen(selectedTab)
        }
        let standard = tab.target.port == (tab.target.scheme == .https ? 443 : 80)
        let port = standard ? "" : ":\(tab.target.port)"
        targetText = "\(tab.target.scheme.rawValue)://\(tab.target.host)\(port)"
        targetError = nil
        chain = []
        shown = nil
        let id = tab.id
        Task {
            await refreshScopeBadge()
            history = await session.repeater.history(id)
            guard !history.isEmpty, selectedID == id else {
                historyIndex = nil
                return
            }
            show(at: history.count - 1)
        }
    }
}

/// Proxy → Repeater.
public struct RepeaterView: View {
    @State private var model: RepeaterModel
    @State private var renaming: Int64?
    @State private var newTitle = ""
    @State private var showOptions = false
    @State private var showRPCEditor = false

    /// The Repeater for `session`.
    public init(session: ProjectSession) {
        _model = State(initialValue: RepeaterModel(session: session))
    }

    public var body: some View {
        VStack(spacing: 0) {
            tabBar
            Divider()
            if let tab = model.selected, tab.options.isWebSocket {
                webSocketControls
                Divider()
                HSplitView {
                    MessageEditor(title: "Upgrade request", bytes: $model.draft, editable: true)
                        .frame(minWidth: 280)
                    webSocketSide.frame(minWidth: 320)
                }
            } else if model.selected != nil {
                controls
                Divider()
                HSplitView {
                    MessageEditor(title: "Request", bytes: $model.draft, editable: true)
                        .frame(minWidth: 280)
                    responseSide.frame(minWidth: 280)
                }
            } else {
                ContentUnavailableView {
                    Label("No Repeater tabs", systemImage: "arrow.triangle.2.circlepath")
                } description: {
                    Text("Send a request here from HTTP History (⌘R), or start a blank tab.")
                } actions: {
                    Button("New Tab") { model.newTab() }
                    Button("New WebSocket Tab") { model.newWebSocketTab() }
                }
            }
        }
        .navigationTitle("Repeater")
        .sheet(isPresented: groupResultsShown) { groupResultsSheet }
        .alert(
            "Target is out of scope. Send anyway?", isPresented: scopeConfirmationShown,
            presenting: model.scopeConfirmation
        ) { pending in
            Button("Send Anyway") { model.confirmScope(pending, send: true) }
            if let host = pending.host {
                Button("Send, and Don't Ask Again for \(host)") {
                    model.confirmScope(pending, send: true, dontAskAgain: true)
                }
            }
            Button("Cancel", role: .cancel) { model.confirmScope(pending, send: false) }
        } message: { _ in
            Text("Change the scope in Target → Scope to stop this question for this host.")
        }
        .alert("Rename tab", isPresented: renamingBinding) {
            TextField("Title", text: $newTitle)
            Button("Rename") {
                if let renaming { model.rename(renaming, to: newTitle) }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private var scopeConfirmationShown: Binding<Bool> {
        Binding(
            get: { model.scopeConfirmation != nil },
            set: { if !$0 { model.scopeConfirmation = nil } })
    }

    private var groupResultsShown: Binding<Bool> {
        Binding(get: { model.groupResults != nil }, set: { if !$0 { model.groupResults = nil } })
    }

    /// REP-010 / HTTP-035: the group send's results, with each request's final-write offset.
    private var groupResultsSheet: some View {
        let results = model.groupResults ?? []
        let spread = results.compactMap(\.exchange.timing.finalWriteOffsetMs).max()
        return VStack(alignment: .leading, spacing: 8) {
            Text("Group results").font(.headline)
            if let spread {
                Text(String(format: "Final writes spread over %.2f ms", spread)).foregroundStyle(.secondary)
            }
            Table(results) {
                TableColumn("Tab") { Text(model.title(of: $0.tabID)) }
                TableColumn("Status") { result in
                    Text(
                        result.exchange.response.map { String($0.parsed.statusCode) }
                            ?? (result.error?.code ?? "–"))
                }
                .width(60)
                TableColumn("Length") { Text("\($0.exchange.response?.bytes.count ?? 0)").monospacedDigit() }
                    .width(70)
                TableColumn("Time") {
                    Text($0.exchange.timing.totalMs.map { String(format: "%.0f ms", $0) } ?? "–")
                }
                .width(80)
                TableColumn("Final write") { result in
                    Text(
                        result.exchange.timing.finalWriteOffsetMs.map { String(format: "+%.2f ms", $0) }
                            ?? "–")
                }
                .width(90)
            }
            .frame(minWidth: 520, minHeight: 240)
            HStack {
                Spacer()
                Button("Done") { model.groupResults = nil }.keyboardShortcut(.defaultAction)
            }
        }
        .padding()
    }

    private var renamingBinding: Binding<Bool> {
        Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })
    }

    // MARK: tab bar

    private var tabBar: some View {
        HStack(spacing: 4) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(Array(model.tabs.enumerated()), id: \.element.id) { index, tab in
                        tabChip(tab, at: index)
                    }
                }
                .padding(.horizontal, 4)
            }
            Menu {
                Button("New Tab") { model.newTab() }
                Button("New WebSocket Tab") { model.newWebSocketTab() }
            } label: {
                Image(systemName: "plus")
            } primaryAction: {
                model.newTab()
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .help("New tab (hold for a WebSocket tab)")
            Button {
                model.reopenClosed()
            } label: {
                Image(systemName: "arrow.uturn.backward")
            }
            .buttonStyle(.borderless)
            .keyboardShortcut("t", modifiers: [.command, .shift])
            .help("Reopen closed tab (⌘⇧T)")
        }
        .padding(4)
    }

    private func tabChip(_ tab: RepeaterTab, at index: Int) -> some View {
        let isSelected = tab.id == model.selectedID
        return HStack(spacing: 4) {
            if let group = model.group(of: tab) {
                RoundedRectangle(cornerRadius: 2)
                    .fill(Self.color(group.color))
                    .frame(width: 4, height: 14)
                    .help("Group: \(group.name)")
            }
            if model.sendingTabs.contains(tab.id) {
                Circle().fill(.orange).frame(width: 6, height: 6)
            }
            Text(tab.title).lineLimit(1)
            Button {
                model.close(tab.id)
            } label: {
                Image(systemName: "xmark").font(.caption2)
            }
            .buttonStyle(.borderless)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(isSelected ? Color.accentColor.opacity(0.2) : Color.clear, in: .rect(cornerRadius: 5))
        .contentShape(Rectangle())
        .onTapGesture(count: 2) {
            newTitle = tab.title
            renaming = tab.id
        }
        .onTapGesture { model.selectedID = tab.id }
        .draggable(String(tab.id))
        .dropDestination(for: String.self) { items, _ in
            guard let dragged = items.first.flatMap(Int64.init) else { return false }
            model.move(dragged, to: index)
            return true
        }
        .contextMenu {
            Button("Rename…") {
                newTitle = tab.title
                renaming = tab.id
            }
            Button("Move Left") { model.move(tab.id, to: max(0, index - 1)) }.disabled(index == 0)
            Button("Move Right") { model.move(tab.id, to: index + 1) }
                .disabled(index == model.tabs.count - 1)
            Divider()
            Menu("Group") {
                Button("New Group") { model.newGroup(with: tab.id) }
                ForEach(model.groups) { group in
                    Button("Add to \(group.name)") { model.assign(tab.id, to: group.id) }
                        .disabled(tab.groupID == group.id)
                }
                if tab.groupID != nil {
                    Divider()
                    Button("Remove from Group") { model.assign(tab.id, to: nil) }
                }
            }
            Divider()
            Button("Close") { model.close(tab.id) }
        }
    }

    static func color(_ name: String) -> Color {
        switch name {
        case "red": .red
        case "orange": .orange
        case "green": .green
        case "purple": .purple
        default: .blue
        }
    }

    // MARK: controls (REP-002, REP-003, REP-004, REP-006, REP-007)

    private var controls: some View {
        HStack(spacing: 8) {
            if model.isSending {
                Button("Cancel") { model.cancel() }
                    .keyboardShortcut(".", modifiers: .command)
            } else {
                Button("Send") { model.send() }
                    .keyboardShortcut(.return, modifiers: .command)
                    .buttonStyle(.borderedProminent)
            }
            TextField("https://host:port", text: $model.targetText)
                .textFieldStyle(.roundedBorder)
                .frame(minWidth: 200, maxWidth: 320)
                .onSubmit { model.commitTarget() }
                .help(model.targetError ?? "Where requests go (the Host header is sent as written)")
            if let error = model.targetError {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.yellow).help(error)
            } else if model.targetOutOfScope {
                Label("Out of scope", systemImage: "scope")
                    .font(.caption).foregroundStyle(.orange)
                    .help("This target is outside the project's scope (Target → Scope).")
            }
            Picker("Version", selection: optionBinding(\.version)) {
                Text("Auto").tag(RepeaterOptions.Version.auto)
                Text("HTTP/1.1").tag(RepeaterOptions.Version.http1_1)
                Text("HTTP/2").tag(RepeaterOptions.Version.http2)
                Text("h2c").tag(RepeaterOptions.Version.http2PriorKnowledge)
            }
            .labelsHidden()
            .fixedSize()
            Button {
                showOptions.toggle()
            } label: {
                Image(systemName: "slider.horizontal.3")
            }
            .help("Send options")
            .popover(isPresented: $showOptions) { optionsForm.padding().frame(width: 300) }
            if model.draftIsRPC {
                Button {
                    showRPCEditor = true
                } label: {
                    Label("Edit Message", systemImage: "curlybraces")
                }
                .help("Edit a protobuf field or the whole message as JSON; the call is re-encoded (F33)")
                .sheet(isPresented: $showRPCEditor) { RPCMessageEditor(model: model) }
            }
            if let group = model.selectedGroup {
                Divider().frame(height: 16)
                Picker("Group mode", selection: Binding(get: { group.mode }, set: { model.setGroupMode($0) }))
                {
                    Text("Single packet").tag(RepeaterGroup.Mode.singlePacket)
                    Text("Parallel").tag(RepeaterGroup.Mode.parallel)
                    Text("Sequential").tag(RepeaterGroup.Mode.sequential)
                    Text("Separate connections").tag(RepeaterGroup.Mode.separate)
                }
                .labelsHidden()
                .fixedSize()
                Button(model.sendingGroup ? "Sending group…" : "Send group (\(model.memberCount(group)))") {
                    model.sendGroup()
                }
                .disabled(model.sendingGroup)
                .help("Send every tab in \(group.name) together (the race-condition workflow)")
            }
            Spacer()
            Button {
                model.step(-1)
            } label: {
                Image(systemName: "chevron.left")
            }
            .disabled(!model.canStep(-1))
            .keyboardShortcut("[", modifiers: .command)
            Text(historyLabel).monospacedDigit().foregroundStyle(.secondary)
            Button {
                model.step(1)
            } label: {
                Image(systemName: "chevron.right")
            }
            .disabled(!model.canStep(1))
            .keyboardShortcut("]", modifiers: .command)
        }
        .controlSize(.small)
        .padding(6)
    }

    private var historyLabel: String {
        guard let index = model.historyIndex else { return "–" }
        return "\(index + 1)/\(model.history.count)"
    }

    private var optionsForm: some View {
        Form {
            Toggle("Update Content-Length", isOn: optionBinding(\.updateContentLength))
            Toggle("Evaluate Transform Tags («op{…}»)", isOn: optionBinding(\.transformTags))
                .help("Off sends tags as literal text (F12 DEC-022)")
            Picker("Follow redirects", selection: optionBinding(\.redirects)) {
                Text("Never").tag(RepeaterOptions.Redirects.never)
                Text("On-site").tag(RepeaterOptions.Redirects.onSite)
                Text("In scope").tag(RepeaterOptions.Redirects.inScope)
                Text("Always").tag(RepeaterOptions.Redirects.always)
            }
            Stepper(
                "Max hops: \(model.options.maxRedirects)", value: optionBinding(\.maxRedirects), in: 1...30)
            Toggle("New connection for each send", isOn: optionBinding(\.newConnection))
            Toggle("Check the server certificate", isOn: optionBinding(\.validateCertificates))
            Stepper(
                "Timeout: \(model.options.timeoutSeconds) s", value: optionBinding(\.timeoutSeconds),
                in: 1...600)
        }
    }

    private func optionBinding<Value>(_ path: WritableKeyPath<RepeaterOptions, Value>) -> Binding<Value> {
        Binding(
            get: { model.options[keyPath: path] },
            set: { value in
                var options = model.options
                options[keyPath: path] = value
                model.options = options
            })
    }

    // MARK: WebSocket tabs (REP-012)

    private var webSocketControls: some View {
        HStack(spacing: 8) {
            if model.webSocketConnected {
                Button("Disconnect") { model.disconnectWebSocket() }
                Button("Reconnect") { model.connectWebSocket() }
            } else {
                Button("Connect") { model.connectWebSocket() }
                    .keyboardShortcut(.return, modifiers: .command)
                    .buttonStyle(.borderedProminent)
            }
            TextField("https://host:port", text: $model.targetText)
                .textFieldStyle(.roundedBorder)
                .frame(minWidth: 200, maxWidth: 320)
                .onSubmit { model.commitTarget() }
            Circle()
                .fill(model.webSocketConnected ? Color.green : Color.secondary)
                .frame(width: 8, height: 8)
                .help(model.webSocketConnected ? "Connected" : "Not connected")
            if let error = model.webSocketError {
                Text(error).foregroundStyle(.red).lineLimit(1)
            }
            Spacer()
        }
        .controlSize(.small)
        .padding(6)
    }

    private var webSocketSide: some View {
        VSplitView {
            List(model.webSocketLog) { entry in
                HStack(alignment: .top) {
                    Text(entry.direction == .toServer ? "→" : "←").foregroundStyle(.secondary)
                    Text(Self.opcodeName(entry.opcode)).foregroundStyle(.secondary).frame(
                        width: 48, alignment: .leading)
                    Text(String(decoding: entry.payload.prefix(2_000), as: UTF8.self))
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            .frame(minHeight: 160)
            VStack(alignment: .leading, spacing: 4) {
                TextEditor(text: $model.webSocketMessage)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 80)
                HStack {
                    Button("Send") { model.sendWebSocketMessage() }
                        .keyboardShortcut(.return, modifiers: [.command, .shift])
                        .disabled(!model.webSocketConnected)
                    Button("Send as binary") { model.sendWebSocketMessage(binary: true) }
                        .disabled(!model.webSocketConnected)
                    Spacer()
                }
                .controlSize(.small)
            }
            .padding(6)
        }
    }

    static func opcodeName(_ opcode: UInt8) -> String {
        switch opcode {
        case 1: "text"
        case 2: "binary"
        case 8: "close"
        case 9: "ping"
        case 10: "pong"
        default: "op \(opcode)"
        }
    }

    // MARK: response

    @ViewBuilder private var responseSide: some View {
        VStack(spacing: 0) {
            if model.showsLive {
                MessageViewer(
                    title: "Response (receiving… \(model.liveTotal) bytes)",
                    bytes: model.live.isEmpty ? nil : Bytes(model.live))
            } else {
                ResponsePane(exchange: model.shown)
            }
            Divider()
            statusLine
            if !model.chain.isEmpty { redirectChain }
        }
    }

    private var statusLine: some View {
        HStack(spacing: 10) {
            if let exchange = model.shown {
                if let response = exchange.response {
                    Text("\(response.parsed.statusCode)").bold()
                    Text("\(response.bytes.count) bytes")
                }
                if case .failed(let error) = exchange.state {
                    Text(error.userDescription).foregroundStyle(.red)
                }
                if let total = exchange.timing.totalMs { Text(String(format: "%.0f ms", total)) }
                Text(exchange.httpVersion == .http2 ? "HTTP/2" : "HTTP/1.1")
                if let tls = exchange.tls {
                    Text([tls.version, tls.alpn].compactMap { $0 }.joined(separator: " · "))
                }
                if exchange.connectionID != 0 { Text("connection #\(exchange.connectionID)") }
            } else {
                Text(model.isSending ? "Sending…" : "Not sent yet")
            }
            Spacer()
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(6)
    }

    private var redirectChain: some View {
        HStack(spacing: 6) {
            Text("Redirects:").font(.caption).foregroundStyle(.secondary)
            ForEach(Array(model.chain.enumerated()), id: \.offset) { index, hop in
                Button("\(index + 1). \(hop.response.map { String($0.parsed.statusCode) } ?? "–")") {
                    model.showHop(hop)
                }
                .buttonStyle(.link)
            }
            Spacer()
        }
        .padding(.horizontal, 6)
        .padding(.bottom, 6)
    }
}
/// Edit a message of an RPC draft (F33 GRP-004): field edits as `path=value` lines, or a whole
/// message as JSON (needs a schema for protobuf bodies).
struct RPCMessageEditor: View {
    let model: RepeaterModel
    @Environment(\.dismiss) private var dismiss
    @State private var message = 1
    @State private var fields = ""
    @State private var json = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Edit Message").font(.title2)
            Stepper("Message \(message)", value: $message, in: 1...999)
            Text("Fields, one per line: path=value (names with a schema, else numbers, e.g. 3.1=x)")
                .font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $fields).font(.system(.body, design: .monospaced)).frame(minHeight: 80)
            Text("Or the whole message as JSON").font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $json).font(.system(.body, design: .monospaced)).frame(minHeight: 80)
            if let error { Text(error).foregroundStyle(.red).font(.caption) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                Button("Apply") { apply() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(minWidth: 460, minHeight: 360)
    }

    func apply() {
        var edits: [(path: String, value: String)] = []
        for line in fields.split(whereSeparator: \.isNewline)
        where !line.trimmingCharacters(in: .whitespaces).isEmpty {
            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else {
                error = "Expected path=value: \(line)"
                return
            }
            edits.append((String(parts[0]).trimmingCharacters(in: .whitespaces), String(parts[1])))
        }
        let trimmed = json.trimmingCharacters(in: .whitespacesAndNewlines)
        error = model.editRPC(message: message - 1, fields: edits, json: trimmed.isEmpty ? nil : trimmed)
        if error == nil { dismiss() }
    }
}
#endif
