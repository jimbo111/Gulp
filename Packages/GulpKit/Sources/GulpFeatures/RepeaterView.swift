// GulpFeatures — the Repeater tool (F06 REP-001…REP-007, REP-016): a tab bar of requests, each with
// its target, version and options; Send (⌘↩) / Cancel; the response with status, length and time,
// the redirect chain, a streamed response as it arrives with its Events tab; and the tab's history
// (◀ ▶, ⌘[ ⌘]). The logic lives in `RepeaterService` (GulpRepeater, tested on Linux); this file
// only shows it.

#if canImport(AppKit)
import AppKit
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
    /// The selected tab's request, as edited.
    public var draft: [UInt8] = [] {
        didSet {
            guard !loading, draft != oldValue, let id = selectedID else { return }
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
    /// A streamed response as it arrives (REP-016).
    public private(set) var live: [UInt8] = []

    @ObservationIgnored private let session: ProjectSession
    @ObservationIgnored private var loading = false
    @ObservationIgnored private var listener: Task<Void, Never>?

    /// The Repeater of `session`.
    public init(session: ProjectSession) {
        self.session = session
        listener = Task { [weak self] in
            guard let opened = await self?.session.repeaterTabsOpened() else { return }
            for await id in opened {
                await self?.reload(select: id)
            }
        }
        // Opened by "Send to Repeater": the newest tab (just appended) is the one to show.
        Task { await reload(select: await session.repeater.allTabs.last?.id) }
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

    // MARK: tabs (REP-001, REP-005)

    /// Reload the tabs from the service, selecting `id` (or keeping the selection).
    func reload(select id: Int64?) async {
        tabs = await session.repeater.allTabs
        if let id {
            selectedID = id
        } else if selectedID == nil || selected == nil {
            selectedID = tabs.first?.id
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
        Task { await session.repeater.setTarget(id, target) }
    }

    // MARK: sending (REP-002, REP-016)

    /// Send the selected tab (⌘↩).
    public func send() {
        guard let id = selectedID, !sendingTabs.contains(id) else { return }
        commitTarget()
        guard targetError == nil else { return }
        sendingTabs.insert(id)
        live = []
        let repeater = session.repeater
        Task {
            let result = await repeater.send(id) { [weak self] bytes in
                Task { @MainActor in self?.received(bytes, for: id) }
            }
            sendingTabs.remove(id)
            guard selectedID == id else { return }
            history = await repeater.history(id)
            live = []
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

    private func received(_ bytes: [UInt8], for id: Int64) {
        guard selectedID == id, sendingTabs.contains(id) else { return }
        live += bytes
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
        let standard = tab.target.port == (tab.target.scheme == .https ? 443 : 80)
        let port = standard ? "" : ":\(tab.target.port)"
        targetText = "\(tab.target.scheme.rawValue)://\(tab.target.host)\(port)"
        targetError = nil
        chain = []
        shown = nil
        let id = tab.id
        Task {
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

    /// The Repeater for `session`.
    public init(session: ProjectSession) {
        _model = State(initialValue: RepeaterModel(session: session))
    }

    public var body: some View {
        VStack(spacing: 0) {
            tabBar
            Divider()
            if model.selected != nil {
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
                }
            }
        }
        .navigationTitle("Repeater")
        .alert("Rename tab", isPresented: renamingBinding) {
            TextField("Title", text: $newTitle)
            Button("Rename") {
                if let renaming { model.rename(renaming, to: newTitle) }
            }
            Button("Cancel", role: .cancel) {}
        }
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
            Button {
                model.newTab()
            } label: {
                Image(systemName: "plus")
            }
            .buttonStyle(.borderless)
            .help("New tab")
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
            Button("Close") { model.close(tab.id) }
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

    // MARK: response

    @ViewBuilder private var responseSide: some View {
        VStack(spacing: 0) {
            if model.isSending {
                MessageViewer(
                    title: "Response (receiving…)", bytes: model.live.isEmpty ? nil : Bytes(model.live))
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
#endif
