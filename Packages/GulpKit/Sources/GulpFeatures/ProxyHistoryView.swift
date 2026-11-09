// GulpFeatures — Proxy → HTTP History (F05 HIS-001…HIS-006): filter chips, the paged table, and the
// read-only request/response viewer (Raw and Hex; the full editor arrives with M5).

#if canImport(AppKit)
import AppKit
import GulpCore
import GulpProxy
import GulpStore
import GulpWorkspace
import SwiftUI

/// Proxy → HTTP History.
public struct ProxyHistoryView: View {
    let store: ProjectStore
    let events: EventBus
    let sendToRepeater: (@MainActor ([ExchangeID]) -> Void)?
    /// Send to Comparer / Decoder (CMP-001, DEC-004), when the view knows the session.
    var sendToComparer: (@MainActor ([ExchangeID]) -> Void)?
    var sendToDecoder: (@MainActor (ExchangeID) -> Void)?
    /// Built once when the view appears: `View.init` runs on every parent re-render, and a model
    /// owns an event subscription and runs queries.
    @State private var model: HistoryModel?
    @AppStorage("gulp.history.sideBySide") private var sideBySide = true

    /// A History view over `store`, live-updated from `events`.
    public init(
        store: ProjectStore, events: EventBus, sendToRepeater: (@MainActor ([ExchangeID]) -> Void)? = nil
    ) {
        self.store = store
        self.events = events
        self.sendToRepeater = sendToRepeater
    }

    public var body: some View {
        if let model {
            VSplitView {
                VStack(spacing: 0) {
                    HistoryFilterBar(model: model)
                    Divider()
                    HistoryTableView(model: model)
                }
                .frame(minHeight: 180)
                messages(model)
                    .frame(minHeight: 160)
            }
            .navigationTitle("HTTP History")
        } else {
            ProgressView()
                .task {
                    let created = HistoryModel(store: store, events: events)
                    created.sendToRepeater = sendToRepeater
                    created.sendToComparer = sendToComparer
                    created.sendToDecoder = sendToDecoder
                    model = created
                }
        }
    }

    @ViewBuilder private func messages(_ model: HistoryModel) -> some View {
        let request = model.selected?.request.bytes
        Group {
            if sideBySide {
                HSplitView {
                    MessageViewer(title: "Request", bytes: request)
                    ResponsePane(exchange: model.selected)
                }
            } else {
                VSplitView {
                    MessageViewer(title: "Request", bytes: request)
                    ResponsePane(exchange: model.selected)
                }
            }
        }
        .toolbar {
            if let sendToRepeater {
                Button {
                    sendToRepeater(model.selectedIDs)
                } label: {
                    Label("Send to Repeater", systemImage: "arrow.triangle.2.circlepath")
                }
                .keyboardShortcut("r")
                .disabled(model.selectedIDs.isEmpty)
                .help("Open the selected requests in Repeater tabs (⌘R)")
            }
            Toggle(isOn: $sideBySide) {
                Label("Side by side", systemImage: "rectangle.split.2x1")
            }
            .help("Show request and response side by side or stacked (UI-050)")
        }
    }
}

/// The response, plus HIS-007's Events tab (one row per SSE event with its arrival time) for
/// `text/event-stream` and a chunk timeline for other streamed bodies.
struct ResponsePane: View {
    enum Tab: String, CaseIterable {
        case message = "Response"
        case events = "Events"
        case chunks = "Chunks"
    }

    let exchange: Exchange?
    @State private var tab = Tab.message

    var body: some View {
        let response = exchange?.response
        let marks = exchange?.timing.streamMarks ?? []
        let isEventStream = response.map(SSETimeline.isEventStream) ?? false
        let tabs = Tab.allCases.filter { tab in
            switch tab {
            case .message: true
            case .events: isEventStream
            case .chunks: !marks.isEmpty && !isEventStream
            }
        }
        VStack(spacing: 0) {
            if tabs.count > 1 {
                Picker("", selection: $tab) {
                    ForEach(tabs, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(4)
            }
            switch tabs.contains(tab) ? tab : .message {
            case .message:
                MessageViewer(title: "Response", bytes: response?.wireBytes)
            case .events:
                EventsTable(events: response.map { SSETimeline.events(in: $0, marks: marks) } ?? [])
            case .chunks:
                ChunkTimeline(marks: marks)
            }
        }
    }
}

/// HIS-007: SSE events — id, event, data, time.
struct EventsTable: View {
    struct Row: Identifiable {
        let id: Int
        let event: SSEEvent
    }

    let events: [SSEEvent]

    var body: some View {
        Table(events.enumerated().map { Row(id: $0.offset + 1, event: $0.element) }) {
            TableColumn("#") { Text("\($0.id)").monospacedDigit() }.width(40)
            TableColumn("id") { Text($0.event.id ?? "") }.width(70)
            TableColumn("event") { Text($0.event.event ?? "message") }.width(90)
            TableColumn("data") {
                Text($0.event.data).lineLimit(2).font(.system(.body, design: .monospaced))
            }
            TableColumn("time") { Text(ChunkTimeline.format($0.event.receivedMs)).monospacedDigit() }
                .width(80)
        }
    }
}

/// HIS-007: when each piece of a streamed body arrived.
struct ChunkTimeline: View {
    struct Row: Identifiable {
        let id: Int
        let mark: StreamMark
        let size: Int
    }

    let marks: [StreamMark]

    var body: some View {
        let rows = marks.enumerated().map { index, mark in
            Row(id: index + 1, mark: mark, size: mark.offset - (index > 0 ? marks[index - 1].offset : 0))
        }
        Table(rows) {
            TableColumn("#") { Text("\($0.id)").monospacedDigit() }.width(40)
            TableColumn("time") { Text(Self.format($0.mark.ms)).monospacedDigit() }.width(90)
            TableColumn("bytes") { Text("\($0.size)").monospacedDigit() }.width(80)
            TableColumn("total") { Text("\($0.mark.offset)").monospacedDigit() }
        }
    }

    static func format(_ ms: Double?) -> String {
        guard let ms else { return "" }
        return ms < 1_000 ? String(format: "%.0f ms", ms) : String(format: "%.2f s", ms / 1_000)
    }
}

/// Quick-filter chips and the search field (HIS-006).
struct HistoryFilterBar: View {
    @Bindable var model: HistoryModel

    var body: some View {
        HStack(spacing: 8) {
            TextField("Filter host or path", text: textBinding)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 260)
            Toggle("Hide assets", isOn: $model.filter.hideStaticAssets)
            Toggle("Has params", isOn: $model.filter.onlyWithParams)
            Toggle("Annotated", isOn: $model.filter.onlyAnnotated)
            ForEach(1...5, id: \.self) { statusClass in
                Toggle("\(statusClass)xx", isOn: statusBinding(statusClass))
            }
            Spacer()
            Toggle("Auto-scroll", isOn: $model.autoScroll)
            Text("\(model.rowCount) items")
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
        .toggleStyle(.button)
        .controlSize(.small)
        .padding(6)
    }

    private var textBinding: Binding<String> {
        Binding(
            get: { model.filter.text ?? "" },
            set: { model.filter.text = $0.isEmpty ? nil : $0 })
    }

    private func statusBinding(_ statusClass: Int) -> Binding<Bool> {
        Binding(
            get: { model.filter.statusClasses.contains(statusClass) },
            set: { on in
                if on {
                    model.filter.statusClasses.insert(statusClass)
                } else {
                    model.filter.statusClasses.remove(statusClass)
                }
            })
    }
}

/// A read-only message view with Raw and Hex tabs (HIS-003; doc 05 UI-010 subset).
struct MessageViewer: View {
    enum Mode: String, CaseIterable {
        case raw = "Raw"
        case hex = "Hex"
    }

    /// Text views get slow on huge bodies; longer messages are cut for display only.
    static let displayLimit = 1_024 * 1_024

    let title: String
    let bytes: Bytes?
    @State private var mode = Mode.raw

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(title).font(.headline)
                Spacer()
                Picker("", selection: $mode) {
                    ForEach(Mode.allCases, id: \.self) { Text($0.rawValue) }
                }
                .pickerStyle(.segmented)
                .fixedSize()
            }
            .padding(6)
            Divider()
            if let bytes {
                content(bytes)
            } else {
                Text("No message")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    @ViewBuilder private func content(_ bytes: Bytes) -> some View {
        let shown = bytes.count > Self.displayLimit ? bytes[0..<Self.displayLimit] : bytes
        switch mode {
        case .raw:
            RawTextView(text: shown.string())
        case .hex:
            let lines = (shown.count + 15) / 16
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(0..<lines, id: \.self) { line in
                        Text(Self.hexLine(shown, line))
                            .font(.system(.body, design: .monospaced))
                    }
                }
                .textSelection(.enabled)
                .padding(6)
            }
        }
    }

    /// One hex-dump line: offset, 16 bytes in hex, then printable ASCII.
    static func hexLine(_ bytes: Bytes, _ line: Int) -> String {
        let start = line * 16
        let end = min(start + 16, bytes.count)
        var hex = ""
        var ascii = ""
        for index in start..<end {
            let byte = bytes[index]
            hex += String(format: "%02x ", byte)
            ascii.append(byte >= 0x20 && byte < 0x7F ? Character(UnicodeScalar(byte)) : ".")
        }
        let padding = String(repeating: "   ", count: 16 - (end - start))
        return String(format: "%08x  ", start) + hex + padding + " " + ascii
    }
}

/// Read-only monospaced text in an `NSTextView` with non-contiguous layout, so a megabyte-sized
/// message lays out only what is on screen instead of blocking the main thread.
struct RawTextView: NSViewRepresentable {
    let text: String

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        if let view = scroll.documentView as? NSTextView {
            view.isEditable = false
            view.isSelectable = true
            view.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
            view.textContainerInset = NSSize(width: 4, height: 4)
            view.layoutManager?.allowsNonContiguousLayout = true
        }
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let view = scroll.documentView as? NSTextView, view.string != text else { return }
        view.string = text
    }
}

/// The project's proxy listeners (PRX-001): edit, apply, and see bind errors.
public struct ProxyListenersView: View {
    let session: ProjectSession
    @State private var listeners: [ProxyListenerConfig]
    @State private var status: [UUID: String] = [:]

    /// Listener settings for `session`.
    public init(session: ProjectSession) {
        self.session = session
        _listeners = State(initialValue: session.settings.get(ProxySettings.self).listeners)
    }

    public var body: some View {
        VStack(alignment: .leading) {
            Text("Proxy listeners").font(.headline)
            List {
                ForEach($listeners) { $listener in
                    HStack {
                        Toggle("Enabled", isOn: $listener.enabled).labelsHidden()
                        TextField("Bind address", text: $listener.bindAddress).frame(width: 160)
                        TextField("Port", value: $listener.port, format: .number).frame(width: 80)
                        Text(status[listener.id] ?? "—").foregroundStyle(.secondary)
                    }
                }
            }
            .frame(minHeight: 120)
            HStack {
                Button("Add") { listeners.append(ProxyListenerConfig(port: 8081)) }
                Button("Remove last") { _ = listeners.popLast() }.disabled(listeners.isEmpty)
                Spacer()
                Button("Apply") { apply() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(minWidth: 520, minHeight: 240)
    }

    private func apply() {
        let session = self.session
        let listeners = self.listeners
        Task {
            try? await session.settings.set(ProxySettings(listeners: listeners), scope: .project)
            await session.proxy.stopAll()
            let results = await session.startProxyListeners()
            var text: [UUID: String] = [:]
            for (id, result) in results {
                switch result {
                case .success(let port): text[id] = "Running on port \(port)"
                case .failure(let error): text[id] = error.message
                }
            }
            status = text
        }
    }
}
#endif

#if canImport(AppKit)
/// The History screen for a session. Loads the session's current store, and reloads when
/// `generation` changes (after Save As switches the project file).
public struct SessionHistoryView: View {
    let session: ProjectSession
    let generation: Int
    @State private var store: ProjectStore?

    /// History for `session`; bump `generation` after the project file changes.
    public init(session: ProjectSession, generation: Int) {
        self.session = session
        self.generation = generation
    }

    private func proxyHistory(_ store: ProjectStore) -> ProxyHistoryView {
        let session = self.session
        var view = ProxyHistoryView(store: store, events: session.events) { ids in
            Task { await session.sendToRepeater(ids) }
        }
        view.sendToComparer = { ids in Task { try? await session.sendToComparer(ids, part: .response) } }
        view.sendToDecoder = { id in Task { try? await session.sendToDecoder(id, part: .request) } }
        return view
    }

    public var body: some View {
        Group {
            if let store {
                proxyHistory(store)
                    .id(ObjectIdentifier(store))
            } else {
                ProgressView()
            }
        }
        .task(id: generation) {
            store = await session.store
        }
    }
}
#endif
