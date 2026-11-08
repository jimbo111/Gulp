// GulpFeatures — Proxy → WebSockets History (F01 PRX-032): the connection list, the selected
// connection's messages with direction/kind/text filters, and a viewer for the selected message.
// Updates from traffic are coalesced (at most one refresh per 100 ms, CLAUDE.md §4).

#if canImport(AppKit)
import AppKit
import GulpCore
import GulpStore
import GulpWorkspace
import Observation
import SwiftUI

/// State behind the WebSockets History view.
@MainActor
@Observable
public final class WebSocketHistoryModel {
    /// Every recorded connection, oldest first.
    public private(set) var connections: [WebSocketConnectionSummary] = []
    /// The selected connection.
    public var selectedConnection: Int64? {
        didSet { if oldValue != selectedConnection { loadMessages() } }
    }
    /// The selected connection's messages that pass `filter`.
    public private(set) var messages: [WebSocketMessageRecord] = []
    /// The selected message.
    public var selectedMessage: Int64?
    /// Message filters.
    public var filter = WebSocketMessageFilter() {
        didSet { applyFilter() }
    }

    @ObservationIgnored private var allMessages: [WebSocketMessageRecord] = []
    @ObservationIgnored private let store: ProjectStore
    @ObservationIgnored private var listener: Task<Void, Never>?
    @ObservationIgnored private var pendingRefresh: Task<Void, Never>?

    /// A model over `store`, live-updated from `events`.
    public init(store: ProjectStore, events: EventBus) {
        self.store = store
        listener = Task { [weak self] in
            for await delivery in await events.subscribe() {
                guard let self else { return }
                switch delivery.event {
                case .wsMessage, .wsConnectionChanged, nil: self.scheduleRefresh()
                default: break
                }
            }
        }
        refresh()
    }

    /// The selected message's record.
    public var message: WebSocketMessageRecord? {
        messages.first { $0.id == selectedMessage }
    }

    private func scheduleRefresh() {
        guard pendingRefresh == nil else { return }
        pendingRefresh = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(100))
            self?.pendingRefresh = nil
            self?.refresh()
        }
    }

    private func refresh() {
        let store = self.store
        Task { [weak self] in
            let connections = (try? await store.webSocketConnections()) ?? []
            guard let self else { return }
            self.connections = connections
            if self.selectedConnection == nil { self.selectedConnection = connections.last?.id }
            self.loadMessages()
        }
    }

    private func loadMessages() {
        guard let id = selectedConnection else {
            allMessages = []
            applyFilter()
            return
        }
        let store = self.store
        Task { [weak self] in
            let loaded = (try? await store.webSocketMessages(connection: id)) ?? []
            guard let self, self.selectedConnection == id else { return }
            self.allMessages = loaded
            self.applyFilter()
        }
    }

    private func applyFilter() {
        messages = allMessages.filter(filter.matches)
    }
}

/// Proxy → WebSockets History.
public struct WebSocketHistoryView: View {
    let store: ProjectStore
    let events: EventBus
    @State private var model: WebSocketHistoryModel?

    /// WebSockets History over `store`, live-updated from `events`.
    public init(store: ProjectStore, events: EventBus) {
        self.store = store
        self.events = events
    }

    public var body: some View {
        if let model {
            VSplitView {
                connections(model).frame(minHeight: 120)
                VStack(spacing: 0) {
                    WebSocketFilterBar(model: model)
                    Divider()
                    messages(model)
                }
                .frame(minHeight: 160)
                MessageViewer(title: "Message", bytes: model.message.map { Bytes($0.payload) })
                    .frame(minHeight: 120)
            }
            .navigationTitle("WebSockets History")
        } else {
            ProgressView()
                .task { model = WebSocketHistoryModel(store: store, events: events) }
        }
    }

    private func connections(_ model: WebSocketHistoryModel) -> some View {
        let selection = Binding(get: { model.selectedConnection }, set: { model.selectedConnection = $0 })
        return Table(model.connections, selection: selection) {
            TableColumn("#") { Text("\($0.id)").monospacedDigit() }.width(40)
            TableColumn("URL") { Text($0.url).lineLimit(1) }
            TableColumn("Messages") { Text("\($0.messageCount)").monospacedDigit() }.width(70)
            TableColumn("Status") { connection in
                if connection.closedAt == nil {
                    Text("Open").foregroundStyle(.green)
                } else {
                    Text(connection.closeCode.map { "Closed (\($0))" } ?? "Closed")
                        .foregroundStyle(.secondary)
                }
            }
            .width(110)
            TableColumn("Opened") { Text($0.openedAt, format: .dateTime.hour().minute().second()) }
                .width(80)
        }
    }

    private func messages(_ model: WebSocketHistoryModel) -> some View {
        let selection = Binding(get: { model.selectedMessage }, set: { model.selectedMessage = $0 })
        return Table(model.messages, selection: selection) {
            TableColumn("Direction") { message in
                Text(message.direction == WSDirection.toServer.rawValue ? "→ To server" : "← To client")
            }
            .width(100)
            TableColumn("Type") { Text(Self.opcodeName($0.opcode)) }.width(70)
            TableColumn("Length") { Text("\($0.payload.count)").monospacedDigit() }.width(70)
            TableColumn("Frames") { Text("\($0.frames.count)").monospacedDigit() }.width(55)
            TableColumn("Preview") {
                Text(Self.preview($0)).lineLimit(1).font(.system(.body, design: .monospaced))
            }
            TableColumn("Time") { Text($0.createdAt, format: .dateTime.hour().minute().second()) }.width(80)
        }
    }

    static func opcodeName(_ opcode: Int) -> String {
        switch opcode {
        case 1: "Text"
        case 2: "Binary"
        case 8: "Close"
        case 9: "Ping"
        case 10: "Pong"
        default: "Opcode \(opcode)"
        }
    }

    static func preview(_ message: WebSocketMessageRecord) -> String {
        if message.opcode == 1 { return String(decoding: message.payload.prefix(300), as: UTF8.self) }
        if message.opcode == 8, message.payload.count >= 2 {
            return "code \(Int(message.payload[0]) << 8 | Int(message.payload[1]))"
        }
        return message.payload.prefix(32).map { String(format: "%02x", $0) }.joined(separator: " ")
    }
}

/// Direction, kind and text filters for the message table.
struct WebSocketFilterBar: View {
    @Bindable var model: WebSocketHistoryModel

    var body: some View {
        HStack {
            Picker("Direction", selection: $model.filter.direction) {
                Text("Both").tag(WSDirection?.none)
                Text("To server").tag(WSDirection?.some(.toServer))
                Text("To client").tag(WSDirection?.some(.toClient))
            }
            .fixedSize()
            Picker("Type", selection: $model.filter.kind) {
                ForEach(WebSocketMessageFilter.Kind.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            .fixedSize()
            TextField("Filter text", text: $model.filter.text)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 260)
            Spacer()
            Text("\(model.messages.count) messages").foregroundStyle(.secondary)
        }
        .padding(6)
    }
}

/// WebSockets History for a session (follows Save As).
public struct SessionWebSocketHistoryView: View {
    let session: ProjectSession
    let generation: Int
    @State private var store: ProjectStore?

    /// WebSockets History for `session`; bump `generation` after the project file changes.
    public init(session: ProjectSession, generation: Int) {
        self.session = session
        self.generation = generation
    }

    public var body: some View {
        Group {
            if let store {
                WebSocketHistoryView(store: store, events: session.events)
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
