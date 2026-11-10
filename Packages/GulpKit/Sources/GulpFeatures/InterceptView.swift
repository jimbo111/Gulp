// GulpFeatures — Proxy → Intercept (F01 PRX-010, PRX-011, PRX-014): the toggles, the queue with
// time waiting, the held message in an editable MessageEditor, and Forward / Drop / all.

#if canImport(AppKit)
import GulpCore
import GulpProxy
import GulpUI
import GulpWorkspace
import SwiftUI

/// State behind the Intercept screen.
@MainActor
@Observable
final class InterceptModel {
    private(set) var items: [InterceptItem] = []
    var selectedID: InterceptItemID? {
        didSet { loadSelection() }
    }
    /// The selected item's message as edited in the editor.
    var editing: [UInt8] = []
    private(set) var interceptRequests = false
    private(set) var interceptResponses = false
    private(set) var interceptWebSockets = false

    @ObservationIgnored private let session: ProjectSession
    @ObservationIgnored private var listener: Task<Void, Never>?
    @ObservationIgnored private var original: [UInt8] = []

    init(session: ProjectSession) {
        self.session = session
        let stored = session.settings.get(InterceptSettings.self)
        interceptRequests = stored.interceptRequests
        interceptResponses = stored.interceptResponses
        interceptWebSockets = stored.interceptWebSockets
        let events = session.events
        listener = Task { [weak self] in
            for await delivery in await events.subscribe() {
                guard let self else { return }
                if case .interceptQueued = delivery.event { await self.refresh() }
            }
        }
        Task { await refresh() }
    }

    var selected: InterceptItem? { items.first { $0.id == selectedID } }

    func refresh() async {
        items = await session.intercept.items
        if selectedID == nil || selected == nil { selectedID = items.first?.id }
    }

    private func loadSelection() {
        guard let item = selected else {
            editing = []
            original = []
            return
        }
        switch item.kind {
        case .request: original = item.request.bytes.rawBytes
        case .response: original = item.response?.wireBytes.rawBytes ?? []
        case .webSocket: original = item.webSocketPayload ?? []
        }
        editing = original
    }

    /// Forward the selected item, with the edits if there are any (PRX-012).
    func forward() {
        guard let id = selectedID else { return }
        let edited = editing == original ? nil : Bytes(editing)
        decide(id, .forward(edited))
    }

    /// Drop the selected item.
    func drop() {
        guard let id = selectedID else { return }
        decide(id, .drop)
    }

    func decideAll(_ decision: InterceptDecision) {
        let queue = session.intercept
        Task {
            await queue.decideAll(decision)
            selectedID = nil
            await refresh()
        }
    }

    private func decide(_ id: InterceptItemID, _ decision: InterceptDecision) {
        let queue = session.intercept
        Task {
            await queue.decide(id, decision)
            selectedID = nil
            await refresh()
        }
    }

    /// Turn request, response or WebSocket interception on or off (stored in the project,
    /// PRX-010/014/033).
    func setIntercepting(requests: Bool? = nil, responses: Bool? = nil, webSockets: Bool? = nil) {
        var stored = session.settings.get(InterceptSettings.self)
        if let webSockets {
            stored.interceptWebSockets = webSockets
            interceptWebSockets = webSockets
        }
        if let requests {
            stored.interceptRequests = requests
            interceptRequests = requests
        }
        if let responses {
            stored.interceptResponses = responses
            interceptResponses = responses
        }
        let session = self.session
        let value = stored
        Task {
            try? await session.setInterceptSettings(value)
            await refresh()
        }
    }
}

/// Proxy → Intercept.
public struct InterceptView: View {
    @State private var model: InterceptModel
    @State private var editingRules = false
    let session: ProjectSession

    /// The Intercept screen for `session`.
    public init(session: ProjectSession) {
        _model = State(initialValue: InterceptModel(session: session))
        self.session = session
    }

    public var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Toggle(
                    "Intercept is \(model.interceptRequests ? "on" : "off")",
                    isOn: Binding(
                        get: { model.interceptRequests }, set: { model.setIntercepting(requests: $0) })
                )
                .keyboardShortcut("i", modifiers: [.command, .shift])
                Toggle(
                    "Responses",
                    isOn: Binding(
                        get: { model.interceptResponses }, set: { model.setIntercepting(responses: $0) }))
                Toggle(
                    "WebSockets",
                    isOn: Binding(
                        get: { model.interceptWebSockets }, set: { model.setIntercepting(webSockets: $0) }))
                Button("Rules…") { editingRules = true }
                    .help("Which requests, responses and WebSocket connections are held")
                Spacer()
                Button("Forward") { model.forward() }
                    .keyboardShortcut("f", modifiers: [.command, .option])
                    .disabled(model.selected == nil)
                Button("Drop") { model.drop() }
                    .keyboardShortcut("x", modifiers: [.command, .option])
                    .disabled(model.selected == nil)
                Button("Forward all") { model.decideAll(.forward(nil)) }.disabled(model.items.isEmpty)
                Button("Drop all") { model.decideAll(.drop) }.disabled(model.items.isEmpty)
            }
            .toggleStyle(.button)
            .controlSize(.small)
            .padding(6)
            Divider()
            VSplitView {
                queue.frame(minHeight: 100, idealHeight: 160)
                if let item = model.selected {
                    MessageEditor(title: Self.title(item), bytes: $model.editing, editable: true)
                        .frame(minHeight: 200)
                } else {
                    let on = model.interceptRequests || model.interceptResponses || model.interceptWebSockets
                    ContentUnavailableView(
                        on ? "Nothing held" : "Intercept is off",
                        systemImage: "hand.raised",
                        description: Text("Matching requests wait here until you forward or drop them."))
                }
            }
        }
        .navigationTitle("Intercept")
        .sheet(isPresented: $editingRules) { InterceptRulesSheet(session: session) }
    }

    private var queue: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            List(model.items, selection: $model.selectedID) { item in
                HStack {
                    Text(Self.arrow(item)).foregroundStyle(.secondary)
                    Text(Self.label(item)).bold()
                    Text(Self.url(item)).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text(Self.waiting(item)).monospacedDigit().foregroundStyle(.secondary)
                }
                .tag(item.id)
            }
        }
    }

    static func title(_ item: InterceptItem) -> String {
        switch item.kind {
        case .request: "Request"
        case .response: "Response"
        case .webSocket(.toServer): "WebSocket message to server"
        case .webSocket(.toClient): "WebSocket message to client"
        }
    }

    static func label(_ item: InterceptItem) -> String {
        item.isWebSocket ? "WS" : item.request.bytes[item.request.parsed.method].string()
    }

    static func arrow(_ item: InterceptItem) -> String {
        switch item.kind {
        case .request, .webSocket(.toServer): "→"
        case .response, .webSocket(.toClient): "←"
        }
    }

    static func url(_ item: InterceptItem) -> String {
        let target = item.target
        let path = item.request.bytes[item.request.parsed.target].string()
        if path.hasPrefix("http") { return path }
        return "\(target.scheme.rawValue)://\(target.host):\(target.port)\(path)"
    }

    static func waiting(_ item: InterceptItem) -> String {
        let seconds = Int((ContinuousClock.now - item.queuedAt).components.seconds)
        return seconds < 60 ? "\(seconds)s" : "\(seconds / 60)m \(seconds % 60)s"
    }
}
/// The intercept rule editor (PRX-013 requests, PRX-014 responses).
struct InterceptRulesSheet: View {
    let session: ProjectSession
    @State private var settings: InterceptSettings
    @State private var status: String?
    @Environment(\.dismiss) private var dismiss

    init(session: ProjectSession) {
        self.session = session
        _settings = State(initialValue: session.settings.get(InterceptSettings.self))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Intercept rules").font(.headline)
            Text("Conditions are evaluated top to bottom; each joins the result so far with AND or OR.")
                .foregroundStyle(.secondary)
            ConditionList(title: "Requests", conditions: $settings.requestRules)
            ConditionList(title: "Responses", conditions: $settings.responseRules)
            // PRX-015 / HIS-027: a GulpQL expression replaces the builder's conditions when set.
            Text("Or write the rule in GulpQL (replaces the conditions above when not empty)")
                .font(.subheadline)
            TextField(#"Requests, e.g. req.method == POST and in_scope"#, text: $settings.requestQuery)
                .font(.system(.body, design: .monospaced))
                .textFieldStyle(.roundedBorder)
            TextField(
                #"Responses, e.g. resp.status >= 500 or resp.body ~ "error""#, text: $settings.responseQuery
            )
            .font(.system(.body, design: .monospaced))
            .textFieldStyle(.roundedBorder)
            ConditionList(
                title: "WebSocket connections (conditions on the upgrade request)",
                conditions: $settings.webSocketRules)
            HStack {
                if let status { Text(status).foregroundStyle(.secondary) }
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Apply") {
                    let session = self.session
                    let value = settings
                    Task {
                        do {
                            try await session.setInterceptSettings(value)
                            dismiss()
                        } catch {
                            status = "Not saved: \(error)"
                        }
                    }
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(minWidth: 720, minHeight: 540)
    }
}

/// An editable list of intercept conditions.
struct ConditionList: View {
    let title: String
    @Binding var conditions: [InterceptCondition]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title).bold()
                Spacer()
                Button("Add") { conditions.append(InterceptCondition(field: .url, pattern: "")) }
                Button("Remove last") { _ = conditions.popLast() }.disabled(conditions.isEmpty)
            }
            List {
                ForEach($conditions) { $condition in
                    HStack {
                        Toggle("", isOn: $condition.enabled).labelsHidden()
                        Picker("", selection: $condition.join) {
                            Text("AND").tag(InterceptJoin.and)
                            Text("OR").tag(InterceptJoin.or)
                        }
                        .labelsHidden()
                        .frame(width: 70)
                        Picker("", selection: $condition.field) {
                            ForEach(InterceptField.allCases, id: \.self) { Text($0.rawValue) }
                        }
                        .labelsHidden()
                        .frame(width: 170)
                        Picker("", selection: $condition.negate) {
                            Text("matches").tag(false)
                            Text("doesn't match").tag(true)
                        }
                        .labelsHidden()
                        .frame(width: 130)
                        TextField("Regex (empty = anything)", text: $condition.pattern)
                            .font(.system(.body, design: .monospaced))
                    }
                }
            }
            .frame(minHeight: 110)
        }
    }
}
#endif
