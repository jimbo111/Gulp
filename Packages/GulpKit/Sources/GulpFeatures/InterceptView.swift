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

    @ObservationIgnored private let session: ProjectSession
    @ObservationIgnored private var listener: Task<Void, Never>?
    @ObservationIgnored private var original: [UInt8] = []

    init(session: ProjectSession) {
        self.session = session
        let stored = session.settings.get(InterceptSettings.self)
        interceptRequests = stored.interceptRequests
        interceptResponses = stored.interceptResponses
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

    /// Turn request or response interception on or off (stored in the project, PRX-010/014).
    func setIntercepting(requests: Bool? = nil, responses: Bool? = nil) {
        var stored = session.settings.get(InterceptSettings.self)
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

    /// The Intercept screen for `session`.
    public init(session: ProjectSession) {
        _model = State(initialValue: InterceptModel(session: session))
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
                    MessageEditor(
                        title: item.kind == .request ? "Request" : "Response", bytes: $model.editing,
                        editable: true
                    )
                    .frame(minHeight: 200)
                } else {
                    let on = model.interceptRequests || model.interceptResponses
                    ContentUnavailableView(
                        on ? "Nothing held" : "Intercept is off",
                        systemImage: "hand.raised",
                        description: Text("Matching requests wait here until you forward or drop them."))
                }
            }
        }
        .navigationTitle("Intercept")
    }

    private var queue: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            List(model.items, selection: $model.selectedID) { item in
                HStack {
                    Text(item.kind == .request ? "→" : "←").foregroundStyle(.secondary)
                    Text(item.request.bytes[item.request.parsed.method].string()).bold()
                    Text(Self.url(item)).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text(Self.waiting(item)).monospacedDigit().foregroundStyle(.secondary)
                }
                .tag(item.id)
            }
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
#endif
