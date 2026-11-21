// GulpFeatures — the Notebook (F14 NB-001…NB-004, NB-006): a filterable list (search box with
// status:/tag:/host:/is:, grouping by status or host, drag to reorder) and, for the selected item,
// its title, status, tags, highlight and markdown note (rendered as a preview, never as HTML) above
// the saved request/response snapshot, with "send back" to Repeater, Comparer and Fuzzer.

#if canImport(AppKit)
import AppKit
import GulpCore
import GulpStore
import GulpUI
import GulpWorkspace
import Observation
import SwiftUI

/// State behind the Notebook.
@MainActor
@Observable
final class NotebookModel {
    private(set) var items: [NotebookItem] = []
    private(set) var groups: [(name: String, items: [NotebookItem])] = []
    var filterText = "" {
        didSet { reload() }
    }
    var grouping: NotebookGrouping? {
        didSet { reload() }
    }
    var selection: Set<Int64> = []
    private(set) var message: String?

    @ObservationIgnored let session: ProjectSession
    @ObservationIgnored private var pendingSave: Task<Void, Never>?
    /// Edits not yet written, merged per item (a later edit of another field mustn't drop them).
    @ObservationIgnored private var pendingEdits: [Int64: NotebookEdit] = [:]
    /// Counts reloads, so a slower, older query cannot overwrite a newer one.
    @ObservationIgnored private var reloads = 0

    init(session: ProjectSession) {
        self.session = session
        reload()
    }

    var selected: NotebookItem? {
        guard selection.count == 1, let id = selection.first else { return nil }
        return items.first { $0.id == id }
    }

    func reload() {
        let session = self.session
        let filter = NotebookFilter(filterText)
        let grouping = self.grouping
        reloads += 1
        let reload = reloads
        Task {
            let loaded = (try? await session.notebook(filter)) ?? []
            var grouped: [(name: String, items: [NotebookItem])] = []
            if let grouping { grouped = (try? await session.notebookGroups(grouping, filter: filter)) ?? [] }
            // A newer reload (the filter changed meanwhile) wins, whichever query finishes last.
            guard reload == reloads else { return }
            items = loaded
            groups = grouped
        }
    }

    func newNote() {
        let session = self.session
        write("Adding a note") {
            let item = try await session.addNote(title: "New note")
            self.reload()
            self.selection = [item.id]
        }
    }

    func delete() {
        let ids = Array(selection)
        let session = self.session
        write("Deleting") {
            try await session.store.deleteNotebookItems(ids)
            self.selection = []
            self.reload()
        }
    }

    func move(from source: IndexSet, to destination: Int) {
        var order = items.map(\.id)
        order.move(fromOffsets: source, toOffset: destination)
        items.move(fromOffsets: source, toOffset: destination)
        let session = self.session
        write("Reordering") { try await session.store.reorderNotebook(order) }
    }

    /// Save an edit after a short pause (typing in the note doesn't write on every key).
    func edit(_ id: Int64, _ change: NotebookEdit, immediately: Bool = false) {
        if let index = items.firstIndex(where: { $0.id == id }) {
            if let title = change.title { items[index].title = title }
            if let status = change.status { items[index].status = status }
            if let note = change.note { items[index].note = note }
            if let tags = change.tags { items[index].tags = tags }
            if let highlight = change.highlight { items[index].highlight = highlight }
        }
        var merged = pendingEdits[id] ?? NotebookEdit()
        if let title = change.title { merged.title = title }
        if let status = change.status { merged.status = status }
        if let note = change.note { merged.note = note }
        if let tags = change.tags { merged.tags = tags }
        if let highlight = change.highlight { merged.highlight = highlight }
        pendingEdits[id] = merged
        pendingSave?.cancel()
        pendingSave = Task {
            if !immediately { try? await Task.sleep(for: .milliseconds(400)) }
            guard !Task.isCancelled else { return }
            await flushEdits()
        }
    }

    /// Write every pending edit now. An edit that fails stays pending (unless a newer one replaced
    /// it) and the failure is shown.
    func flushEdits() async {
        let edits = pendingEdits
        pendingEdits = [:]
        for (id, edit) in edits {
            do {
                try await session.store.updateNotebookItem(id, edit)
            } catch {
                if pendingEdits[id] == nil { pendingEdits[id] = edit }
                message = "Saving the note failed: \(ProjectSession.describe(error))"
            }
        }
    }

    func send(_ id: Int64, to destination: NotebookDestination) {
        let session = self.session
        write("Sending") {
            let sent = try await session.sendNotebookItem(id, to: destination)
            self.message =
                sent
                ? "Sent to \(destination.rawValue.capitalized)" : "Nothing to send (a note has no request)"
        }
    }

    /// Run a write; a failure is shown under the editor (never dropped).
    private func write(_ action: String, _ body: @escaping () async throws -> Void) {
        Task {
            do {
                try await body()
            } catch {
                message = "\(action) failed: \(ProjectSession.describe(error))"
            }
        }
    }
}

/// The Notebook tool.
public struct NotebookView: View {
    let session: ProjectSession
    @State private var model: NotebookModel?

    /// The Notebook of `session`.
    public init(session: ProjectSession) {
        self.session = session
    }

    /// The screen.
    public var body: some View {
        if let model {
            NotebookPanel(model: model)
        } else {
            ProgressView().task { model = NotebookModel(session: session) }
        }
    }
}

struct NotebookPanel: View {
    @Bindable var model: NotebookModel

    var body: some View {
        HSplit {
            VStack(spacing: 0) {
                HStack {
                    TextField("Filter (status:confirmed tag:xss host:api …)", text: $model.filterText)
                        .textFieldStyle(.roundedBorder)
                    Picker("", selection: $model.grouping) {
                        Text("No groups").tag(NotebookGrouping?.none)
                        Text("By status").tag(NotebookGrouping?.some(.status))
                        Text("By host").tag(NotebookGrouping?.some(.host))
                    }
                    .labelsHidden()
                    .frame(width: 110)
                }
                .padding(6)
                List(selection: $model.selection) {
                    if model.grouping == nil {
                        ForEach(model.items) { item in row(item).tag(item.id) }
                            .onMove { model.move(from: $0, to: $1) }
                    } else {
                        ForEach(model.groups.indices, id: \.self) { index in
                            Section(model.groups[index].name) {
                                ForEach(model.groups[index].items) { item in row(item).tag(item.id) }
                            }
                        }
                    }
                }
                HStack {
                    Button("New Note") { model.newNote() }
                    Button("Delete") { model.delete() }.disabled(model.selection.isEmpty)
                    Spacer()
                    Text("^[\(model.items.count) item](inflect: true)").foregroundStyle(.secondary).font(.caption)
                }
                .padding(6)
                if model.selected == nil, let message = model.message {
                    Text(message).font(.caption).foregroundStyle(.secondary).padding(
                        [.horizontal, .bottom], 6)
                }
            }
            .frame(minWidth: 280, idealWidth: 340)
            if let item = model.selected {
                NotebookItemEditor(model: model, item: item).id(item.id)
            } else {
                ContentUnavailableView(
                    "Notebook", systemImage: "note.text",
                    description: Text("Add exchanges from History (⌘⇧N) or write a note."))
            }
        }
        .navigationTitle("Notebook")
    }

    private func row(_ item: NotebookItem) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                if let highlight = item.highlight {
                    Circle().fill(color(highlight)).frame(width: 8, height: 8)
                }
                Text(item.title).lineLimit(1)
                Spacer()
                Text(item.status.title).font(.caption).foregroundStyle(.secondary)
            }
            Text(item.location ?? "Note").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            if !item.tags.isEmpty {
                Text(item.tags.map { "#" + $0 }.joined(separator: " ")).font(.caption2).foregroundStyle(.tint)
            }
        }
    }
}

func color(_ highlight: Highlight) -> Color {
    switch highlight.rawValue {
    case "red": .red
    case "orange": .orange
    case "yellow": .yellow
    case "green": .green
    case "cyan": .cyan
    case "blue": .blue
    case "pink": .pink
    case "magenta", "purple": .purple
    default: .gray
    }
}

struct NotebookItemEditor: View {
    let model: NotebookModel
    let item: NotebookItem
    @State private var title: String
    @State private var note: String
    @State private var tags: String
    @State private var previewNote = false

    init(model: NotebookModel, item: NotebookItem) {
        self.model = model
        self.item = item
        _title = State(initialValue: item.title)
        _note = State(initialValue: item.note)
        _tags = State(initialValue: item.tags.joined(separator: ", "))
    }

    var body: some View {
        VSplit {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    TextField("Title", text: $title)
                        .font(.title3)
                        .textFieldStyle(.plain)
                        .onChange(of: title) { model.edit(item.id, NotebookEdit(title: title)) }
                    Picker("Status", selection: statusBinding) {
                        ForEach(NotebookStatus.allCases, id: \.self) { Text($0.title).tag($0) }
                    }
                    .frame(width: 200)
                    Picker("", selection: highlightBinding) {
                        Text("No color").tag(Highlight?.none)
                        ForEach(Highlight.allCases, id: \.self) {
                            Text($0.rawValue.capitalized).tag(Highlight?.some($0))
                        }
                    }
                    .labelsHidden()
                    .frame(width: 110)
                }
                TextField("Tags (comma-separated)", text: $tags)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: tags) {
                        let list = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                            .filter { !$0.isEmpty }
                        model.edit(item.id, NotebookEdit(tags: list))
                    }
                HStack {
                    Toggle("Preview", isOn: $previewNote).toggleStyle(.switch).controlSize(.small)
                    Spacer()
                    if item.kind == .exchange {
                        Button("Send to Repeater") { model.send(item.id, to: .repeater) }
                        Button("Comparer") { model.send(item.id, to: .comparer) }
                        Button("Fuzzer") { model.send(item.id, to: .fuzzer) }
                    }
                }
                if previewNote {
                    ScrollView {
                        // AttributedString's markdown parser produces styled text only: links are
                        // inert attributes and raw HTML is shown as text, never executed (F14 §5).
                        Text(markdown).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                    }
                } else {
                    TextEditor(text: $note)
                        .font(.system(.body, design: .monospaced))
                        .onChange(of: note) { model.edit(item.id, NotebookEdit(note: note)) }
                }
                if let message = model.message { Text(message).font(.caption).foregroundStyle(.secondary) }
                if item.truncated {
                    Text("The saved messages were larger than the snapshot limit and are cut.")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            .padding(8)
            .frame(minHeight: 220)
            if item.kind == .exchange {
                HSplit {
                    MessageViewer(title: "Saved request", bytes: item.request.map { Bytes($0) })
                    ResponsePane(exchange: snapshot)
                }
                .frame(minHeight: 180)
            }
        }
    }

    private var markdown: AttributedString {
        (try? AttributedString(
            markdown: note, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)))
            ?? AttributedString(note)
    }

    /// The snapshot as an exchange, for the response pane.
    private var snapshot: Exchange? {
        guard let target = item.target, let request = item.request else { return nil }
        return Exchange(
            id: item.exchangeID ?? 0, source: .proxy, target: target, request: RawRequest(Bytes(request)),
            response: item.response.map { RawResponse(wire: Bytes($0)) }, state: .complete)
    }

    private var statusBinding: Binding<NotebookStatus> {
        Binding(
            get: { model.items.first { $0.id == item.id }?.status ?? item.status },
            set: { model.edit(item.id, NotebookEdit(status: $0), immediately: true) })
    }

    private var highlightBinding: Binding<Highlight?> {
        Binding(
            get: { model.items.first { $0.id == item.id }?.highlight ?? nil },
            set: { model.edit(item.id, NotebookEdit(highlight: .some($0)), immediately: true) })
    }
}
#endif
