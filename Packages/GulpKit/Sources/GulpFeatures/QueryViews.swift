// GulpFeatures — GulpQL in the UI (F05): the filter field (parse errors shown as you type,
// completions, saved and recent filters — HIS-025/026), the Logger (HIS-040/041) and global search
// (⌘⇧F, HIS-050…052). The language, the store queries and the services are in GulpQuery, GulpStore
// and GulpWorkspace, tested on Linux; this file only shows them.

#if canImport(AppKit)
import AppKit
import GulpCore
import GulpQuery
import GulpStore
import GulpUI
import GulpWorkspace
import Observation
import SwiftUI

/// Saved and recent filters for a GulpQL field (HIS-026).
public struct GulpQLLibrary: Sendable {
    let load: @Sendable () async -> FilterSettings
    let save: @Sendable (_ name: String, _ query: String) async throws -> Void
    let remember: @Sendable (_ query: String) async -> Void

    /// The library of `session`'s user.
    public init(session: ProjectSession) {
        load = { await session.filterSettings() }
        save = { name, query in try await session.saveFilter(name: name, query: query) }
        remember = { query in try? await session.rememberFilter(query) }
    }
}

/// A GulpQL filter field: ⏎ applies; parse errors are flagged as you type; the menu offers
/// completions for the word being typed, recent and saved filters, and "Save Filter…".
public struct GulpQLFilterField: View {
    @Binding var expression: GulpQLExpression?
    var library: GulpQLLibrary?
    @State private var text = ""
    @State private var error: GulpQLError?
    @State private var settings = FilterSettings.defaultValue
    @State private var naming = false
    @State private var name = ""

    /// A field bound to an expression (nil: no filter).
    public init(expression: Binding<GulpQLExpression?>, library: GulpQLLibrary? = nil) {
        _expression = expression
        self.library = library
    }

    /// The screen.
    public var body: some View {
        HStack(spacing: 4) {
            TextField(#"GulpQL, e.g. resp.status >= 500 and req.host ~ "api""#, text: $text)
                .font(.system(.body, design: .monospaced))
                .textFieldStyle(.roundedBorder)
                .overlay(RoundedRectangle(cornerRadius: 5).stroke(error == nil ? Color.clear : Color.red))
                .onSubmit(apply)
                .onChange(of: text) { validate() }
                .help(
                    error.map { "\($0.message) (character \($0.range.lowerBound + 1))" }
                        ?? "GulpQL filter — ⏎ applies")
            if error != nil {
                Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.red)
                    .help(error?.message ?? "")
            }
            Menu {
                let completions = GulpQL.completions(text, cursor: text.count).prefix(12)
                if !completions.isEmpty {
                    Section("Complete") {
                        ForEach(Array(completions), id: \.self) { word in
                            Button(word) { complete(word) }
                        }
                    }
                }
                if !settings.recents.isEmpty {
                    Section("Recent") {
                        ForEach(settings.recents.prefix(10), id: \.self) { query in
                            Button(query) { use(query) }
                        }
                    }
                }
                if !settings.saved.isEmpty {
                    Section("Saved") {
                        ForEach(settings.saved) { filter in
                            Button(filter.name) { use(filter.query) }
                        }
                    }
                }
                Button("Save Filter…") { naming = true }
                    .disabled(library == nil || error != nil || text.isEmpty)
                Button("Clear") { use("") }
            } label: {
                Image(systemName: "line.3.horizontal.decrease.circle")
            }
            .menuStyle(.borderlessButton)
            .frame(width: 28)
        }
        .task { await reload() }
        .onAppear { text = expression.map(\.description) ?? "" }
        .alert("Save Filter", isPresented: $naming) {
            TextField("Name", text: $name)
            Button("Save") {
                let (name, query) = (name, text)
                Task {
                    try? await library?.save(name, query)
                    await reload()
                }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private func validate() {
        do {
            _ = try GulpQL.parse(text)
            error = nil
        } catch let parseError {
            error = parseError
        }
    }

    private func apply() {
        validate()
        guard error == nil, let parsed = try? GulpQL.parse(text) else { return }
        expression = parsed == .constant(true) ? nil : parsed
        let query = text
        Task {
            await library?.remember(query)
            await reload()
        }
    }

    private func use(_ query: String) {
        text = query
        apply()
    }

    /// Replace the word being typed with `word`.
    private func complete(_ word: String) {
        var characters = Array(text)
        while let last = characters.last, last.isLetter || last.isNumber || last == "_" || last == "." {
            characters.removeLast()
        }
        text = String(characters) + word
    }

    private func reload() async {
        if let library { settings = await library.load() }
    }
}

/// The Logger (HIS-040/041): every tool's traffic in one table, newest first, with its own source
/// set, GulpQL filter and a capture switch.
public struct LoggerView: View {
    let session: ProjectSession
    let generation: Int
    @State private var model: HistoryModel?
    @State private var settings = LoggerSettings()
    @State private var query: GulpQLExpression?
    static let tools = ["proxy", "repeater", "fuzzer", "scanner", "crawler", "sequencer", "automation", "ai"]

    /// The Logger of `session`; bump `generation` after the project file changes (Save As), and the
    /// Logger reopens on the new store.
    public init(session: ProjectSession, generation: Int) {
        self.session = session
        self.generation = generation
    }

    /// The screen.
    public var body: some View {
        content.task(id: generation) { await start() }
    }

    @ViewBuilder private var content: some View {
        if let model {
            VSplit {
                VStack(spacing: 0) {
                    HStack(spacing: 8) {
                        Toggle("Capture", isOn: captureBinding(model))
                            .help(
                                "When off, the Logger keeps its rows and stops updating (traffic is still recorded)"
                            )
                        ForEach(Self.tools, id: \.self) { tool in
                            Toggle(tool.capitalized, isOn: sourceBinding(tool, model))
                        }
                        GulpQLFilterField(expression: $query, library: GulpQLLibrary(session: session))
                            .frame(minWidth: 220, maxWidth: 420)
                            .onChange(of: query) { apply(model) }
                        Spacer()
                        Text("\(model.rowCount) items").foregroundStyle(.secondary).monospacedDigit()
                    }
                    .toggleStyle(.button)
                    .controlSize(.small)
                    .padding(6)
                    Divider()
                    HistoryTableView(model: model)
                }
                .frame(minHeight: 180)
                HSplit {
                    MessageViewer(title: "Request", bytes: model.selected?.request.bytes)
                    ResponsePane(exchange: model.selected)
                }
                .frame(minHeight: 160)
            }
            .navigationTitle("Logger")
        } else {
            ProgressView()
        }
    }

    private func start() async {
        let created = HistoryModel(store: await session.store, events: session.events)
        created.sort = HistorySort(column: .id, ascending: false)
        let stored = await session.loggerSettings()
        settings = stored
        query = try? GulpQL.parse(stored.query)
        if query == .constant(true) { query = nil }
        created.live = stored.capture
        created.filter = (try? stored.filter()) ?? HistoryFilter()
        let session = self.session
        created.sendToRepeater = { ids in Task { await session.sendToRepeater(ids) } }
        created.addToNotebook = { ids in Task { for id in ids { _ = try? await session.addToNotebook(id) } } }
        model = created
    }

    private func apply(_ model: HistoryModel) {
        settings.query = query?.description ?? ""
        model.filter = (try? settings.filter()) ?? HistoryFilter()
        let value = settings
        Task { try? await session.setLoggerSettings(value) }
    }

    private func captureBinding(_ model: HistoryModel) -> Binding<Bool> {
        Binding(
            get: { settings.capture },
            set: { on in
                settings.capture = on
                model.live = on
                let value = settings
                Task { try? await session.setLoggerSettings(value) }
            })
    }

    /// No tool selected means all tools; selecting tools narrows the Logger to them.
    private func sourceBinding(_ tool: String, _ model: HistoryModel) -> Binding<Bool> {
        Binding(
            get: { settings.sources.contains(tool) },
            set: { on in
                settings.sources.removeAll { $0 == tool }
                if on { settings.sources.append(tool) }
                apply(model)
            })
    }
}

/// Global search (⌘⇧F, HIS-050…052): results grouped by tool, with match previews.
public struct SearchView: View {
    let session: ProjectSession
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var regex = false
    @State private var part = SearchQuery.Part.both
    @State private var section = SearchQuery.Section.all
    @State private var inScopeOnly = false
    @State private var results: SearchResults?
    @State private var searching = false
    @State private var failure: String?
    @State private var selected: ExchangeID?
    @State private var shown: Exchange?
    @State private var running: Task<Void, Never>?

    /// Search in `session`'s project.
    public init(session: ProjectSession) {
        self.session = session
    }

    /// The screen.
    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                TextField("Search requests and responses", text: $text)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(search)
                Toggle("Regex", isOn: $regex).toggleStyle(.checkbox)
                Picker("", selection: $part) {
                    Text("Both").tag(SearchQuery.Part.both)
                    Text("Requests").tag(SearchQuery.Part.request)
                    Text("Responses").tag(SearchQuery.Part.response)
                }
                .labelsHidden()
                .frame(width: 110)
                Picker("", selection: $section) {
                    Text("Headers + body").tag(SearchQuery.Section.all)
                    Text("Headers").tag(SearchQuery.Section.headers)
                    Text("Body").tag(SearchQuery.Section.body)
                }
                .labelsHidden()
                .frame(width: 130)
                Toggle("In scope", isOn: $inScopeOnly).toggleStyle(.checkbox)
                if searching {
                    ProgressView().controlSize(.small)
                    Button("Cancel") { running?.cancel() }
                } else {
                    Button("Search", action: search).keyboardShortcut(.defaultAction)
                }
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            if let failure { Text(failure).foregroundStyle(.red).font(.caption) }
            if let results {
                Text(summary(results)).font(.caption).foregroundStyle(.secondary)
                if let hint = results.hint { Text(hint).font(.caption).foregroundStyle(.orange) }
            }
            HSplit {
                List(selection: $selected) {
                    ForEach(groups) { group in
                        Section("\(group.id) (\(group.hits.count))") {
                            ForEach(group.hits) { hit in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("#\(hit.id) \(hit.method ?? "") \(hit.host)\(hit.path)").lineLimit(1)
                                    Text(hit.preview).font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(.secondary).lineLimit(1)
                                }
                                .tag(hit.id)
                            }
                        }
                    }
                }
                .frame(minWidth: 320)
                VSplit {
                    MessageViewer(title: "Request", bytes: shown?.request.bytes)
                    ResponsePane(exchange: shown)
                }
                .frame(minWidth: 320)
            }
        }
        .padding()
        .frame(minWidth: 900, minHeight: 560)
        .onChange(of: selected) {
            guard let selected else { return }
            let session = self.session
            Task { shown = try? await session.store.exchange(id: selected) }
        }
    }

    /// Hits of one tool.
    struct HitGroup: Identifiable {
        /// The tool (`proxy`, `repeater`…).
        var id: String
        var hits: [SearchHit]
    }

    private var groups: [HitGroup] {
        let hits = results?.hits ?? []
        var order: [String] = []
        var bySource: [String: [SearchHit]] = [:]
        for hit in hits {
            let name = hit.source.rawValue
            if bySource[name] == nil { order.append(name) }
            bySource[name, default: []].append(hit)
        }
        return order.map { HitGroup(id: $0, hits: bySource[$0] ?? []) }
    }

    private func summary(_ results: SearchResults) -> String {
        "\(results.hits.count) hit(s)" + (results.truncated ? "+" : "")
            + (results.usedIndex ? " · index" : " · scanned \(results.examined) rows")
    }

    private func search() {
        var query = SearchQuery(text)
        query.regex = regex
        query.part = part
        query.section = section
        query.filter.inScopeOnly = inScopeOnly
        failure = nil
        searching = true
        let session = self.session
        running = Task {
            do {
                results = try await session.store.search(query)
            } catch is CancellationError {
                failure = "Cancelled"
            } catch {
                failure = "\(error)"
            }
            searching = false
        }
    }
}
#endif
