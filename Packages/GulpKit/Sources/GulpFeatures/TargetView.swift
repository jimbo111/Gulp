// GulpFeatures — the Target tool (F04): a **Site map** tab (the host → path tree with visited and
// dimmed inferred nodes, filters, the endpoints of the selected node and the selected exchange,
// node actions and notes, Analyze target) and a **Scope** tab (the simple list and Add field, the
// advanced rules table, a live "test a URL" field, JSON export/import and "Use scope for the proxy").
// The logic lives in GulpCore (SiteMap, ScopeService, TargetAnalysis) and GulpWorkspace
// (SiteMapService, ScopeActions), tested on Linux; this file only shows it.

#if canImport(AppKit)
import AppKit
import GulpCore
import GulpStore
import GulpWorkspace
import Observation
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Site map model

/// One row of the site map tree (only the nodes that pass the filter).
public struct SiteMapRow: Identifiable, Hashable {
    /// The node id (its URL key).
    public var id: String
    /// The node.
    public var node: SiteMapNode
    /// Visible children; nil for a leaf (so the list shows no disclosure triangle).
    public var children: [SiteMapRow]?
}

/// State behind Target → Site map.
@MainActor
@Observable
public final class SiteMapModel {
    /// The tree, filtered.
    public private(set) var rows: [SiteMapRow] = []
    /// Nodes shown / total.
    public private(set) var counts = (shown: 0, total: 0)
    /// The filter bar (TGT-005).
    public var filter = SiteMapFilter() {
        didSet { if filter != oldValue { rebuildRows() } }
    }
    /// The MIME filter field (comma-separated substrings).
    public var mimeText = "" {
        didSet {
            let parts = mimeText.split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespaces).lowercased()
            }
            filter.mimes = Set(parts.filter { !$0.isEmpty })
        }
    }
    /// Fold numeric/UUID segments into `{id}` (TGT-006).
    public var grouped = false {
        didSet {
            guard grouped != oldValue else { return }
            let siteMap = session.siteMap
            let on = grouped
            Task { await siteMap.setGroupsParameterized(on) }
        }
    }
    /// The selected node.
    public var selectedNodeID: String? {
        didSet { if selectedNodeID != oldValue { loadEndpoints() } }
    }
    /// The selected node's endpoints (TGT-002).
    public private(set) var endpoints: [ExchangeSummary] = []
    /// The endpoint shown in the viewer.
    public var selectedExchangeID: ExchangeID? {
        didSet { if selectedExchangeID != oldValue { loadExchange() } }
    }
    /// The exchange shown.
    public private(set) var shown: Exchange?
    /// Annotations by node id (TGT-007).
    public private(set) var notes: [String: SiteMapNote] = [:]
    /// The Analyze target result shown in a sheet (TGT-008).
    public var analysis: (host: String, result: TargetAnalysis)?
    /// The last action's failure, shown under the tree.
    public private(set) var message: String?

    @ObservationIgnored let session: ProjectSession
    @ObservationIgnored private var map = SiteMap()

    /// The site map of `session`.
    public init(session: ProjectSession) {
        self.session = session
    }

    /// Follow the site map until cancelled (the view's `.task`, so only while it is shown): refresh
    /// now, then as traffic changes it.
    func follow() async {
        let changes = await session.siteMap.changes()
        await refresh()
        for await _ in changes {
            await refresh()
            // Coalesce traffic-driven updates: at most one redraw per 100 ms (CLAUDE.md §4).
            try? await Task.sleep(for: .milliseconds(100))
        }
    }

    /// The node for a row id.
    public func node(_ id: String) -> SiteMapNode? { map.node(id) }

    private func refresh() async {
        map = await session.siteMap.snapshot
        notes = (try? await session.siteMapNotes()) ?? notes
        rebuildRows()
        if let selectedNodeID, map.node(selectedNodeID) == nil {
            self.selectedNodeID = nil
        } else {
            loadEndpoints()
        }
    }

    private func rebuildRows() {
        let visible = map.visible(filter)
        func row(_ id: String) -> SiteMapRow? {
            guard visible.contains(id), let node = map.node(id) else { return nil }
            let children = node.children.compactMap(row)
            return SiteMapRow(id: id, node: node, children: children.isEmpty ? nil : children)
        }
        rows = map.roots.compactMap(row)
        counts = (visible.count, map.count)
    }

    private func loadEndpoints() {
        guard let id = selectedNodeID else {
            endpoints = []
            return
        }
        let session = self.session
        Task {
            let rows = (try? await session.siteMapEndpoints(id)) ?? []
            guard selectedNodeID == id else { return }
            endpoints = rows
            if let selectedExchangeID, !rows.contains(where: { $0.id == selectedExchangeID }) {
                self.selectedExchangeID = rows.last?.id
            } else if selectedExchangeID == nil {
                selectedExchangeID = rows.last?.id
            }
        }
    }

    private func loadExchange() {
        guard let id = selectedExchangeID else {
            shown = nil
            return
        }
        let session = self.session
        Task {
            let exchange = try? await session.store.exchange(id: id)
            if selectedExchangeID == id { shown = exchange }
        }
    }

    // MARK: actions (TGT-004, TGT-007, TGT-008)

    /// The URL a node stands for (default ports dropped).
    public nonisolated static func url(of nodeID: String) -> String {
        guard let target = HTTPTarget(url: nodeID) else { return nodeID }
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        let hostKey = SiteMap.hostKey(target)
        let path = nodeID.dropFirst(hostKey.count)
        return
            "\(target.scheme.rawValue)://\(target.host)\(standard ? "" : ":\(target.port)")\(path.isEmpty ? "/" : path)"
    }

    /// Add the node's host and path to scope (TGT-021).
    public func addToScope(_ nodeID: String) {
        let url = Self.url(of: nodeID)
        run { try await $0.addToScope(url: url) }
    }

    /// Exclude the node's host and path from scope.
    public func excludeFromScope(_ nodeID: String) {
        let url = Self.url(of: nodeID)
        run { try await $0.excludeFromScope(url: url) }
    }

    /// Open Repeater tabs for exchanges.
    public func sendToRepeater(_ ids: [ExchangeID]) {
        let session = self.session
        Task { await session.sendToRepeater(ids) }
    }

    /// Open Repeater tabs for the newest exchange of each endpoint under a node.
    public func sendNodeToRepeater(_ nodeID: String) {
        let session = self.session
        Task {
            let rows = (try? await session.siteMapEndpoints(nodeID)) ?? []
            var newest: [String: ExchangeID] = [:]
            for row in rows { newest["\(row.method ?? "") \(row.path ?? "")"] = row.id }
            await session.sendToRepeater(Array(newest.values).sorted().suffix(20))
        }
    }

    /// Copy the URLs requested at or below a node, one per line.
    public func copyURLs(_ nodeID: String) {
        let session = self.session
        Task {
            let rows = (try? await session.siteMapEndpoints(nodeID)) ?? []
            var seen: Set<String> = []
            let urls = rows.map(\.url).filter { seen.insert($0).inserted }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(urls.joined(separator: "\n"), forType: .string)
        }
    }

    /// "Delete branch": delete every exchange at or below a node.
    public func deleteBranch(_ nodeID: String) {
        run { _ = try await $0.deleteSiteMapBranch(nodeID) }
    }

    /// Run Analyze target on the node's host.
    public func analyze(_ nodeID: String) {
        let session = self.session
        Task {
            do {
                if let result = try await session.analyzeTarget(nodeID) {
                    let host =
                        map.hosts.first { nodeID == $0.id || nodeID.hasPrefix($0.id + "/") }?.name ?? nodeID
                    analysis = (host, result)
                }
            } catch {
                message = ProjectSession.describe(error)
            }
        }
    }

    /// Set a node's highlight (nil clears it).
    public func setHighlight(_ highlight: Highlight?, for nodeID: String) {
        var note = notes[nodeID] ?? SiteMapNote(nodeKey: nodeID)
        note.highlight = highlight
        save(note)
    }

    /// Set a node's comment, or a host's notes.
    public func setText(_ text: String, for nodeID: String) {
        var note = notes[nodeID] ?? SiteMapNote(nodeKey: nodeID)
        let value = text.isEmpty ? nil : text
        if map.node(nodeID)?.kind == .host { note.notes = value } else { note.comment = value }
        save(note)
    }

    private func save(_ note: SiteMapNote) {
        notes[note.nodeKey] = note.isEmpty ? nil : note
        run { try await $0.setSiteMapNote(note) }
    }

    private func run(_ action: @escaping @Sendable (ProjectSession) async throws -> Void) {
        let session = self.session
        Task {
            do {
                try await action(session)
                message = nil
            } catch {
                message = ProjectSession.describe(error)
            }
        }
    }
}

// MARK: - Scope model

/// State behind Target → Scope.
@MainActor
@Observable
public final class ScopeModel {
    /// The rules as edited (applied with `apply()`).
    public var rules: [ScopeRule] = []
    /// The rules as stored.
    public private(set) var stored: [ScopeRule] = []
    /// The Add field.
    public var addText = ""
    /// The test-a-URL field.
    public var testText = "" {
        didSet { updateTest() }
    }
    /// The test result: "In scope (rule 2)" etc.
    public private(set) var testResult: String?
    /// The readable summary of the stored scope (TGT-025).
    public private(set) var summary = ""
    /// "Use scope for the proxy" (TGT-024).
    public private(set) var useScopeForProxy = false
    /// The last error.
    public private(set) var message: String?

    @ObservationIgnored private let session: ProjectSession

    /// The scope of `session`.
    public init(session: ProjectSession) {
        self.session = session
        Task { await reload() }
    }

    /// Unapplied edits.
    public var isDirty: Bool { rules != stored }

    /// The problems of a rule's regexes, if any.
    public func problem(_ rule: ScopeRule) -> String? {
        (rule.hostIsRegex ? ScopeRule.problem(with: rule.host) : nil) ?? ScopeRule.problem(with: rule.path)
    }

    func reload() async {
        let scope = await session.scope()
        stored = scope.rules
        rules = scope.rules
        summary = scope.summary
        useScopeForProxy = session.settings.get(ProxySettings.self).useScope
        updateTest()
    }

    /// Add the Add field's URL (or bare host) as an include rule (simple mode, TGT-021).
    public func addFromField(kind: ScopeRule.Kind = .include) {
        var text = addText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        if !text.contains("://") { text = "https://" + text }
        guard let rule = ScopeRule.include(url: text, kind: kind) else {
            message = "Enter a host or an http(s) URL."
            return
        }
        // A bare host covers both schemes.
        var added = rule
        if !addText.contains("://") { added.scheme = .any }
        rules.append(added)
        addText = ""
        apply()
    }

    /// A blank advanced rule.
    public func addBlankRule() {
        rules.append(ScopeRule(host: "example.com"))
    }

    /// Remove rules.
    public func remove(_ ids: Set<UUID>) {
        rules.removeAll { ids.contains($0.id) }
    }

    /// Move a rule up (-1) or down (+1): order matters, the last match wins.
    public func move(_ id: UUID, by delta: Int) {
        guard let index = rules.firstIndex(where: { $0.id == id }), rules.indices.contains(index + delta)
        else {
            return
        }
        rules.swapAt(index, index + delta)
    }

    /// Store the edited rules (recomputes every row's in-scope flag in the background).
    public func apply() {
        if let bad = rules.first(where: { problem($0) != nil }) {
            message = "\(bad.host): \(problem(bad) ?? "")"
            return
        }
        let edited = rules
        let session = self.session
        Task {
            do {
                try await session.setScope(edited)
                message = nil
            } catch {
                message = ProjectSession.describe(error)
            }
            await reload()
        }
    }

    /// Drop unapplied edits.
    public func revert() {
        rules = stored
    }

    /// Turn "Use scope for the proxy" on or off.
    public func setUseScopeForProxy(_ on: Bool) {
        useScopeForProxy = on
        let session = self.session
        Task { try? await session.setUseScopeForProxy(on) }
    }

    /// Export the stored scope to a file the user picks.
    public func export() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "scope.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let session = self.session
        Task {
            do {
                try await session.exportScope().write(to: url)
            } catch {
                message = ProjectSession.describe(error)
            }
        }
    }

    /// Replace the scope with a file the user picks.
    public func importFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url, let data = try? Data(contentsOf: url) else {
            return
        }
        let session = self.session
        Task {
            do {
                try await session.importScope(data)
                message = nil
            } catch {
                message = ProjectSession.describe(error)
            }
            await reload()
        }
    }

    private func updateTest() {
        let text = testText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else {
            testResult = nil
            return
        }
        guard let target = HTTPTarget(url: text) else {
            testResult = "Enter an http(s) URL."
            return
        }
        // Tested against the rules as edited, so a change can be tried before applying it.
        let scope = ScopeService(rules: rules)
        let path = ScopeService.requestPath(ofURL: text)
        guard let rule = scope.decidingRule(for: target, path: path), let index = rules.firstIndex(of: rule)
        else {
            testResult = "Out of scope: no rule matches."
            return
        }
        testResult =
            rule.kind == .include
            ? "In scope: rule \(index + 1) includes it." : "Out of scope: rule \(index + 1) excludes it."
    }
}

// MARK: - Views

/// Target: Site map and Scope.
public struct TargetView: View {
    enum Tab: String, CaseIterable {
        case siteMap = "Site map"
        case scope = "Scope"
    }

    let models: ToolModels
    @State private var tab = Tab.siteMap

    /// The Target tool of the project whose tool models are `models`.
    public init(models: ToolModels) {
        self.models = models
    }

    public var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $tab) {
                ForEach(Tab.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 260)
            .padding(6)
            Divider()
            switch tab {
            case .siteMap:
                SiteMapView(model: models.siteMap)
                    .task { await models.siteMap.follow() }
            case .scope:
                ScopeView(model: models.scope)
            }
        }
        .navigationTitle("Target")
    }
}

/// Target → Site map.
struct SiteMapView: View {
    @Bindable var model: SiteMapModel
    @State private var editingNote: String?
    @State private var noteText = ""

    var body: some View {
        VStack(spacing: 0) {
            filterBar
            Divider()
            HSplitView {
                tree.frame(minWidth: 240, idealWidth: 320)
                VSplitView {
                    endpointTable.frame(minHeight: 140)
                    HSplitView {
                        MessageViewer(title: "Request", bytes: model.shown?.request.bytes)
                        ResponsePane(exchange: model.shown)
                    }
                    .frame(minHeight: 160)
                }
                .frame(minWidth: 360)
            }
        }
        .sheet(isPresented: analysisShown) { analysisSheet }
        .alert(noteTitle, isPresented: noteShown) {
            TextField("Text", text: $noteText)
            Button("Save") { if let editingNote { model.setText(noteText, for: editingNote) } }
            Button("Cancel", role: .cancel) {}
        }
    }

    private var filterBar: some View {
        HStack(spacing: 10) {
            Toggle("In scope", isOn: $model.filter.inScopeOnly)
            Toggle("Hide inferred", isOn: $model.filter.visitedOnly)
            Toggle("Hide 404", isOn: $model.filter.hideNotFound)
            Toggle("Group {id}", isOn: $model.grouped)
                .help("Fold numeric and UUID path segments into {id} (TGT-006)")
            TextField("MIME (html, json…)", text: $model.mimeText)
                .frame(maxWidth: 140)
            TextField("Search host/path", text: $model.filter.search)
                .frame(maxWidth: 220)
            Spacer()
            Text("\(model.counts.shown) of \(model.counts.total) nodes").foregroundStyle(.secondary).font(
                .caption)
        }
        .toggleStyle(.checkbox)
        .textFieldStyle(.roundedBorder)
        .padding(6)
    }

    private var tree: some View {
        VStack(spacing: 0) {
            if model.rows.isEmpty {
                ContentUnavailableView(
                    "No site map yet", systemImage: "scope",
                    description: Text(
                        "Browse through the proxy; hosts and paths appear here as traffic arrives."))
            } else {
                List(model.rows, children: \.children, selection: $model.selectedNodeID) { row in
                    nodeLabel(row.node)
                        .contextMenu { menu(for: row.node) }
                }
            }
            if let message = model.message {
                Text(message).font(.caption).foregroundStyle(.red).padding(4)
            }
        }
    }

    private func nodeLabel(_ node: SiteMapNode) -> some View {
        let note = model.notes[node.id]
        return HStack(spacing: 6) {
            Image(systemName: node.kind == .host ? "globe" : (node.children.isEmpty ? "doc" : "folder"))
                .foregroundStyle(node.inScope ? Color.accentColor : .secondary)
            Text(node.name)
                .foregroundStyle(node.visited ? .primary : .secondary)  // TGT-003: inferred is dimmed
                .italic(!node.visited)
            if !node.exchanges.isEmpty {
                Text("\(node.exchanges.count)").font(.caption2).foregroundStyle(.secondary)
            }
            if let text = note?.comment ?? note?.notes {
                Image(systemName: "text.bubble").font(.caption).help(text)
            }
        }
        .padding(.horizontal, 2)
        .background(note?.highlight.map { Self.color($0).opacity(0.25) } ?? Color.clear)
        .help(
            node.visited ? SiteMapModel.url(of: node.id) : "Inferred: linked from a response, never requested"
        )
    }

    @ViewBuilder private func menu(for node: SiteMapNode) -> some View {
        Button("Add to Scope") { model.addToScope(node.id) }
        Button("Remove from Scope") { model.excludeFromScope(node.id) }
        Divider()
        Button("Send to Repeater") { model.sendNodeToRepeater(node.id) }
            .disabled(!node.visited)
        Button("Copy URLs") { model.copyURLs(node.id) }
        Divider()
        Button("Actively Scan This Branch") {}.disabled(true).help("Arrives with the Scanner (M11)")
        Button("Crawl from Here") {}.disabled(true).help("Arrives with the Crawler (M9)")
        Button("Analyze Target") { model.analyze(node.id) }
        Divider()
        Menu("Highlight") {
            ForEach(Highlight.allCases, id: \.self) { highlight in
                Button(highlight.rawValue.capitalized) { model.setHighlight(highlight, for: node.id) }
            }
            Divider()
            Button("None") { model.setHighlight(nil, for: node.id) }
        }
        Button(node.kind == .host ? "Host Notes…" : "Comment…") {
            let note = model.notes[node.id]
            noteText = (node.kind == .host ? note?.notes : note?.comment) ?? ""
            editingNote = node.id
        }
        Divider()
        Button("Delete Branch", role: .destructive) { model.deleteBranch(node.id) }
            .disabled(!node.visited)
    }

    private var endpointTable: some View {
        Table(model.endpoints, selection: $model.selectedExchangeID) {
            TableColumn("#") { Text("\($0.id)").monospacedDigit() }.width(50)
            TableColumn("Method") { Text($0.method ?? "") }.width(60)
            TableColumn("Path") { row in
                Text((row.path ?? "") + (row.query.map { "?" + $0 } ?? "")).lineLimit(1).truncationMode(
                    .middle)
            }
            TableColumn("Status") { Text($0.status.map(String.init) ?? "–").monospacedDigit() }.width(50)
            TableColumn("Length") { Text($0.responseLength.map(String.init) ?? "").monospacedDigit() }.width(
                70)
            TableColumn("MIME") { Text($0.mime ?? "") }.width(110)
            TableColumn("Params") { Text("\($0.paramCount)").monospacedDigit() }.width(50)
            TableColumn("Time") { Text($0.createdAt, style: .time) }.width(80)
        }
        .contextMenu(forSelectionType: ExchangeID.self) { ids in
            Button("Send to Repeater") { model.sendToRepeater(Array(ids)) }
        }
    }

    private var analysisShown: Binding<Bool> {
        Binding(get: { model.analysis != nil }, set: { if !$0 { model.analysis = nil } })
    }

    @ViewBuilder private var analysisSheet: some View {
        if let analysis = model.analysis {
            let host = analysis.host
            let result = analysis.result
            VStack(alignment: .leading, spacing: 10) {
                Text("Analyze target: \(host)").font(.title3)
                Text(
                    "\(result.requestCount) requests · \(result.endpointCount) endpoints "
                        + "(\(result.dynamicEndpointCount) dynamic, \(result.staticEndpointCount) static) · "
                        + "\(result.redirectCount) redirects")
                Text("Parameters").font(.headline)
                Table(result.parameters) {
                    TableColumn("Name", value: \.name)
                    TableColumn("Where") {
                        Text($0.locations.sorted().map(\.rawValue).joined(separator: ", "))
                    }
                    TableColumn("Seen") { Text("\($0.count)").monospacedDigit() }.width(50)
                    TableColumn("Endpoints") { Text($0.endpoints.joined(separator: ", ")).lineLimit(1) }
                    TableColumn("Example", value: \.sampleValue)
                }
                .frame(minHeight: 160)
                Text("Observations").font(.headline)
                List(result.observations, id: \.self) { observation in
                    VStack(alignment: .leading) {
                        Text("\(observation.parameter) — \(observation.endpoint)").bold()
                        Text(observation.detail).foregroundStyle(.secondary)
                    }
                }
                .frame(minHeight: 120)
                HStack {
                    Spacer()
                    Button("Done") { model.analysis = nil }.keyboardShortcut(.defaultAction)
                }
            }
            .padding()
            .frame(minWidth: 720, minHeight: 520)
        }
    }

    private var noteShown: Binding<Bool> {
        Binding(get: { editingNote != nil }, set: { if !$0 { editingNote = nil } })
    }

    private var noteTitle: String {
        guard let editingNote else { return "" }
        return model.node(editingNote)?.kind == .host ? "Host notes" : "Comment"
    }

    static func color(_ highlight: Highlight) -> Color {
        switch highlight {
        case .red: .red
        case .orange: .orange
        case .yellow: .yellow
        case .green: .green
        case .cyan: .cyan
        case .blue: .blue
        case .purple: .purple
        case .pink: .pink
        case .gray: .gray
        }
    }
}

/// Target → Scope.
struct ScopeView: View {
    @Bindable var model: ScopeModel
    @State private var advanced = false
    @State private var selection: Set<UUID> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(model.summary).font(.callout).textSelection(.enabled)
            HStack {
                TextField("Host or URL prefix, e.g. https://example.com/app", text: $model.addText)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { model.addFromField() }
                Button("Add to Scope") { model.addFromField() }
                Button("Exclude") { model.addFromField(kind: .exclude) }
            }
            chips
            HStack {
                TextField("Test a URL against the scope", text: $model.testText)
                    .textFieldStyle(.roundedBorder)
                if let result = model.testResult {
                    Text(result).foregroundStyle(result.hasPrefix("In") ? .green : .orange)
                }
            }
            Toggle(
                "Use scope for the proxy (out-of-scope traffic is forwarded but not recorded)",
                isOn: Binding(get: { model.useScopeForProxy }, set: { model.setUseScopeForProxy($0) }))
            DisclosureGroup("Advanced: include and exclude rules (last match wins)", isExpanded: $advanced) {
                rulesTable
            }
            if let message = model.message {
                Text(message).foregroundStyle(.red).font(.caption)
            }
            Spacer()
            HStack {
                Button("Import…") { model.importFile() }
                Button("Export…") { model.export() }
                Spacer()
            }
        }
        .padding()
    }

    private var chips: some View {
        ScrollView(.horizontal) {
            HStack {
                ForEach(model.stored.filter(\.enabled)) { rule in
                    HStack(spacing: 4) {
                        Text(
                            (rule.kind == .exclude ? "− " : "") + rule.host
                                + (rule.path.isEmpty ? "" : " " + rule.path)
                        )
                        .lineLimit(1)
                        Button {
                            model.remove([rule.id])
                            model.apply()
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(
                        (rule.kind == .include ? Color.accentColor : Color.orange).opacity(0.18),
                        in: Capsule())
                }
            }
        }
    }

    /// A binding to one rule of the edited list, by id (rows can move and be removed).
    private func binding(_ rule: ScopeRule) -> Binding<ScopeRule> {
        Binding(
            get: { model.rules.first { $0.id == rule.id } ?? rule },
            set: { changed in
                if let index = model.rules.firstIndex(where: { $0.id == rule.id }) {
                    model.rules[index] = changed
                }
            })
    }

    private var rulesTable: some View {
        VStack(alignment: .leading) {
            Table(model.rules, selection: $selection) {
                TableColumn("On") { row in Toggle("", isOn: binding(row).enabled).labelsHidden() }.width(30)
                TableColumn("Kind") { row in
                    Picker("", selection: binding(row).kind) {
                        Text("Include").tag(ScopeRule.Kind.include)
                        Text("Exclude").tag(ScopeRule.Kind.exclude)
                    }
                    .labelsHidden()
                }
                .width(90)
                TableColumn("Scheme") { row in
                    Picker("", selection: binding(row).scheme) {
                        ForEach(ScopeRule.Scheme.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    .labelsHidden()
                }
                .width(80)
                TableColumn("Host") { row in
                    HStack {
                        TextField("host", text: binding(row).host)
                        Toggle("Regex", isOn: binding(row).hostIsRegex).toggleStyle(.checkbox)
                    }
                }
                TableColumn("Port") { row in TextField("any", text: binding(row).port) }.width(80)
                TableColumn("Path regex") { row in
                    HStack {
                        TextField("any", text: binding(row).path)
                        if let problem = model.problem(row) {
                            Image(systemName: "exclamationmark.triangle").foregroundStyle(.yellow).help(
                                problem)
                        }
                    }
                }
            }
            .frame(minHeight: 180)
            HStack {
                Button("Add Rule") { model.addBlankRule() }
                Button("Remove") { model.remove(selection) }.disabled(selection.isEmpty)
                Button("Move Up") { if let id = selection.first { model.move(id, by: -1) } }
                    .disabled(selection.count != 1)
                Button("Move Down") { if let id = selection.first { model.move(id, by: 1) } }
                    .disabled(selection.count != 1)
                Spacer()
                Button("Revert") { model.revert() }.disabled(!model.isDirty)
                Button("Apply") { model.apply() }.disabled(!model.isDirty).keyboardShortcut(.defaultAction)
            }
        }
    }
}
#endif
