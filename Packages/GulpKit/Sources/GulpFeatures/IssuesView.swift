// GulpFeatures — the Dashboard's issues (F08 SCN-005): a tree (severity → type → location) with
// filters and bulk status changes, and a detail pane with the issue's markdown, triage controls and
// each evidence exchange with the proof highlighted (SCN-002), plus Send to Repeater. The passive
// scanner's switches live in the header. Live updates are coalesced (at most every 100 ms).

#if canImport(AppKit)
import AppKit
import GulpCore
import GulpStore
import GulpWorkspace
import Observation
import SwiftUI

/// State behind the issues dashboard.
@MainActor
@Observable
final class IssuesModel {
    private(set) var issues: [Issue] = []
    var selection: Set<IssueID> = []
    private(set) var detail: Issue?
    private(set) var evidenceExchanges: [Int64: Exchange] = [:]
    var severities: Set<IssueSeverity> = [] { didSet { reload() } }
    var statuses: Set<IssueStatus> = [.open] { didSet { reload() } }
    var minimumConfidence = IssueConfidence.tentative { didSet { reload() } }
    var hostFilter = "" { didSet { reload() } }
    var config = PassiveScanConfig()

    @ObservationIgnored let session: ProjectSession
    @ObservationIgnored private var listener: Task<Void, Never>?
    @ObservationIgnored private var pending: Task<Void, Never>?

    init(session: ProjectSession) {
        self.session = session
        listener = Task { [weak self] in
            guard let events = self?.session.events else { return }
            for await delivery in await events.subscribe() {
                guard let self else { return }
                if case .issueFound = delivery.event { self.scheduleReload() }
            }
        }
        Task { config = await session.passiveScanConfig() }
        reload()
    }

    /// Issues of one type within a severity.
    struct TypeGroup: Identifiable {
        var id: String
        var issues: [Issue]
    }

    /// One severity's types.
    struct SeverityGroup: Identifiable {
        var id: IssueSeverity
        var types: [TypeGroup]
        var count: Int { types.reduce(0) { $0 + $1.issues.count } }
    }

    /// Severity → type → issues, most severe first.
    var tree: [SeverityGroup] {
        IssueSeverity.allCases.reversed().compactMap { severity in
            let matching = issues.filter { $0.severity == severity }
            guard !matching.isEmpty else { return nil }
            var order: [String] = []
            var byType: [String: [Issue]] = [:]
            for issue in matching {
                if byType[issue.name] == nil { order.append(issue.name) }
                byType[issue.name, default: []].append(issue)
            }
            return SeverityGroup(
                id: severity, types: order.map { TypeGroup(id: $0, issues: byType[$0] ?? []) })
        }
    }

    private func scheduleReload() {
        guard pending == nil else { return }
        pending = Task {
            try? await Task.sleep(for: .milliseconds(100))
            pending = nil
            reload()
        }
    }

    func reload() {
        var filter = IssueFilter()
        filter.severities = severities
        filter.statuses = statuses
        filter.host = hostFilter.isEmpty ? nil : hostFilter
        filter.confidences = Set(IssueConfidence.allCases.filter { $0 >= minimumConfidence })
        let session = self.session
        Task {
            issues = (try? await session.store.issues(filter)) ?? []
            if let current = detail?.id { load(current) }
        }
    }

    func load(_ id: IssueID?) {
        guard let id else {
            detail = nil
            return
        }
        let session = self.session
        Task {
            guard let issue = try? await session.store.issue(id) else { return }
            var exchanges: [Int64: Exchange] = [:]
            for evidence in issue.evidence.prefix(5) {
                if let exchangeID = evidence.exchangeID,
                    let exchange = try? await session.store.exchange(id: exchangeID)
                {
                    exchanges[evidence.id] = exchange
                }
            }
            if selection == [id] || selection.isEmpty {
                detail = issue
                evidenceExchanges = exchanges
            }
        }
    }

    func setStatus(_ status: IssueStatus) {
        let ids = Array(selection)
        let session = self.session
        Task {
            try? await session.store.setIssueStatus(status, for: ids)
            reload()
        }
    }

    func override(severity: IssueSeverity?, confidence: IssueConfidence?) {
        guard let id = detail?.id else { return }
        let session = self.session
        Task {
            try? await session.store.overrideIssue(id, severity: severity, confidence: confidence)
            reload()
        }
    }

    func saveNotes(_ notes: String) {
        guard let id = detail?.id else { return }
        let session = self.session
        Task { try? await session.store.setIssueNotes(id, notes) }
    }

    func sendToRepeater(_ exchangeID: ExchangeID) {
        let session = self.session
        Task { _ = await session.sendToRepeater([exchangeID]) }
    }

    func applyConfig() {
        let value = config
        let session = self.session
        Task { try? await session.setPassiveScanConfig(value) }
    }

    func rescan() {
        let session = self.session
        Task { try? await session.passiveScan.rescanAll() }
    }
}

/// The Dashboard: issues found by the Scanner (passive since M10a).
public struct IssuesDashboard: View {
    let session: ProjectSession
    @State private var model: IssuesModel?

    /// The dashboard of `session`.
    public init(session: ProjectSession) {
        self.session = session
    }

    public var body: some View {
        if let model {
            IssuesPanel(model: model)
        } else {
            ProgressView().task { model = IssuesModel(session: session) }
        }
    }
}

struct IssuesPanel: View {
    @Bindable var model: IssuesModel

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HSplitView {
                List(selection: $model.selection) {
                    ForEach(model.tree) { group in
                        Section("\(group.id.title) (\(group.count))") {
                            ForEach(group.types) { type in
                                DisclosureGroup("\(type.id) (\(type.issues.count))") {
                                    ForEach(type.issues) { issue in
                                        VStack(alignment: .leading, spacing: 1) {
                                            Text(issue.host + issue.path).lineLimit(1)
                                            Text(
                                                [
                                                    issue.insertionPoint, issue.confidence.title,
                                                    issue.status.title,
                                                ]
                                                .compactMap { $0 }.joined(separator: " · ")
                                            )
                                            .font(.caption).foregroundStyle(.secondary)
                                        }
                                        .tag(issue.id)
                                    }
                                }
                            }
                        }
                    }
                }
                .frame(minWidth: 320, idealWidth: 380)
                .contextMenu {
                    ForEach(IssueStatus.allCases, id: \.self) { status in
                        Button("Mark \(status.title)") { model.setStatus(status) }
                    }
                }
                .onChange(of: model.selection) {
                    model.load(model.selection.count == 1 ? model.selection.first : nil)
                }
                if let issue = model.detail, model.selection.count <= 1 {
                    IssueDetail(model: model, issue: issue).id(issue.id)
                } else {
                    ContentUnavailableView(
                        model.selection.count > 1
                            ? "\(model.selection.count) issues selected" : "No issue selected",
                        systemImage: "ladybug",
                        description: Text(
                            model.selection.count > 1
                                ? "Use the context menu to change their status."
                                : "Browse in scope; passive checks run as traffic arrives."))
                }
            }
        }
        .navigationTitle("Dashboard")
    }

    private var header: some View {
        HStack(spacing: 8) {
            ForEach(Array(IssueSeverity.allCases.reversed()), id: \.self) { severity in
                Toggle(severity.title, isOn: membership(\.severities, severity))
            }
            Divider().frame(height: 16)
            ForEach(IssueStatus.allCases, id: \.self) { status in
                Toggle(status.title, isOn: membership(\.statuses, status))
            }
            Picker("Confidence ≥", selection: $model.minimumConfidence) {
                ForEach(IssueConfidence.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .frame(width: 180)
            TextField("Host", text: $model.hostFilter).textFieldStyle(.roundedBorder).frame(width: 140)
            Spacer()
            Menu("Passive Scanning") {
                Toggle("Enabled", isOn: $model.config.enabled)
                Toggle("Include out-of-scope traffic", isOn: $model.config.allTraffic)
                Toggle("Also scan Repeater traffic", isOn: extraTool("repeater"))
                Toggle("Also scan Fuzzer traffic", isOn: extraTool("fuzzer"))
                Divider()
                Button("Scan History Again") { model.rescan() }
            }
            .frame(width: 150)
            .onChange(of: model.config) { model.applyConfig() }
        }
        .toggleStyle(.button)
        .controlSize(.small)
        .padding(6)
    }

    private func membership<T: Hashable>(_ path: ReferenceWritableKeyPath<IssuesModel, Set<T>>, _ value: T)
        -> Binding<Bool>
    {
        Binding(
            get: { model[keyPath: path].contains(value) },
            set: { on in
                if on { model[keyPath: path].insert(value) } else { model[keyPath: path].remove(value) }
            })
    }

    private func extraTool(_ tool: String) -> Binding<Bool> {
        Binding(
            get: { model.config.extraTools.contains(tool) },
            set: { on in
                model.config.extraTools.removeAll { $0 == tool }
                if on { model.config.extraTools.append(tool) }
            })
    }
}

struct IssueDetail: View {
    let model: IssuesModel
    let issue: Issue
    @State private var notes: String

    init(model: IssuesModel, issue: Issue) {
        self.model = model
        self.issue = issue
        _notes = State(initialValue: issue.notes)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text(issue.name).font(.title2)
                HStack {
                    Picker("Severity", selection: severityBinding) {
                        ForEach(Array(IssueSeverity.allCases.reversed()), id: \.self) {
                            Text($0.title).tag($0)
                        }
                    }
                    .frame(width: 180)
                    Picker("Confidence", selection: confidenceBinding) {
                        ForEach(Array(IssueConfidence.allCases.reversed()), id: \.self) {
                            Text($0.title).tag($0)
                        }
                    }
                    .frame(width: 200)
                    if issue.severityOverride != nil || issue.confidenceOverride != nil {
                        Button("Restore Check Values") { model.override(severity: nil, confidence: nil) }
                    }
                    Spacer()
                    Text(issue.status.title).foregroundStyle(.secondary)
                }
                Text("\(issue.host)\(issue.path)" + (issue.insertionPoint.map { " · \($0)" } ?? ""))
                    .font(.system(.body, design: .monospaced)).textSelection(.enabled)
                section("Detail", issue.detail)
                section("Background", issue.background)
                section("Remediation", issue.remediation)
                if !issue.references.isEmpty { section("References", issue.references) }
                Text("Notes").font(.headline)
                TextEditor(text: $notes).frame(minHeight: 60).onChange(of: notes) { model.saveNotes(notes) }
                Text("Evidence (\(issue.evidenceCount))").font(.headline)
                ForEach(issue.evidence.prefix(5), id: \.id) { evidence in
                    if let exchange = model.evidenceExchanges[evidence.id] {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text("Exchange #\(exchange.id)" + (evidence.note.map { " — \($0)" } ?? ""))
                                Spacer()
                                Button("Send to Repeater") { model.sendToRepeater(exchange.id) }
                            }
                            HSplitView {
                                HighlightedBytes(
                                    title: "Request", bytes: exchange.request.bytes.rawBytes,
                                    markers: evidence.requestMarkers)
                                HighlightedBytes(
                                    title: "Response", bytes: exchange.response?.wireBytes.rawBytes ?? [],
                                    markers: evidence.responseMarkers)
                            }
                            .frame(minHeight: 220)
                        }
                    } else {
                        Text(evidence.note ?? "Evidence without a stored exchange").foregroundStyle(
                            .secondary)
                    }
                }
            }
            .padding()
        }
    }

    private func section(_ title: String, _ markdown: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline)
            // Inline markdown only: links are inert attributes, raw HTML stays text.
            Text(
                (try? AttributedString(
                    markdown: markdown, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)))
                    ?? AttributedString(markdown)
            )
            .textSelection(.enabled)
        }
    }

    private var severityBinding: Binding<IssueSeverity> {
        Binding(
            get: { issue.severity },
            set: { model.override(severity: $0, confidence: issue.confidenceOverride) })
    }

    private var confidenceBinding: Binding<IssueConfidence> {
        Binding(
            get: { issue.confidence },
            set: { model.override(severity: issue.severityOverride, confidence: $0) })
    }
}

/// Bytes as text with the marker ranges highlighted (SCN-002). One character per byte (Latin-1), so
/// byte offsets index the text exactly.
struct HighlightedBytes: View {
    let title: String
    let bytes: [UInt8]
    let markers: [MarkerRange]
    static let limit = 256 * 1024

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            ScrollView([.vertical, .horizontal]) {
                Text(attributed).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var attributed: AttributedString {
        let shown = Array(bytes.prefix(Self.limit))
        func text(_ range: Range<Int>) -> AttributedString {
            var scalars = String.UnicodeScalarView()
            scalars.append(contentsOf: shown[range].map { Unicode.Scalar($0) })
            return AttributedString(String(scalars))
        }
        var result = AttributedString()
        var position = 0
        for marker in markers.sorted(by: { $0.start < $1.start }) {
            let start = min(max(marker.start, position), shown.count)
            let end = min(marker.end, shown.count)
            guard start < end else { continue }
            result += text(position..<start)
            var highlighted = text(start..<end)
            highlighted.backgroundColor = .yellow.opacity(0.45)
            highlighted.foregroundColor = .primary
            result += highlighted
            position = end
        }
        result += text(position..<shown.count)
        return result
    }
}
#endif
