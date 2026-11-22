// GulpFeatures — the Dashboard's issues (F08 SCN-005): a tree (severity → type → location) with
// filters and bulk status changes, and a detail pane with the issue's markdown, triage controls and
// each evidence exchange with the proof highlighted (SCN-002), plus Send to Repeater. The passive
// scanner's switches live in the header. Live updates are coalesced (at most every 100 ms).

#if canImport(AppKit)
import AppKit
import GulpCore
import GulpStore
import GulpUI
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
    /// Why the last change could not be saved, if it could not.
    private(set) var message: String?
    var severities: Set<IssueSeverity> = [] { didSet { reload() } }
    var statuses: Set<IssueStatus> = [.open] { didSet { reload() } }
    var minimumConfidence = IssueConfidence.tentative { didSet { reload() } }
    var hostFilter = "" { didSet { reload() } }
    var config = PassiveScanConfig()

    @ObservationIgnored let session: ProjectSession
    @ObservationIgnored private var listener: Task<Void, Never>?
    @ObservationIgnored private var pending: Task<Void, Never>?
    /// Counts reloads, so a slower, older query cannot overwrite a newer one.
    @ObservationIgnored private var reloads = 0

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
        reloads += 1
        let reload = reloads
        Task {
            let found = (try? await session.store.issues(filter)) ?? []
            // A newer reload (the filter changed meanwhile) wins, whichever query finishes last.
            guard reload == reloads else { return }
            issues = found
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
        write("Changing the status", reloading: true) {
            try await session.store.setIssueStatus(status, for: ids)
        }
    }

    func override(severity: IssueSeverity?, confidence: IssueConfidence?) {
        guard let id = detail?.id else { return }
        let session = self.session
        write("Overriding the issue", reloading: true) {
            try await session.store.overrideIssue(id, severity: severity, confidence: confidence)
        }
    }

    func saveNotes(_ notes: String) {
        guard let id = detail?.id else { return }
        let session = self.session
        write("Saving the notes") { try await session.store.setIssueNotes(id, notes) }
    }

    func sendToRepeater(_ exchangeID: ExchangeID) {
        let session = self.session
        Task { _ = await session.sendToRepeater([exchangeID]) }
    }

    func applyConfig() {
        let value = config
        let session = self.session
        write("Saving the passive scan settings") { try await session.setPassiveScanConfig(value) }
    }

    func rescan() {
        let session = self.session
        write("Scanning History again") { try await session.passiveScan.rescanAll() }
    }

    /// Run a write; a failure is shown above the issues (never dropped), and `reloading` refreshes
    /// the list afterwards.
    private func write(_ action: String, reloading: Bool = false, _ body: @escaping () async throws -> Void) {
        Task {
            do {
                try await body()
                message = nil
            } catch {
                message = "\(action) failed: \(ProjectSession.describe(error))"
            }
            if reloading { reload() }
        }
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

    /// The screen.
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
            if let message = model.message {
                Text(message).font(.caption).foregroundStyle(.red).padding(.horizontal, 6)
            }
            Divider()
            HSplit {
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
        HStack(alignment: .top, spacing: 8) {
            // Wraps instead of truncating the chips when the detail area is narrow (UI-002).
            FlowLayout(spacing: 16) {
                HStack(spacing: 8) {
                    ForEach(Array(IssueSeverity.allCases.reversed()), id: \.self) { severity in
                        Toggle(severity.title, isOn: membership(\.severities, severity))
                    }
                }
                HStack(spacing: 8) {
                    ForEach(IssueStatus.allCases, id: \.self) { status in
                        Toggle(status.title, isOn: membership(\.statuses, status))
                    }
                }
                Picker("Confidence ≥", selection: $model.minimumConfidence) {
                    ForEach(IssueConfidence.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .fixedSize()
                TextField("Host", text: $model.hostFilter).textFieldStyle(.roundedBorder).frame(width: 140)
            }
            Spacer(minLength: 0)
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
                            HSplit {
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
/// byte offsets index the text exactly. An `NSTextView` draws it and lays out only what is visible;
/// a SwiftUI `Text` laid out all of it on the main thread (~350 ms per 256 KB pane in a debug build,
/// and an issue shows up to ten panes).
struct HighlightedBytes: View {
    let title: String
    let bytes: [UInt8]
    let markers: [MarkerRange]
    static let limit = 256 * 1024

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            RawTextView(
                text: Self.text(bytes), highlights: Self.ranges(markers, length: min(bytes.count, Self.limit))
            )
        }
    }

    static func text(_ bytes: [UInt8]) -> String {
        String(bytes: bytes.prefix(limit), encoding: .isoLatin1) ?? ""
    }

    /// The markers inside the shown text, as text ranges.
    static func ranges(_ markers: [MarkerRange], length: Int) -> [NSRange] {
        markers.compactMap { marker in
            let start = max(0, marker.start)
            let end = min(marker.end, length)
            return start < end ? NSRange(location: start, length: end - start) : nil
        }
    }
}
#endif
