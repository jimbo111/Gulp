// GulpFeatures — the Scanner screen (F08 SCN-034/035): an Audit pane and the Crawl pane (F09).
// Audit takes the requests sent with "Actively scan" (History), lets the user pick a preset, the
// "unsafe payloads" gate and an explicit out-of-scope override, then runs the scan as a task with
// pause/resume/stop. Progress and the live findings list refresh at most every 100 ms; findings are
// recorded as issues by the workspace, so the Dashboard shows them too.

#if canImport(AppKit)
import AppKit
import GulpCore
import GulpScanner
import GulpWorkspace
import Observation
import SwiftUI

/// State behind the Audit pane.
@MainActor
@Observable
final class ActiveScanModel {
    var preset = ScanConfig.Preset.balanced
    var unsafe = false
    var allowOutOfScope = false
    private(set) var queued: [ExchangeID] = []
    private(set) var running = false
    private(set) var paused = false
    private(set) var pointsDone = 0
    private(set) var points = 0
    private(set) var probes = 0
    private(set) var findings: [IssueFinding] = []
    private(set) var log: [String] = []
    private(set) var summary: ScanSummary?
    @ObservationIgnored let session: ProjectSession
    @ObservationIgnored private var scan: ActiveScan?
    @ObservationIgnored private var pending: (findings: [IssueFinding], log: [String]) = ([], [])
    @ObservationIgnored private var pendingProgress: (done: Int, total: Int, probes: Int)?

    init(session: ProjectSession) { self.session = session }

    /// Follow "Actively scan" sends for as long as the pane is shown.
    func watchInbox() async {
        let inbox = session.inbox
        queued = await inbox.scanInput
        for await tool in await inbox.opened() where tool == .scanner {
            queued = await inbox.scanInput
        }
    }

    func start() {
        guard !queued.isEmpty, !running else { return }
        var config = ScanConfig.preset(preset)
        config.unsafe = unsafe
        running = true
        paused = false
        summary = nil
        findings = []
        log = []
        let ids = queued
        let allow = allowOutOfScope
        Task {
            let requests = (try? await session.scanRequests(exchanges: ids)) ?? []
            let run = await session.startActiveScan(
                requests, config: config, allowOutOfScope: allow, name: "Active scan (\(ids.count) requests)")
            scan = run.scan
            let ticker = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for: .milliseconds(100))  // coalesced UI updates
                    self?.refresh()
                }
            }
            for await event in run.events {
                switch event {
                case .finding(let finding): pending.findings.append(finding)
                case .log(let line): pending.log.append(line)
                case .progress(_, _, let done, let total, let probes): pendingProgress = (done, total, probes)
                case .finished(let done): summary = done
                }
            }
            ticker.cancel()
            refresh()
            running = false
            scan = nil
        }
    }

    func refresh() {
        if !pending.findings.isEmpty {
            findings.append(contentsOf: pending.findings)
            findings.sort { ($0.severity, $0.name) > ($1.severity, $1.name) }
        }
        if !pending.log.isEmpty {
            log.append(contentsOf: pending.log)
            if log.count > 1_000 { log.removeFirst(log.count - 1_000) }
        }
        pending = ([], [])
        if let progress = pendingProgress {
            pointsDone = progress.done
            points = progress.total
            probes = progress.probes
            pendingProgress = nil
        }
    }

    func togglePause() {
        guard let scan else { return }
        paused.toggle()
        let pause = paused
        Task {
            if pause {
                await scan.pause()
            } else {
                await scan.resume()
            }
        }
    }

    func stop() {
        guard let scan else { return }
        Task { await scan.cancel() }
    }
}

/// Scanner: Audit (active scan) and Crawl.
public struct ScannerView: View {
    enum Pane: String, CaseIterable { case audit = "Audit", crawl = "Crawl" }

    let session: ProjectSession
    @State private var pane = Pane.audit

    /// The Scanner for `session`.
    public init(session: ProjectSession) { self.session = session }

    public var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $pane) {
                ForEach(Pane.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 240)
            .padding(8)
            Divider()
            switch pane {
            case .audit: ActiveScanView(session: session)
            case .crawl: CrawlerView(session: session)
            }
        }
    }
}

/// Scanner → Audit (SCN-034/035).
struct ActiveScanView: View {
    @State private var model: ActiveScanModel
    @State private var confirmOutOfScope = false
    @State private var confirmUnsafe = false

    init(session: ProjectSession) { _model = State(initialValue: ActiveScanModel(session: session)) }

    var body: some View {
        HSplitView {
            Form {
                Section("Requests") {
                    if model.queued.isEmpty {
                        Text("Select rows in HTTP History and choose **Actively scan**.")
                            .foregroundStyle(.secondary)
                    } else {
                        Text(
                            "\(model.queued.count) request(s) queued: "
                                + model.queued.prefix(8).map { "#\($0)" }.joined(separator: ", ")
                                + (model.queued.count > 8 ? "…" : ""))
                    }
                }
                Section("Configuration") {
                    Picker("Preset", selection: $model.preset) {
                        Text("Light").tag(ScanConfig.Preset.light)
                        Text("Balanced").tag(ScanConfig.Preset.balanced)
                        Text("Thorough").tag(ScanConfig.Preset.thorough)
                        Text("Passive only").tag(ScanConfig.Preset.passiveOnly)
                    }
                    Toggle("Payloads that may change data", isOn: unsafeBinding)
                        .help(
                            "Off by default (SCN-038): stored-XSS markers still run on requests that already submit data."
                        )
                    Toggle("Scan out-of-scope requests", isOn: outOfScopeBinding)
                        .help("Only in-scope requests are sent unless you override it for this scan.")
                }
                Section {
                    HStack {
                        Button(model.running ? "Scanning…" : "Start scan") { model.start() }
                            .disabled(model.running || model.queued.isEmpty)
                            .keyboardShortcut(.defaultAction)
                        Button(model.paused ? "Resume" : "Pause") { model.togglePause() }.disabled(
                            !model.running)
                        Button("Stop") { model.stop() }.disabled(!model.running)
                    }
                    if model.running || model.summary != nil {
                        ProgressView(value: Double(model.pointsDone), total: Double(max(1, model.points)))
                        Text(
                            "\(model.pointsDone)/\(model.points) insertion points · \(model.probes) requests"
                        )
                        .font(.caption).foregroundStyle(.secondary)
                    }
                    if let summary = model.summary {
                        Text(
                            "\(summary.stopReason == "done" ? "Finished" : "Stopped"): \(summary.findings) issue(s), \(summary.probes) requests in \(String(format: "%.1f", summary.seconds)) s"
                                + (summary.outOfScope > 0
                                    ? " · \(summary.outOfScope) out of scope, not scanned" : ""))
                    }
                }
            }
            .formStyle(.grouped)
            .frame(minWidth: 320, idealWidth: 360)
            VSplitView {
                Table(model.findings.map(ScanFindingRow.init)) {
                    TableColumn("Severity") { Text($0.finding.severity.rawValue.capitalized) }.width(70)
                    TableColumn("Issue") { Text($0.finding.name) }
                    TableColumn("Path") { Text($0.finding.path) }
                    TableColumn("Insertion point") { Text($0.finding.insertionPoint ?? "—") }
                }
                .frame(minHeight: 160)
                List(Array(model.log.enumerated()), id: \.offset) {
                    Text($0.element).font(.system(.caption, design: .monospaced))
                }
                .frame(minHeight: 80)
            }
        }
        .task { await model.watchInbox() }
        .confirmationDialog("Scan requests outside the target scope?", isPresented: $confirmOutOfScope) {
            Button("Scan out of scope", role: .destructive) { model.allowOutOfScope = true }
        } message: {
            Text("Active scanning sends attack payloads. Only do this for hosts you are authorized to test.")
        }
        .confirmationDialog("Allow payloads that may change data?", isPresented: $confirmUnsafe) {
            Button("Allow", role: .destructive) { model.unsafe = true }
        }
    }

    private var outOfScopeBinding: Binding<Bool> {
        Binding(
            get: { model.allowOutOfScope },
            set: { on in
                if on { confirmOutOfScope = true } else { model.allowOutOfScope = false }
            })
    }

    private var unsafeBinding: Binding<Bool> {
        Binding(
            get: { model.unsafe },
            set: { on in
                if on { confirmUnsafe = true } else { model.unsafe = false }
            })
    }
}

/// A row of the findings table (the dedup key is unique within a scan).
struct ScanFindingRow: Identifiable {
    let finding: IssueFinding
    var id: String { finding.dedupKey }
}
#endif
