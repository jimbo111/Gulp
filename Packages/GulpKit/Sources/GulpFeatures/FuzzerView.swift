// GulpFeatures — the Fuzzer (F07): Positions (the base request with § markers and the attack type),
// Payloads (one set per position, source + processing + live preview + count), Settings (grep and
// extract columns, concurrency, rps, delays, retries, stop conditions), Results (a live table with
// baseline anomalies, pause/resume/cancel, CSV export), and Discover content (ETL-003) with its path
// tree. The engine is GulpFuzzer, tested on Linux; this file only shows it.

#if canImport(AppKit)
import AppKit
import GulpCodec
import GulpCore
import GulpFuzzer
import GulpUI
import GulpWorkspace
import Observation
import SwiftUI

/// The editable form of one payload set.
struct PayloadSetDraft: Identifiable, Hashable {
    enum Kind: String, CaseIterable, Identifiable {
        case list = "Simple list", file = "Wordlist file", numbers = "Numbers", brute = "Brute force", null =
            "Null"
        case base = "Same as base"
        var id: String { rawValue }
    }

    var id = UUID()
    var kind = Kind.list
    var listText = ""
    var filePath = ""
    var from = 1
    var to = 100
    var step = 1
    var charset = "abc123"
    var minLength = 1
    var maxLength = 3
    var nullCount = 10
    /// Processors, one per line: `prefix=x`, `suffix=x`, `skip=REGEX`, `upper`, `lower`, `reverse`,
    /// `tags=«…«var(payload)»…»`, or a Decoder operation name (`url-encode`, `sha256`…).
    var processorText = ""

    var set: PayloadSet {
        let source: PayloadSource
        switch kind {
        case .list: source = .list(listText.split(whereSeparator: \.isNewline).map(String.init))
        case .file: source = .file(path: filePath)
        case .numbers: source = .numbers(from: from, to: to, step: step, minDigits: 0, hex: false)
        case .brute: source = .bruteForce(charset: charset, minLength: minLength, maxLength: maxLength)
        case .null: source = .null(count: nullCount)
        case .base: source = .sameAsBase
        }
        let processors: [PayloadProcessor] = processorText.split(whereSeparator: \.isNewline).map { line in
            let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
            let value = parts.count > 1 ? parts[1] : ""
            switch parts[0] {
            case "prefix": return .prefix(value)
            case "suffix": return .suffix(value)
            case "skip": return .skipIf(pattern: value)
            case "upper": return .caseRule(.upper)
            case "lower": return .caseRule(.lower)
            case "reverse": return .reverse
            case "tags": return .tags(value)
            default: return .transform(parts[0], [:])
            }
        }
        return PayloadSet(source, processors: processors)
    }
}

/// One saved attack in the Fuzzer's menu (FUZ-026).
struct SavedAttackSummary: Identifiable, Hashable {
    var id: Int64
    var name: String
    var state: String
    var count: Int
}

/// State behind the Fuzzer.
@MainActor
@Observable
final class FuzzerModel {
    // Positions
    var request: [UInt8] = Array("GET /§path§ HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)
    var targetText = "https://example.com"
    var attackType = AttackType.sniper
    /// Protobuf field positions for an RPC request (F33 GRP-005), comma-separated dotted paths
    /// (names with an imported schema, else numbers); empty for § positions.
    var rpcFieldsText = ""
    // Payloads
    var sets: [PayloadSetDraft] = [PayloadSetDraft()]
    // Settings
    var settings = FuzzSettings()
    var matchText = ""
    var extractText = ""
    var allowOutOfScope = false
    // Results
    private(set) var results: [FuzzResult] = []
    private(set) var summary: FuzzSummary?
    private(set) var running = false
    private(set) var paused = false
    var baselineSeq: Int?
    private(set) var message: String?
    private(set) var savedAttacks: [SavedAttackSummary] = []
    var selectedSeq: Int?
    private(set) var shown: Exchange?
    // Discover content
    var discoverURL = "https://example.com/"
    private(set) var discovered: [DiscoveredPath] = []
    private(set) var discovering = false

    /// Wordlist files by path, read off the main thread when a set's path is set (FUZ-010): the
    /// planned count and the preview, which the view renders, never touch the disk.
    private(set) var wordlists: [String: Wordlist] = [:]

    /// A wordlist file's payloads, or why it could not be read.
    enum Wordlist: Equatable {
        case loaded([String])
        case failed(String)
    }

    @ObservationIgnored let session: ProjectSession
    @ObservationIgnored private var run: FuzzRun?
    @ObservationIgnored private var discovery: ContentDiscovery?
    /// Results not yet in the table, and the 100 ms tick that moves them there (AGENTS.md §4).
    @ObservationIgnored private var pendingResults: [FuzzResult] = []
    @ObservationIgnored private var resultTicker: Task<Void, Never>?

    /// The Fuzzer of `session`.
    init(session: ProjectSession) {
        self.session = session
        Task { await reloadSaved() }
    }

    /// The attack as configured; wordlist sets name their file (the engine reads it).
    var config: FuzzAttackConfig? { config(sets: sets.map(\.set)) }

    /// Read the wordlist at `path` once, off the main thread.
    func loadWordlist(_ path: String) async {
        guard !path.isEmpty, wordlists[path] == nil else { return }
        do {
            let lines = try await Task.detached { try PayloadSource.lines(path) }.value
            wordlists[path] = .loaded(lines)
        } catch {
            wordlists[path] = .failed(error.localizedDescription)
        }
    }

    /// The set as planned on screen: a wordlist file becomes its loaded lines; nil while a wordlist
    /// is not loaded.
    private func plannedSet(_ draft: PayloadSetDraft) -> PayloadSet? {
        let set = draft.set
        guard draft.kind == .file else { return set }
        guard case .loaded(let lines) = wordlists[draft.filePath] else { return nil }
        return PayloadSet(.list(lines), processors: set.processors)
    }

    private func config(sets: [PayloadSet]) -> FuzzAttackConfig? {
        // Pure: the view reads this while rendering, so it must not change observed state.
        guard let target = HTTPTarget(url: targetText.trimmingCharacters(in: .whitespaces)) else {
            return nil
        }
        let matches = matchText.split(whereSeparator: \.isNewline).map { line -> GrepMatch in
            line.hasPrefix("re:")
                ? GrepMatch(String(line.dropFirst(3)), isRegex: true) : GrepMatch(String(line))
        }
        let extracts = extractText.split(whereSeparator: \.isNewline).compactMap { line -> GrepExtract? in
            if line.hasPrefix("regex:") { return .regex(pattern: String(line.dropFirst(6)), group: 1) }
            let parts = line.split(separator: "|", maxSplits: 1).map(String.init)
            return parts.count == 2 ? .between(start: parts[0], end: parts[1]) : nil
        }
        return FuzzAttackConfig(
            name: "Attack \(savedAttacks.count + 1)", target: target, request: request,
            attackType: attackType,
            sets: sets, matches: matches, extracts: extracts, settings: settings,
            rpcFields: rpcFields)
    }

    /// The protobuf field paths of `rpcFieldsText` (nil: § positions). An unresolvable name makes
    /// an empty path, which the plan reports as a missing field.
    var rpcFields: [[Int]]? {
        let names = rpcFieldsText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !names.isEmpty else { return nil }
        let schema = session.grpcSchemaSet()
        let input = RPC.parse(request: RawRequest(Bytes(request)), response: nil).flatMap {
            schema.types(for: $0.path)?.input
        }
        return names.map { schema.fieldPath($0, type: input) ?? [0] }
    }

    /// Positions in the request (0 when the markers are unbalanced or a field is missing).
    var positionCount: Int {
        if let rpcFields {
            return (try? RPCPositions(request: request, paths: rpcFields).paths.count) ?? 0
        }
        return (try? FuzzTemplate(request, marker: settings.marker).positionCount) ?? 0
    }

    /// The planned request count, or a problem.
    var plannedCount: String {
        for draft in sets where draft.kind == .file {
            switch wordlists[draft.filePath] {
            case nil: return draft.filePath.isEmpty ? "Choose a wordlist" : "Loading wordlist…"
            case .failed(let reason): return "Wordlist unreadable: \(reason)"
            case .loaded: continue
            }
        }
        guard let config = config(sets: sets.compactMap(plannedSet)) else {
            return "Target must be scheme://host[:port]"
        }
        do {
            let count = try config.plan().count
            return count == .max ? "too many to count" : "\(count) requests"
        } catch {
            return "\(error)"
        }
    }

    /// Keep one payload set per position for pitchfork and cluster bomb.
    func syncSets() {
        let needed = attackType == .pitchfork || attackType == .clusterBomb ? max(1, positionCount) : 1
        while sets.count < needed { sets.append(PayloadSetDraft()) }
        if sets.count > needed { sets.removeLast(sets.count - needed) }
    }

    /// FUZ-001: mark every parameter, cookie and header value.
    func autoMark() {
        request = FuzzTemplate.autoMark(
            RawRequest(Bytes(FuzzTemplate.clear(request, marker: settings.marker))), marker: settings.marker)
        syncSets()
    }

    /// FUZ-001: remove every marker.
    func clearMarks() {
        request = FuzzTemplate.clear(request, marker: settings.marker)
        syncSets()
    }

    /// Live preview of a set's first processed payloads (FUZ-012).
    func preview(_ draft: PayloadSetDraft) -> [String] {
        guard let set = plannedSet(draft) else { return [] }
        return (try? PayloadPipeline(set.processors).preview(set.source, count: 8)) ?? ["(invalid processor)"]
    }

    /// Start the attack (FUZ-004).
    func start() {
        guard !running else { return }
        guard let config else {
            message = "Target must be scheme://host[:port]."
            return
        }
        results = []
        summary = nil
        message = nil
        running = true
        paused = false
        let session = self.session
        let allow = allowOutOfScope
        Task {
            beginResults()
            do {
                let run = try await session.startAttack(config, allowOutOfScope: allow)
                self.run = run
                for await event in run.events {
                    switch event {
                    case .result(let result): buffer(result)
                    case .finished(let done): summary = done
                    }
                }
            } catch {
                message = "\(error)"
            }
            endResults()
            running = false
            await reloadSaved()
        }
    }

    /// Start moving buffered results into the table every 100 ms.
    func beginResults() {
        resultTicker?.cancel()
        pendingResults = []
        resultTicker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(100))
                guard let self else { return }
                self.flushResults()
            }
        }
    }

    /// Hold a result for the next tick.
    func buffer(_ result: FuzzResult) { pendingResults.append(result) }

    /// Stop the tick and move what is left into the table.
    func endResults() {
        resultTicker?.cancel()
        resultTicker = nil
        flushResults()
    }

    private func flushResults() {
        guard !pendingResults.isEmpty else { return }
        results += pendingResults
        pendingResults = []
    }

    func pause() {
        guard let attack = run?.attack else { return }
        paused = true
        Task { await attack.pause() }
    }

    func resume() {
        guard let attack = run?.attack else { return }
        paused = false
        Task { await attack.resume() }
    }

    func cancel() {
        guard let attack = run?.attack else { return }
        Task { await attack.cancel() }
    }

    /// FUZ-023: the anomalies of a row against the baseline row.
    func anomalies(_ result: FuzzResult) -> Set<Anomaly> {
        guard let baselineSeq, let base = results.first(where: { $0.seq == baselineSeq }) else { return [] }
        return Baseline(status: base.status, length: base.length, timeMs: base.timeMs)
            .anomalies(
                status: result.status, length: result.length, timeMs: result.timeMs,
                error: result.error != nil)
    }

    /// Lengths and how many rows have each (FUZ-023's histogram).
    var histogram: [(length: Int, count: Int)] {
        Array(lengthHistogram(results.map(\.length)).prefix(8))
    }

    /// Show a row's exchange.
    func select(_ seq: Int?) {
        selectedSeq = seq
        guard let seq, let id = results.first(where: { $0.seq == seq })?.exchangeID, id > 0 else {
            shown = nil
            return
        }
        let session = self.session
        Task { shown = try? await session.store.exchange(id: id) }
    }

    func reloadSaved() async {
        savedAttacks = ((try? await session.savedAttacks()) ?? []).map {
            SavedAttackSummary(
                id: $0.row.id, name: $0.row.name, state: $0.row.state, count: $0.row.resultCount)
        }
    }

    /// FUZ-026: reopen a saved attack's results and configuration.
    func open(saved id: Int64) {
        let session = self.session
        Task {
            if let config = try? await session.savedAttacks().first(where: { $0.row.id == id })?.config {
                request = config.request
                targetText = "\(config.target.scheme.rawValue)://\(config.target.host):\(config.target.port)"
                attackType = config.attackType
                settings = config.settings
            }
            results = (try? await session.attackResults(id)) ?? []
            summary = nil
        }
    }

    /// FUZ-026: export a saved attack as CSV.
    func export(saved id: Int64) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "attack-\(id).csv"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let session = self.session
        Task { try? await session.exportAttackCSV(id)?.write(to: url, atomically: true, encoding: .utf8) }
    }

    /// ETL-003: run content discovery from `discoverURL` with the bundled list.
    func discover() {
        guard !discovering, let words = BundledWordlists.url("content.txt")?.path else { return }
        discovered = []
        discovering = true
        let session = self.session
        let config = DiscoveryConfig(baseURL: discoverURL, words: .file(path: words))
        let allow = allowOutOfScope
        Task {
            do {
                let (discovery, events) = try await session.discoverContent(config, allowOutOfScope: allow)
                self.discovery = discovery
                for await event in events {
                    if case .found(let path) = event { discovered.append(path) }
                }
            } catch {
                message = "\(error)"
            }
            discovering = false
        }
    }

    /// "Send to Fuzzer" (F07): take the inbox's request now and whenever another arrives. Runs for
    /// as long as the view is shown (the caller's `.task` cancels it).
    func followInbox() async {
        let inbox = session.inbox
        if let input = await inbox.fuzzerInput { take(input) }
        for await tool in await inbox.opened() where tool == .fuzzer {
            if let input = await inbox.fuzzerInput { take(input) }
        }
    }

    @ObservationIgnored private var takenInput: UUID?

    private func take(_ input: FuzzerInput) {
        guard input.id != takenInput else { return }
        takenInput = input.id
        request = input.request
        let target = input.target
        targetText = "\(target.scheme.rawValue)://\(target.host):\(target.port)"
        discoverURL = targetText + "/"
        // Mark every parameter value; the user prunes what they don't want (FUZ-001).
        autoMark()
        results = []
        summary = nil
    }

    func stopDiscovery() {
        guard let discovery else { return }
        Task { await discovery.cancel() }
    }
}

/// Fuzzer and Discover content.
public struct FuzzerView: View {
    private let model: FuzzerModel

    /// The Fuzzer of the project whose tool models are `models`.
    public init(models: ToolModels) {
        model = models.fuzzer
    }

    /// The screen.
    public var body: some View {
        FuzzerPanel(model: model)
            .task { await model.followInbox() }
    }
}

struct FuzzerPanel: View {
    enum Tab: String, CaseIterable {
        case positions = "Positions", payloads = "Payloads", settings = "Settings", results = "Results"
        case discover = "Discover content"
    }

    @Bindable var model: FuzzerModel
    @State private var tab = Tab.positions

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $tab) {
                    ForEach(Tab.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 560)
                Spacer()
                Text(model.plannedCount).font(.caption).foregroundStyle(.secondary)
                if model.running {
                    Button(model.paused ? "Resume" : "Pause") {
                        model.paused ? model.resume() : model.pause()
                    }
                    Button("Stop") { model.cancel() }
                } else {
                    Button("Start Attack") {
                        model.start()
                        tab = .results
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
            .padding(6)
            if let message = model.message { Text(message).foregroundStyle(.red).font(.caption) }
            Divider()
            switch tab {
            case .positions: positions
            case .payloads: payloads
            case .settings: settingsPane
            case .results: resultsPane
            case .discover: discoverPane
            }
        }
        .navigationTitle("Fuzzer")
    }

    private var positions: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField("https://host:port", text: $model.targetText).textFieldStyle(.roundedBorder).frame(
                    maxWidth: 320)
                Picker("Attack", selection: $model.attackType) {
                    Text("Sniper").tag(AttackType.sniper)
                    Text("Battering ram").tag(AttackType.batteringRam)
                    Text("Pitchfork").tag(AttackType.pitchfork)
                    Text("Cluster bomb").tag(AttackType.clusterBomb)
                }
                .frame(maxWidth: 240)
                .onChange(of: model.attackType) { model.syncSets() }
                Picker("HTTP", selection: $model.settings.httpVersion) {
                    Text("Auto").tag(FuzzHTTPVersion.auto)
                    Text("HTTP/1.1").tag(FuzzHTTPVersion.http1_1)
                    Text("HTTP/2").tag(FuzzHTTPVersion.http2)
                    Text("h2c").tag(FuzzHTTPVersion.http2PriorKnowledge)
                }
                .frame(maxWidth: 160)
                Button("Auto §") { model.autoMark() }
                Button("Clear §") { model.clearMarks() }
                Text("\(model.positionCount) positions").font(.caption)
                if RPC.detect(RawRequest(Bytes(model.request))) != nil {
                    TextField("Protobuf fields, e.g. message, 3.1", text: $model.rpcFieldsText)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 220)
                        .help(
                            "Fuzz inside protobuf fields instead of § markers; each payload is re-encoded (F33)"
                        )
                }
            }
            MessageEditor(
                title: "Base request (wrap payload positions in §…§)", bytes: $model.request, editable: true)
        }
        .padding(6)
    }

    private var payloads: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                ForEach($model.sets) { $draft in
                    let index = model.sets.firstIndex(where: { $0.id == draft.id }) ?? 0
                    GroupBox("Payload set \(index + 1)") {
                        VStack(alignment: .leading) {
                            Picker("Type", selection: $draft.kind) {
                                ForEach(PayloadSetDraft.Kind.allCases) { Text($0.rawValue).tag($0) }
                            }
                            .frame(maxWidth: 260)
                            switch draft.kind {
                            case .list: TextEditor(text: $draft.listText).frame(minHeight: 80)
                            case .file:
                                HStack {
                                    TextField("Wordlist path", text: $draft.filePath).textFieldStyle(
                                        .roundedBorder)
                                    Menu("Bundled") {
                                        ForEach(BundledWordlists.labels.map { $0.file }, id: \.self) { file in
                                            Button(
                                                BundledWordlists.labels.first { $0.file == file }?.label
                                                    ?? file
                                            ) {
                                                draft.filePath = BundledWordlists.url(file)?.path ?? ""
                                            }
                                        }
                                    }
                                }
                                .task(id: draft.filePath) { await model.loadWordlist(draft.filePath) }
                            case .numbers:
                                HStack {
                                    Stepper("From \(draft.from)", value: $draft.from)
                                    Stepper("To \(draft.to)", value: $draft.to)
                                    Stepper("Step \(draft.step)", value: $draft.step, in: 1...100_000)
                                }
                            case .brute:
                                HStack {
                                    TextField("Charset", text: $draft.charset).textFieldStyle(.roundedBorder)
                                    Stepper("Min \(draft.minLength)", value: $draft.minLength, in: 0...12)
                                    Stepper("Max \(draft.maxLength)", value: $draft.maxLength, in: 0...12)
                                }
                            case .null:
                                Stepper(
                                    "Count \(draft.nullCount)", value: $draft.nullCount, in: 1...1_000_000)
                            case .base: Text("The position's own base value.").foregroundStyle(.secondary)
                            }
                            Text(
                                "Processing (one per line): prefix=…, suffix=…, skip=REGEX, upper, lower, reverse, tags=…, or a Decoder operation"
                            )
                            .font(.caption)
                            TextEditor(text: $draft.processorText).font(
                                .system(.caption, design: .monospaced)
                            ).frame(minHeight: 50)
                            Text("Preview: " + model.preview(draft).joined(separator: " · ")).font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .padding()
        }
    }

    private var settingsPane: some View {
        Form {
            Stepper(
                "Concurrency: \(model.settings.concurrency)", value: $model.settings.concurrency, in: 1...256)
            TextField(
                "Requests per second (empty: no cap)",
                value: Binding(
                    get: { model.settings.requestsPerSecond }, set: { model.settings.requestsPerSecond = $0 }),
                format: .number)
            Stepper(
                "Delay: \(model.settings.delayMs) ms", value: $model.settings.delayMs, in: 0...60_000,
                step: 50)
            Stepper(
                "Random extra delay: \(model.settings.delayJitterMs) ms",
                value: $model.settings.delayJitterMs, in: 0...60_000, step: 50)
            Stepper("Retries: \(model.settings.retries)", value: $model.settings.retries, in: 0...10)
            Toggle("Stop at the first grep match", isOn: $model.settings.stopOnGrepMatch)
            Toggle("Update Content-Length", isOn: $model.settings.updateContentLength)
            Toggle("Follow on-site redirects", isOn: $model.settings.followRedirects)
            Toggle("Evaluate Transform Tags in the base request", isOn: $model.settings.transformTags)
            Toggle("Send out-of-scope requests (override ScopeGuard)", isOn: $model.allowOutOfScope)
            Section("Grep — match (one per line; re: for a regex)") {
                TextEditor(text: $model.matchText).frame(minHeight: 60)
                HStack {
                    Button("Add SQL errors") {
                        model.matchText +=
                            (model.matchText.isEmpty ? "" : "\n") + "re:" + GrepMatch.sqlErrors.pattern
                    }
                    Button("Add stack traces") {
                        model.matchText +=
                            (model.matchText.isEmpty ? "" : "\n") + "re:" + GrepMatch.stackTraces.pattern
                    }
                }
            }
            Section("Grep — extract (START|END, or regex:PATTERN with one group)") {
                TextEditor(text: $model.extractText).frame(minHeight: 60)
            }
        }
        .padding()
    }

    private var resultsPane: some View {
        VSplit {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    if let summary = model.summary {
                        Text(
                            String(
                                format: "Sent %d · errors %d · refused %d · %.0f req/s%@", summary.sent,
                                summary.errors,
                                summary.refused, summary.rate,
                                summary.stopReason.map { " · stopped: \($0)" } ?? ""))
                    } else {
                        Text("\(model.results.count) rows")
                    }
                    Spacer()
                    Text(
                        "Lengths: "
                            + model.histogram.map { "\($0.length)×\($0.count)" }.joined(separator: " ")
                    ).font(.caption)
                }
                Table(
                    model.results, selection: Binding(get: { model.selectedSeq }, set: { model.select($0) })
                ) {
                    TableColumn("#") { Text("\($0.seq)").monospacedDigit() }.width(50)
                    TableColumn("Payloads") {
                        Text($0.payloads.map { $0 ?? "–" }.joined(separator: " | ")).lineLimit(1)
                    }
                    TableColumn("Status") { Text($0.status.map(String.init) ?? "–") }.width(50)
                    TableColumn("Length") { Text("\($0.length)").monospacedDigit() }.width(60)
                    TableColumn("ms") { Text(String(format: "%.0f", $0.timeMs)).monospacedDigit() }.width(50)
                    TableColumn("Grep") { row in
                        Text(
                            row.findings.matches.map { $0 ? "✓" : "·" }.joined() + " "
                                + row.findings.extracts.map { $0 ?? "" }.joined(separator: " ")
                        )
                        .lineLimit(1)
                    }
                    TableColumn("Reflected") {
                        Text($0.findings.reflection == .none ? "" : $0.findings.reflection.rawValue)
                    }.width(70)
                    TableColumn("Anomaly") {
                        Text(model.anomalies($0).map(\.rawValue).sorted().joined(separator: ", "))
                    }.width(110)
                    TableColumn("Error") { Text($0.error ?? "") }.width(110)
                }
                .contextMenu(forSelectionType: Int.self) { seqs in
                    Button("Use as Baseline") { model.baselineSeq = seqs.first }
                }
                HStack {
                    Menu("Saved Attacks") {
                        ForEach(model.savedAttacks) { attack in
                            Menu("\(attack.name) (\(attack.state), \(attack.count) rows)") {
                                Button("Open") { model.open(saved: attack.id) }
                                Button("Export CSV…") { model.export(saved: attack.id) }
                            }
                        }
                    }
                    .frame(maxWidth: 200)
                }
            }
            .padding(6)
            .frame(minHeight: 200)
            HSplit {
                MessageViewer(title: "Request", bytes: model.shown?.request.bytes)
                ResponsePane(exchange: model.shown)
            }
            .frame(minHeight: 160)
        }
    }

    private var discoverPane: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField("https://host/path/", text: $model.discoverURL).textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 360)
                if model.discovering {
                    ProgressView().controlSize(.small)
                    Button("Stop") { model.stopDiscovery() }
                } else {
                    Button("Discover Content") { model.discover() }
                }
                Text("Uses the bundled directories/files list; scope-gated; found paths go to the site map.")
                    .font(.caption)
            }
            List(discoveryTree(model.discovered), id: \.self) { line in
                Text(line).font(.system(.body, design: .monospaced))
            }
        }
        .padding(6)
    }
}
#endif
