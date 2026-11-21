// GulpFeatures — the static crawler (F09 §3) and the Beacon tool (F10 §3). The crawl config sheet
// (seeds, scope reminder, form policy with the "submit forms" confirmation, limits) starts a crawl;
// progress (pages, queue, in flight) and a log update at most every 100 ms. The Beacon tool
// configures OAST (off by default; public servers need an explicit acknowledgement), tests the
// loop, shows health and the interactions with their originating exchange.

#if canImport(AppKit)
import AppKit
import GulpCore
import GulpCrawler
import GulpStore
import GulpUI
import GulpWorkspace
import Observation
import SwiftUI

/// State behind the crawler screen.
@MainActor
@Observable
final class CrawlerModel {
    var seedsText = "https://"
    var maxDepth = 10
    var maxPages = 1_000
    var concurrency = 8
    var forms = FormPolicy.get
    var obeyRobots = false
    private(set) var running = false
    private(set) var paused = false
    private(set) var fetched = 0
    private(set) var queued = 0
    private(set) var log: [String] = []
    private(set) var report: CrawlReport?
    @ObservationIgnored let session: ProjectSession
    @ObservationIgnored private var crawler: Crawler?
    @ObservationIgnored private var pendingLog: [String] = []

    init(session: ProjectSession) { self.session = session }

    var seeds: [String] {
        seedsText.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter {
            !$0.isEmpty
        }
    }

    func start() {
        let config = CrawlConfig(
            seeds: seeds, maxDepth: maxDepth, maxPages: maxPages, concurrency: concurrency, forms: forms,
            obeyRobots: obeyRobots)
        running = true
        paused = false
        report = nil
        log = []
        fetched = 0
        Task {
            let run = await session.startCrawl(config)
            crawler = run.crawler
            let ticker = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for: .milliseconds(100))  // coalesced UI updates
                    await self?.refresh()
                }
            }
            for await event in run.events {
                switch event {
                case .page(let page):
                    pendingLog.append("\(page.status.map(String.init) ?? "-") \(page.method) \(page.url)")
                case .skipped(let url, let reason): pendingLog.append("skipped (\(reason)) \(url)")
                case .auth(let message): pendingLog.append("auth: \(message)")
                case .form(let form): pendingLog.append("form: \(form.method) \(form.action)")
                case .finished(let done): report = done
                }
            }
            ticker.cancel()
            await refresh()
            running = false
            crawler = nil
        }
    }

    func refresh() async {
        if !pendingLog.isEmpty {
            log.append(contentsOf: pendingLog)
            if log.count > 2_000 { log.removeFirst(log.count - 2_000) }
            pendingLog = []
        }
        if let crawler {
            let progress = await crawler.progress
            fetched = progress.fetched
            queued = progress.queued
        }
    }

    func togglePause() {
        guard let crawler else { return }
        paused.toggle()
        let pause = paused
        Task {
            if pause {
                await crawler.pause()
            } else {
                await crawler.resume()
            }
        }
    }

    func stop() {
        guard let crawler else { return }
        Task { await crawler.cancel() }
    }
}

/// Scanner → Crawl (static mode, F09).
struct CrawlerView: View {
    @Bindable var model: CrawlerModel
    @State private var confirmForms = false

    var body: some View {
        HSplit {
            Form {
                Section("Seeds (one URL per line)") {
                    TextEditor(text: $model.seedsText).font(.system(.body, design: .monospaced)).frame(
                        minHeight: 60)
                    Text("Only in-scope URLs are fetched (Target → Scope).").font(.caption).foregroundStyle(
                        .secondary)
                }
                Section("Limits") {
                    Stepper("Max depth: \(model.maxDepth)", value: $model.maxDepth, in: 1...50)
                    Stepper(
                        "Max pages: \(model.maxPages)", value: $model.maxPages, in: 10...100_000, step: 100)
                    Stepper("Parallel requests: \(model.concurrency)", value: $model.concurrency, in: 1...64)
                }
                Section("Forms") {
                    Picker("Submit", selection: formsBinding) {
                        Text("None").tag(FormPolicy.none)
                        Text("GET forms").tag(FormPolicy.get)
                        Text("GET and POST forms").tag(FormPolicy.all)
                    }
                    Toggle("Obey robots.txt Disallow", isOn: $model.obeyRobots)
                        .help(
                            "Off by default for authorized testing; robots.txt and sitemap.xml are still read as hints"
                        )
                }
                HStack {
                    Button(model.running ? "Running…" : "Start Crawl") { model.start() }
                        .disabled(model.running || model.seeds.isEmpty)
                        .keyboardShortcut(.defaultAction)
                    if model.running {
                        Button(model.paused ? "Resume" : "Pause") { model.togglePause() }
                        Button("Stop", role: .destructive) { model.stop() }
                    }
                }
            }
            .formStyle(.grouped)
            .frame(minWidth: 300, maxWidth: 380)
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("\(model.fetched) fetched").monospacedDigit()
                    Text("\(model.queued) queued").monospacedDigit().foregroundStyle(.secondary)
                }
                if let report = model.report {
                    Text(
                        "\(report.pages.count) pages · \(report.forms.count) forms (\(report.formsSubmitted) submitted) · "
                            + "\(report.parameters.count) parameters · \(report.errors.count) errors · "
                            + "\(report.outOfScope.count) out of scope · \(report.excluded.count) excluded — \(report.stopReason)"
                    )
                    .font(.caption)
                }
                List(Array(model.log.enumerated()), id: \.offset) { entry in
                    Text(entry.element).font(.system(.caption, design: .monospaced)).lineLimit(1)
                }
            }
            .padding(8)
            .frame(minWidth: 360)
        }
        .navigationTitle("Crawl")
        .alert("Submit POST forms?", isPresented: $confirmForms) {
            Button("Submit POST Forms") { model.forms = .all }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "POST forms can change data on the target. Forms that look destructive (logout, delete…) are never submitted."
            )
        }
    }

    private var formsBinding: Binding<FormPolicy> {
        Binding(
            get: { model.forms },
            set: { value in
                if value == .all { confirmForms = true } else { model.forms = value }
            })
    }
}

/// State behind the Beacon tool.
@MainActor
@Observable
final class BeaconModel {
    var settings: OASTSettings
    var token = ""
    /// Nil until the first poll.
    private(set) var health: OASTHealth?
    private(set) var interactions: [StoredOASTInteraction] = []
    private(set) var message: String?
    private(set) var testing = false
    var selected: Int64?
    var raw = ""
    @ObservationIgnored let session: ProjectSession

    init(session: ProjectSession) {
        self.session = session
        settings = session.settings.get(OASTSettings.self)
    }

    /// Refresh health and interactions every second until cancelled (the view's `.task`: Beacon is
    /// polled only while it is shown).
    func poll() async {
        while !Task.isCancelled {
            await reload()
            try? await Task.sleep(for: .seconds(1))
        }
    }

    /// OAST is configured and registered.
    var registered: Bool { health?.registered == true }

    func reload() async {
        health = await session.oast.currentHealth
        let store = await session.store
        interactions = (try? await store.oastInteractions()) ?? []
    }

    func apply(enabled: Bool) {
        var value = settings
        value.enabled = enabled
        let token = self.token
        let session = self.session
        Task {
            do {
                try await session.configureOAST(value, token: token.isEmpty ? nil : token)
                settings = value
                message = enabled ? "Registered." : "OAST is off."
            } catch {
                message = "\(error)"
            }
            await reload()
        }
    }

    func test() {
        testing = true
        let session = self.session
        Task {
            do {
                let result = try await session.oast.test()
                message =
                    result.ok
                    ? String(
                        format: "Test Beacon: ok in %.2f s (%@)", result.seconds,
                        result.protocols.joined(separator: ", "))
                    : "Test Beacon failed: \(result.problem ?? "no interaction")"
            } catch {
                message = "\(error)"
            }
            testing = false
            await reload()
        }
    }

    func select(_ id: Int64?) {
        selected = id
        guard let id else { return }
        let session = self.session
        Task {
            let store = await session.store
            let bytes: [UInt8]? = (try? await store.oastInteractionRaw(id)) ?? nil
            raw = bytes.map { String(decoding: $0, as: UTF8.self) } ?? ""
        }
    }
}

/// The Beacon tool (F10 §3).
public struct BeaconView: View {
    @Bindable private var model: BeaconModel

    /// Beacon of the project whose tool models are `models`.
    public init(models: ToolModels) {
        model = models.beacon
    }

    /// The screen.
    public var body: some View {
        VSplit {
            Form {
                Section("Server (OAST is off until configured)") {
                    TextField(
                        "Server URL (dev Beacon: http://127.0.0.1:8090, or an interactsh server)",
                        text: $model.settings.serverURL)
                    TextField("Payload domain (blank: the server's host)", text: $model.settings.domain)
                    SecureField("Token (kept in the Keychain)", text: $model.token)
                    if !model.settings.isLocal && !model.settings.serverURL.isEmpty {
                        Toggle(
                            "I understand this third-party server sees every interaction",
                            isOn: $model.settings.thirdPartyAcknowledged)
                    }
                    HStack {
                        Button("Save and Register") { model.apply(enabled: true) }
                            .disabled(
                                model.settings.serverURL.isEmpty
                                    || (!model.settings.isLocal && !model.settings.thirdPartyAcknowledged))
                        Button("Turn Off") { model.apply(enabled: false) }
                        Button(model.testing ? "Testing…" : "Test Beacon") { model.test() }.disabled(
                            !model.registered || model.testing)
                    }
                    HStack {
                        Circle().fill(model.registered ? Color.green : Color.secondary).frame(
                            width: 8, height: 8)
                        if let health = model.health, health.registered {
                            Text(
                                "\(health.domain) · \(health.payloads) payloads · \(health.interactions) interactions"
                                    + (health.lastError.map { " · \($0)" } ?? "")
                            )
                            .font(.caption)
                        } else {
                            Text("Not registered").font(.caption)
                        }
                    }
                    if let message = model.message {
                        Text(message).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)
            .frame(minHeight: 200)
            HSplit {
                Table(
                    model.interactions, selection: Binding(get: { model.selected }, set: { model.select($0) })
                ) {
                    TableColumn("When") { Text($0.at, style: .time) }.width(70)
                    TableColumn("Protocol") { Text($0.proto) }.width(60)
                    TableColumn("From") { Text($0.remoteAddress) }.width(110)
                    TableColumn("Origin") { item in
                        Text(
                            item.payload.map {
                                "\($0.context.tool) #\($0.exchangeID.map(String.init) ?? "-")"
                            } ?? "unknown payload")
                    }
                    TableColumn("Summary") { Text($0.summary).lineLimit(1) }
                }
                ScrollView {
                    Text(model.raw).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .topLeading).padding(6)
                }
                .frame(minWidth: 240)
            }
        }
        .navigationTitle("Beacon")
        .task { await model.poll() }
    }
}
#endif
