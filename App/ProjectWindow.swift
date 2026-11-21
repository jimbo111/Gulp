import AppKit
import GulpFeatures
import GulpUI
import GulpWorkspace
import SwiftUI
import UniformTypeIdentifiers

/// One project window: opens its ProjectSession, starts the proxy listeners, shows the tools.
struct ProjectWindow: View {
    let ref: ProjectRef
    @State private var session: ProjectSession?
    /// One model per tool for this session, created with it (doc 05 §8).
    @State private var models: ToolModels?
    @State private var projectName = ""
    @State private var generation = 0
    @State private var failure: String?
    @State private var selection: Tool? = .proxy
    @State private var showListeners = false
    /// Global search (⌘⇧F, HIS-050).
    @State private var showSearch = false
    /// The panic stop is engaged (F20 GOV-001).
    @State private var panicked = false
    /// Project → gRPC Schemas… (F33); the revision reloads the schemas RPC views use.
    @State private var showGRPCSchemas = false
    @State private var grpcRevision = 0
    /// Listener bind failures from opening the project (PRX-001), shown above the tools.
    @State private var bindErrors: [String] = []
    /// Gulp Browser (BRW-001…004): offer Chrome for Testing when nothing is installed.
    @State private var offerDownload = false
    @State private var browserStatus: String?
    /// The ports the proxy listens on (the toolbar's listener status, docs/05 §2).
    @State private var listenerPorts: [Int] = []
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            if let session, let models {
                NavigationSplitView {
                    List(selection: $selection) {
                        ForEach(ToolSection.allCases) { section in
                            Section(section.title) {
                                ForEach(section.tools) { tool in
                                    Label(tool.title, systemImage: tool.symbol).tag(tool)
                                        .accessibilityIdentifier("sidebar.\(tool.rawValue)")
                                }
                            }
                        }
                    }
                    .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 300)
                    .listStyle(.sidebar)
                } detail: {
                    detail(session: session, models: models)
                        // Every tool is titled by its sidebar name; a view may refine it
                        // ("HTTP History", "Intercept") with its own navigationTitle.
                        .navigationTitle(selection?.title ?? "Gulp")
                        .accessibilityElement(children: .contain)
                        .accessibilityIdentifier("tool.\(selection?.rawValue ?? "none")")
                        .safeAreaInset(edge: .top) { bindErrorBanner }
                        .grpcSchemas(from: session, revision: grpcRevision)
                }
                .sheet(isPresented: $showListeners) {
                    Task { listenerPorts = await session.listenerPorts }
                } content: {
                    ProxyListenersView(session: session)
                }
                .sheet(isPresented: $showSearch) {
                    SearchView(session: session)
                        .grpcSchemas(from: session, revision: grpcRevision)
                }
                .sheet(isPresented: $showGRPCSchemas) {
                    GRPCSchemasView(session: session) { grpcRevision += 1 }
                }
                .toolbar {
                    // docs/05 §2: the global Intercept toggle (⌘⇧I) and the listener status.
                    ToolbarItem(placement: .primaryAction) {
                        InterceptToolbarToggle(models: models)
                    }
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            showListeners = true
                        } label: {
                            Label(
                                listenerStatus,
                                systemImage: listenerPorts.isEmpty ? "network.slash" : "network"
                            )
                            .labelStyle(.titleAndIcon)
                        }
                        .accessibilityIdentifier("listeners")
                        .help("Proxy listeners for this project (PRX-001)")
                    }
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            showSearch = true
                        } label: {
                            Label("Search", systemImage: "magnifyingglass")
                        }
                        .keyboardShortcut("f", modifiers: [.command, .shift])
                        .help("Search every request and response in the project (⌘⇧F)")
                    }
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            let engage = !panicked
                            panicked = engage
                            Task {
                                if engage {
                                    await session.panicStop()
                                } else {
                                    await session.resumeAll()
                                }
                            }
                        } label: {
                            Label(
                                panicked ? "Resume All" : "Panic Stop",
                                systemImage: panicked ? "play.fill" : "xmark.octagon.fill")
                        }
                        .keyboardShortcut(".", modifiers: [.control])
                        .help(
                            panicked
                                ? "Resume every paused task"
                                : "Pause every active task (Scanner, Crawler, Fuzzer…) and cut their requests in flight (⌃.)"
                        )
                    }
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            showGRPCSchemas = true
                        } label: {
                            Label("gRPC Schemas", systemImage: "curlybraces.square")
                        }
                        .help(
                            "Import .proto files or descriptor sets, or fetch a schema via reflection (F33)")
                    }
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            openBrowser(session)
                        } label: {
                            Label("Open Browser", systemImage: "globe")
                        }
                        .keyboardShortcut("o", modifiers: [.command, .shift])
                        .help("Open a browser proxied through Gulp, with the Gulp CA trusted (⌘⇧O)")
                    }
                }
                .alert("No Chromium-based browser found", isPresented: $offerDownload) {
                    Button("Download Chrome for Testing") { downloadBrowser(session) }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text(
                        "Gulp launches Chrome, Chromium, Edge or Brave with its own profile. It can "
                            + "download Google's Chrome for Testing into Gulp's support folder.")
                }
            } else if let failure {
                ContentUnavailableView(
                    "Could not open the project", systemImage: "exclamationmark.triangle",
                    description: Text(failure))
            } else {
                ProgressView("Opening project…")
            }
        }
        .task { await open() }
        .task(id: session.map { ObjectIdentifier($0) }) {
            // "Send to Repeater" (⌘R in History) brings the Repeater forward (F06 REP-001).
            guard let session else { return }
            for await _ in await session.repeaterTabsOpened() { selection = .repeater }
        }
        .task(id: session.map { ObjectIdentifier($0) }) {
            // "Send to Comparer / Decoder / Fuzzer", "Actively scan" bring that tool forward (CMP-001, DEC-004, F07, SCN-035).
            guard let session else { return }
            for await tool in await session.inbox.opened() {
                switch tool {
                case .comparer: selection = .comparer
                case .decoder: selection = .decoder
                case .fuzzer: selection = .fuzzer
                case .scanner: selection = .scanner
                }
            }
        }
        .onChange(of: OpenProjects.shared.pendingFiles, initial: true) {
            // `.gulp` files from Finder / Open With / the Dock: one window opens each (PRJ-002).
            for url in OpenProjects.shared.takePendingFiles() {
                openWindow(value: ProjectRef(path: url.path))
            }
        }
        .onDisappear {
            guard let session else { return }
            Task { await OpenProjects.shared.close(session) }
        }
        .focusedSceneValue(\.projectActions, actions)
        .navigationSubtitle(projectName)
        .writingToolsDisabled()
    }

    @ViewBuilder
    private func detail(session: ProjectSession, models: ToolModels) -> some View {
        switch selection {
        case .proxy:
            ProxyToolView(models: models, generation: generation)
        case .target:
            TargetView(models: models)
        case .repeater:
            RepeaterView(models: models)
        case .fuzzer:
            FuzzerView(models: models)
        case .scanner:
            ScannerView(models: models)
        case .beacon:
            BeaconView(models: models)
        case .dashboard:
            IssuesDashboard(session: session)
        case .logger:
            LoggerView(session: session, generation: generation)
        case .notebook:
            NotebookView(session: session)
        case .decoder:
            DecoderView(models: models)
        case .comparer:
            ComparerView(models: models)
        case .jwt:
            JWTWorkbenchView()
        case .sequencer:
            SequencerView()
        case .jsRecon:
            JSReconView()
        case .domProbe:
            DOMProbeView()
        case .graphql:
            GraphQLWorkbenchView()
        case .extensions:
            ExtensionsView()
        case .assistant:
            AssistantView()
        case .authzMatrix:
            AuthzMatrixView(models: models)
        case nil:
            ContentUnavailableView(
                "No tool selected", systemImage: "sidebar.left",
                description: Text("Choose a tool in the sidebar."))
        }
    }

    /// The toolbar's listener status: where the proxy listens, or that it does not.
    private var listenerStatus: String {
        listenerPorts.isEmpty
            ? "Proxy off" : "Proxy :" + listenerPorts.map(String.init).joined(separator: ", :")
    }

    private func openBrowser(_ session: ProjectSession) {
        Task {
            do {
                try await session.openBrowser()
                browserStatus = nil
            } catch is NoBrowserFound {
                offerDownload = true
            } catch {
                browserStatus = ProjectSession.describe(error)
            }
        }
    }

    private func downloadBrowser(_ session: ProjectSession) {
        browserStatus = "Downloading Chrome for Testing…"
        Task {
            do {
                _ = try await session.environment.downloadChromeForTesting()
                browserStatus = nil
                openBrowser(session)
            } catch {
                browserStatus = "Download failed: \(ProjectSession.describe(error))"
            }
        }
    }

    @ViewBuilder private var bindErrorBanner: some View {
        if let browserStatus {
            HStack {
                Image(systemName: "globe")
                Text(browserStatus)
                Spacer()
                Button("Dismiss") { self.browserStatus = nil }
            }
            .padding(8)
            .background(.bar)
        }
        if !bindErrors.isEmpty {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
                Text(bindErrors.joined(separator: "\n"))
                Spacer()
                Button("Listeners…") { showListeners = true }
                Button("Dismiss") { bindErrors = [] }
            }
            .padding(8)
            .background(.bar)
        }
    }

    private var actions: ProjectActions? {
        guard let session else { return nil }
        return ProjectActions(
            saveAs: { url in
                Task {
                    try? await session.saveAs(url)
                    projectName = await session.url.lastPathComponent
                    generation += 1  // the History view reloads from the new file
                }
            },
            importFile: { url in
                // PRJ-008 / PRJ-012: a .gulp merges; anything else is detected by content. Never sends.
                Task {
                    do {
                        let report: ImportReport
                        if url.pathExtension == "gulp" {
                            report = try await session.importExport.importProject(at: url)
                        } else {
                            // Read off the main thread: traffic files can be large (AGENTS.md §4).
                            let data = try await Task.detached { try Data(contentsOf: url) }.value
                            report = try await session.importExport.importFile(data)
                        }
                        let skipped = report.skipped.prefix(3).map { "\($0.item): \($0.reason)" }
                        browserStatus = ([report.summary] + skipped).joined(separator: " · ")
                    } catch {
                        browserStatus = "Import failed: \(ProjectSession.describe(error))"
                    }
                }
            },
            export: { format, url in
                // HIS-044: the whole history, as HAR (with Gulp's exact bytes) or CSV.
                Task {
                    do {
                        let data = try await session.importExport.export(as: format)
                        try await Task.detached { try data.write(to: url) }.value
                        browserStatus = "Exported history to \(url.lastPathComponent)"
                    } catch {
                        browserStatus = "Export failed: \(ProjectSession.describe(error))"
                    }
                }
            })
    }

    private func open() async {
        guard session == nil else { return }
        do {
            let opened: ProjectSession
            if let path = ref.path {
                opened = try await ProjectSession.open(at: URL(fileURLWithPath: path))
            } else {
                opened = try await ProjectSession.openTemporary()
            }
            let results = await opened.startProxyListeners()
            bindErrors = results.values.compactMap { result in
                if case .failure(let error) = result { return error.message }
                return nil
            }
            listenerPorts = await opened.listenerPorts
            projectName = await opened.url.lastPathComponent
            let created = ToolModels(session: opened)
            OpenProjects.shared.add(opened, models: created)
            models = created
            session = opened
        } catch {
            failure = "\(error)"
        }
    }
}

/// Window-scoped actions reachable from the menu bar.
struct ProjectActions {
    /// Save the window's project to a file and keep working there.
    let saveAs: @MainActor (URL) -> Void
    /// Import a traffic file or merge a project (PRJ-012).
    let importFile: @MainActor (URL) -> Void
    /// Export the history (HIS-044).
    let export: @MainActor (ExportFormat, URL) -> Void
}

struct ProjectActionsKey: FocusedValueKey {
    typealias Value = ProjectActions
}

extension FocusedValues {
    var projectActions: ProjectActions? {
        get { self[ProjectActionsKey.self] }
        set { self[ProjectActionsKey.self] = newValue }
    }
}

/// File menu: New Temporary Project, New Project…, Open…, Open Recent, Save As… (PRJ-001/002).
struct ProjectCommands: Commands {
    @Environment(\.openWindow) private var openWindow
    @FocusedValue(\.projectActions) private var actions

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Temporary Project") { openWindow(value: ProjectRef()) }
                .keyboardShortcut("n")
            Button("New Project…") {
                if let url = ProjectPanels.save(title: "New Project") {
                    openWindow(value: ProjectRef(path: url.path))
                }
            }
            // No shortcut: ⌘⇧N is Add to Notebook (docs/05 §5).
            Button("Open…") {
                if let url = ProjectPanels.open() { openWindow(value: ProjectRef(path: url.path)) }
            }
            .keyboardShortcut("o")
            Menu("Open Recent") {
                ForEach(RecentProjects.list(in: .standard), id: \.self) { url in
                    Button(url.lastPathComponent) { openWindow(value: ProjectRef(path: url.path)) }
                }
            }
        }
        CommandGroup(replacing: .saveItem) {
            Button("Save As…") {
                if let actions, let url = ProjectPanels.save(title: "Save Project As") { actions.saveAs(url) }
            }
            .keyboardShortcut("s", modifiers: [.command, .shift])
            .disabled(actions == nil)
        }
        CommandGroup(after: .importExport) {
            Button("Import…") {
                // HAR, Postman, OpenAPI/Swagger, XML proxy-history export, Caido, sitemap.xml, URL list, .gulp
                let panel = NSOpenPanel()
                panel.title = "Import Traffic or Merge a Project"
                panel.allowsMultipleSelection = false
                if let actions, panel.runModal() == .OK, let url = panel.url { actions.importFile(url) }
            }
            // No shortcut: ⌘⇧I toggles Intercept (docs/05 §5).
            .disabled(actions == nil)
            Menu("Export History") {
                ForEach(ExportFormat.allCases, id: \.self) { format in
                    Button(format == .har ? "HAR…" : "CSV…") {
                        let panel = NSSavePanel()
                        panel.nameFieldStringValue = "history.\(format.rawValue)"
                        if let actions, panel.runModal() == .OK, let url = panel.url {
                            actions.export(format, url)
                        }
                    }
                }
            }
            .disabled(actions == nil)
        }
    }
}

/// Open/save panels for `.gulp` files.
@MainActor
enum ProjectPanels {
    static let type = UTType(filenameExtension: "gulp") ?? .data

    static func save(title: String) -> URL? {
        let panel = NSSavePanel()
        panel.title = title
        panel.allowedContentTypes = [type]
        panel.nameFieldStringValue = "Untitled.gulp"
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func open() -> URL? {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [type]
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK ? panel.url : nil
    }
}
