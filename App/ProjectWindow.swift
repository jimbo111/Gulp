import AppKit
import GulpFeatures
import GulpWorkspace
import SwiftUI
import UniformTypeIdentifiers

/// One project window: opens its ProjectSession, starts the proxy listeners, shows the tools.
struct ProjectWindow: View {
    let ref: ProjectRef
    @State private var session: ProjectSession?
    @State private var projectName = ""
    @State private var generation = 0
    @State private var failure: String?
    @State private var selection: Tool? = .proxy
    @State private var showListeners = false
    /// Global search (⌘⇧F, HIS-050).
    @State private var showSearch = false
    /// Listener bind failures from opening the project (PRX-001), shown above the tools.
    @State private var bindErrors: [String] = []
    /// Gulp Browser (BRW-001…004): offer Chrome for Testing when nothing is installed.
    @State private var offerDownload = false
    @State private var browserStatus: String?

    var body: some View {
        Group {
            if let session {
                NavigationSplitView {
                    List(selection: $selection) {
                        ForEach(ToolSection.allCases) { section in
                            Section(section.title) {
                                ForEach(section.tools) { tool in
                                    Label(tool.title, systemImage: tool.symbol).tag(tool)
                                }
                            }
                        }
                    }
                    .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 300)
                    .listStyle(.sidebar)
                } detail: {
                    detail(session: session)
                        .safeAreaInset(edge: .top) { bindErrorBanner }
                }
                .sheet(isPresented: $showListeners) {
                    ProxyListenersView(session: session)
                }
                .sheet(isPresented: $showSearch) {
                    SearchView(session: session)
                }
                .toolbar {
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
            // "Send to Comparer / Decoder / Fuzzer" brings that tool forward (CMP-001, DEC-004, F07).
            guard let session else { return }
            for await tool in await session.inbox.opened() {
                switch tool {
                case .comparer: selection = .comparer
                case .decoder: selection = .decoder
                case .fuzzer: selection = .fuzzer
                }
            }
        }
        .onDisappear {
            // Temporary projects are kept (recoverable in Caches) until a save/discard prompt lands.
            let session = self.session
            Task { try? await session?.close(keepTemporary: true) }
        }
        .focusedSceneValue(\.projectActions, actions)
        .navigationSubtitle(projectName)
    }

    @ViewBuilder
    private func detail(session: ProjectSession) -> some View {
        switch selection {
        case .proxy:
            ProxyToolView(session: session, generation: generation)
                .toolbar {
                    Button("Listeners…") { showListeners = true }
                        .help("Proxy listeners for this project (PRX-001)")
                }
        case .target:
            TargetView(session: session)
        case .repeater:
            RepeaterView(session: session)
        case .fuzzer:
            FuzzerView(session: session)
        case .dashboard:
            IssuesDashboard(session: session)
        case .logger:
            LoggerView(session: session)
        case .notebook:
            NotebookView(session: session)
        case .decoder:
            DecoderView(session: session)
        case .comparer:
            ComparerView(session: session)
        case .jwt:
            JWTWorkbenchView()
        default:
            ContentUnavailableView(
                selection?.title ?? "Gulp", systemImage: selection?.symbol ?? "network",
                description: Text("This tool arrives in a later milestone. See docs/03-roadmap.md."))
        }
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
                            report = try await session.importExport.importFile(try Data(contentsOf: url))
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
                        try await session.importExport.export(as: format).write(to: url)
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
            projectName = await opened.url.lastPathComponent
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
            .keyboardShortcut("n", modifiers: [.command, .shift])
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
            .keyboardShortcut("i", modifiers: [.command, .shift])
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
