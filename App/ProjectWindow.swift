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
                }
                .sheet(isPresented: $showListeners) {
                    ProxyListenersView(session: session)
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
            SessionHistoryView(session: session, generation: generation)
                .toolbar {
                    Button("Listeners…") { showListeners = true }
                        .help("Proxy listeners for this project (PRX-001)")
                }
        default:
            ContentUnavailableView(
                selection?.title ?? "Gulp", systemImage: selection?.symbol ?? "network",
                description: Text("This tool arrives in a later milestone. See docs/03-roadmap.md."))
        }
    }

    private var actions: ProjectActions? {
        guard let session else { return nil }
        return ProjectActions { url in
            Task {
                try? await session.saveAs(url)
                projectName = await session.url.lastPathComponent
                generation += 1  // the History view reloads from the new file
            }
        }
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
            _ = await opened.startProxyListeners()
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
