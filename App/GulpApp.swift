import SwiftUI

// M0 app shell: an empty window with the tool sidebar from docs/05-ui-ux.md §2.
// Feature screens (from the GulpFeatures package) are wired in starting at M2.

/// The Gulp application entry point.
@main
struct GulpApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            RootView()
                .frame(minWidth: 1000, minHeight: 640)
        }
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Gulp") {}  // real About panel in M16
            }
        }

        Settings {
            SettingsPlaceholderView()
        }
    }
}

/// The main split view: a tool sidebar and the (currently empty) detail area.
struct RootView: View {
    @State private var selection: Tool? = .dashboard

    var body: some View {
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
            ContentUnavailableView(
                selection?.title ?? "Gulp",
                systemImage: selection?.symbol ?? "network",
                description: Text("This tool arrives in a later milestone. See docs/03-roadmap.md.")
            )
        }
    }
}

/// Placeholder Settings pane until the real panes land (docs/05-ui-ux.md §1).
struct SettingsPlaceholderView: View {
    var body: some View {
        Text("Settings arrive in later milestones.")
            .padding()
            .frame(width: 480, height: 320)
    }
}
