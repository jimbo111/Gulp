import Foundation
import GulpFeatures
import GulpWorkspace
import SwiftUI

// The Gulp app: one window per open project (F20 PRJ-004), each with its own ProjectSession.
// Launch opens a temporary project (PRJ-001); File offers New/Open/Save As/Recent (PRJ-002).

/// The Gulp application entry point.
@main
struct GulpApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup(for: ProjectRef.self) { $ref in
            ProjectWindow(ref: ref)
                .frame(minWidth: 1000, minHeight: 640)
                .defaultAppStorage(AppDefaults.store)
        } defaultValue: {
            ProjectRef()
        }
        // Opened `.gulp` files reach AppDelegate, which opens each in its own window; without this
        // SwiftUI would also open an extra temporary-project window per open event.
        .handlesExternalEvents(matching: ["gulp-project-window"])
        .commands {
            ProjectCommands()
        }

        Settings {
            TabView {
                TLSSettingsView()
                    .tabItem { Label("TLS", systemImage: "lock.shield") }
                SettingsPlaceholderView()
                    .tabItem { Label("Proxy", systemImage: "network") }
            }
            .frame(width: 620, height: 440)
            .defaultAppStorage(AppDefaults.store)
        }
    }
}

/// Where `@AppStorage` view preferences live: the standard defaults, or — when the UI tests set
/// `GULP_DEFAULTS_SUITE` — a suite emptied at launch, so a test never sees (or changes) the
/// user's remembered tabs and layouts.
@MainActor
enum AppDefaults {
    static let store: UserDefaults = {
        guard let suite = ProcessInfo.processInfo.environment["GULP_DEFAULTS_SUITE"], !suite.isEmpty,
            let defaults = UserDefaults(suiteName: suite)
        else { return .standard }
        defaults.removePersistentDomain(forName: suite)
        return defaults
    }()
}

/// Identifies what a window shows: a project file, or (no path) a new temporary project.
struct ProjectRef: Codable, Hashable {
    /// Project file path; nil for a new temporary project.
    var path: String?
    /// Distinguishes temporary-project windows from each other.
    var id = UUID()
}

/// The app-level Settings window. Project settings (like the proxy listeners) live with the project:
/// open them from the project window's toolbar.
struct SettingsPlaceholderView: View {
    var body: some View {
        Text("Proxy listeners are project settings: use “Listeners…” in a project window's Proxy tool.")
            .padding()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
