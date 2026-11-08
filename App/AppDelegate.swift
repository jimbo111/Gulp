import AppKit
import GulpWorkspace

/// Application delegate: app-wide services (launched browsers today; the system-proxy guard later).
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// BRW-004: closing Gulp closes the browsers it launched.
    func applicationWillTerminate(_ notification: Notification) {
        ProjectSession.terminateLaunchedBrowsers()
    }
}
