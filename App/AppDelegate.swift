import AppKit

/// Application delegate. Kept minimal for M0; it will own cross-window services
/// (launched browsers, the system-proxy guard, etc.) in later milestones.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}
