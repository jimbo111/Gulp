import AppKit
import GulpFeatures
import GulpWorkspace

/// Application delegate: quitting closes every open project first, `.gulp` files opened from
/// Finder, Open With or the Dock go to a project window, and launched browsers close with the app.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// ⌘Q: close every project (Notebook edits and Repeater drafts still in their typing pause, the
    /// store's write coalescer and the passive scan queue are flushed) before the process exits.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard OpenProjects.shared.hasOpenProjects else { return .terminateNow }
        Task {
            await OpenProjects.shared.closeAll()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    /// BRW-004: closing Gulp closes the browsers it launched.
    func applicationWillTerminate(_ notification: Notification) {
        ProjectSession.terminateLaunchedBrowsers()
    }

    /// `.gulp` documents from Finder, Open With and the Dock (PRJ-002): a project window opens each.
    func application(_ application: NSApplication, open urls: [URL]) {
        OpenProjects.shared.requestOpen(urls.filter { $0.pathExtension == "gulp" })
    }
}
