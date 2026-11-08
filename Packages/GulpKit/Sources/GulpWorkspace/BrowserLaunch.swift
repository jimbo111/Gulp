// GulpWorkspace — the Gulp Browser for a project (F16 BRW-001…BRW-004): where its profile and the
// downloaded Chrome for Testing live, and launch options for the project's running listener.

import Foundation
import GulpBrowser
import GulpCore

extension WorkspaceEnvironment {
    /// Where Gulp keeps a downloaded Chrome for Testing (BRW-001).
    public var browserDownloads: URL { supportDirectory.appendingPathComponent("Browsers") }

    /// The isolated profile for browsers proxied through `port` (BRW-001/003). One per listener:
    /// a second launch on the same profile opens a window in the running browser, which already
    /// uses that listener.
    public func browserProfile(port: Int) -> URL {
        supportDirectory.appendingPathComponent("BrowserProfiles/listener-\(port)")
    }

    /// Installed Chromium-family browsers, Chrome for Testing first.
    public func installedBrowsers() -> [InstalledBrowser] {
        InstalledBrowser.discover(downloads: browserDownloads)
    }
}

extension ProjectSession {
    /// Launch options for the Gulp Browser through this project's first running listener, trusting
    /// the project's CA and leaf key (BRW-002); nil when no listener runs or there is no CA.
    public func browserLaunchOptions(urls: [String] = []) -> BrowserLaunchOptions? {
        guard let port = listenerPorts.first, let minter else { return nil }
        return BrowserLaunchOptions(
            proxyPort: port, spkiPins: minter.spkiPins, profile: environment.browserProfile(port: port),
            urls: urls)
    }
}

/// No Chromium-family browser is installed (offer Chrome for Testing, BRW-001).
public struct NoBrowserFound: Error, Sendable {}

extension ProjectSession {
    /// Open the Gulp Browser through this project's listener (BRW-004). Throws `NoBrowserFound`
    /// when there is nothing to launch, and a `GulpError` when no listener runs or there is no CA.
    @discardableResult
    public func openBrowser(urls: [String] = []) throws -> LaunchedBrowser {
        guard let browser = environment.installedBrowsers().first else { throw NoBrowserFound() }
        guard let options = browserLaunchOptions(urls: urls) else {
            throw GulpError(
                message: "The Gulp Browser needs a running proxy listener and the Gulp CA.",
                recoverySuggestion: "Start a listener in Proxy → Listeners.")
        }
        return try BrowserLauncher.shared.launch(browser, options: options)
    }

    /// Terminate every browser Gulp launched (on quit, BRW-004).
    public static func terminateLaunchedBrowsers() {
        BrowserLauncher.shared.terminateAll()
    }

    /// A user-facing sentence for an error from the browser actions.
    public static func describe(_ error: any Error) -> String {
        if let error = error as? GulpError {
            return [error.message, error.recoverySuggestion].compactMap { $0 }.joined(separator: " ")
        }
        return "\(error)"
    }
}

#if os(macOS)
extension WorkspaceEnvironment {
    /// Download the current stable Chrome for Testing into `browserDownloads` (BRW-001) and return
    /// it. The browser download is Gulp's own traffic, so it goes direct, not through a listener.
    public func downloadChromeForTesting() async throws -> InstalledBrowser {
        struct Index: Decodable {
            struct Download: Decodable {
                let platform: String
                let url: URL
            }
            struct Channel: Decodable {
                let version: String
                let downloads: [String: [Download]]
            }
            let channels: [String: Channel]
        }
        let indexURL = URL(
            string: "https://googlechromelabs.github.io/chrome-for-testing/"
                + "last-known-good-versions-with-downloads.json")!
        let (data, _) = try await URLSession.shared.data(from: indexURL)
        let index = try JSONDecoder().decode(Index.self, from: data)
        #if arch(arm64)
        let platform = "mac-arm64"
        #else
        let platform = "mac-x64"
        #endif
        let downloads = index.channels["Stable"]?.downloads["chrome"] ?? []
        guard let download = downloads.first(where: { $0.platform == platform }) else {
            throw GulpError(message: "Chrome for Testing has no \(platform) download listed.")
        }
        let (zip, _) = try await URLSession.shared.download(from: download.url)
        let unpacked = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer {
            try? FileManager.default.removeItem(at: unpacked)
            try? FileManager.default.removeItem(at: zip)
        }
        let ditto = Process()
        ditto.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        ditto.arguments = ["-x", "-k", zip.path, unpacked.path]
        try ditto.run()
        ditto.waitUntilExit()
        guard ditto.terminationStatus == 0 else {
            throw GulpError(message: "Could not unpack Chrome for Testing.")
        }
        let app = unpacked.appendingPathComponent("chrome-\(platform)/Google Chrome for Testing.app")
        let destination = browserDownloads.appendingPathComponent("Google Chrome for Testing.app")
        try FileManager.default.createDirectory(at: browserDownloads, withIntermediateDirectories: true)
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.moveItem(at: app, to: destination)
        guard let installed = InstalledBrowser.discover(downloads: browserDownloads).first,
            installed.name == "Chrome for Testing"
        else { throw GulpError(message: "Chrome for Testing was downloaded but cannot be run.") }
        return installed
    }
}
#endif
