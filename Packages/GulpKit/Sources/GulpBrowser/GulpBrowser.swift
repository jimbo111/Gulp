// GulpBrowser — the Gulp Browser launch (F16 BRW-001…BRW-004): find a Chromium-family browser,
// launch it with an isolated profile pointed at a Gulp listener, with the Gulp CA's key pinned
// (`--ignore-certificate-errors-spki-list`) instead of a trust-store change, and terminate what was
// launched when Gulp quits. CDP automation (M13a) is a separate client; this file only launches.
// Plain Foundation (`Process`), so the flags and discovery are tested on Linux too.

import Foundation
import NIOConcurrencyHelpers

/// Namespace and module marker for the `GulpBrowser` module.
public enum GulpBrowser {
    /// The module's name, used in diagnostics.
    public static let moduleName = "GulpBrowser"
}

/// A Chromium-family browser found on this machine (BRW-001).
public struct InstalledBrowser: Sendable, Hashable, Identifiable {
    /// Display name, e.g. "Google Chrome".
    public var name: String
    /// The executable to run.
    public var executable: URL

    /// Stable identity (the executable path).
    public var id: String { executable.path }

    /// A browser at `executable`.
    public init(name: String, executable: URL) {
        self.name = name
        self.executable = executable
    }

    /// Where Chromium-family browsers usually live, in order of preference. `home` is the user's
    /// home directory; `downloads` is where Gulp keeps Chrome for Testing.
    public static func candidates(home: URL, downloads: URL?) -> [InstalledBrowser] {
        var list: [InstalledBrowser] = []
        if let downloads {
            list.append(
                InstalledBrowser(
                    name: "Chrome for Testing",
                    executable: downloads.appendingPathComponent(
                        "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing")))
        }
        let apps: [(String, String)] = [
            ("Google Chrome", "Google Chrome.app/Contents/MacOS/Google Chrome"),
            ("Chromium", "Chromium.app/Contents/MacOS/Chromium"),
            ("Microsoft Edge", "Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            ("Brave Browser", "Brave Browser.app/Contents/MacOS/Brave Browser"),
        ]
        for root in [URL(fileURLWithPath: "/Applications"), home.appendingPathComponent("Applications")] {
            for (name, path) in apps {
                list.append(InstalledBrowser(name: name, executable: root.appendingPathComponent(path)))
            }
        }
        // Linux (headless CI and development).
        for (name, path) in [
            ("Google Chrome", "/usr/bin/google-chrome"), ("Chromium", "/usr/bin/chromium"),
            ("Chromium", "/usr/bin/chromium-browser"), ("Microsoft Edge", "/usr/bin/microsoft-edge"),
        ] {
            list.append(InstalledBrowser(name: name, executable: URL(fileURLWithPath: path)))
        }
        return list
    }

    /// The candidates that exist and are executable.
    public static func discover(
        home: URL = FileManager.default.homeDirectoryForCurrentUser, downloads: URL? = nil,
        fileManager: FileManager = .default
    ) -> [InstalledBrowser] {
        var seen: Set<String> = []
        return candidates(home: home, downloads: downloads).filter { browser in
            let path = browser.executable.path
            return fileManager.isExecutableFile(atPath: path) && seen.insert(path).inserted
        }
    }
}

/// How to launch the Gulp Browser (BRW-001…BRW-003).
public struct BrowserLaunchOptions: Sendable, Hashable {
    /// The Gulp listener to proxy through.
    public var proxyHost: String
    /// Its port.
    public var proxyPort: Int
    /// Base64 SHA-256 SPKI pins of the Gulp CA (and the shared leaf key) — BRW-002.
    public var spkiPins: [String]
    /// The isolated profile directory (`--user-data-dir`).
    public var profile: URL
    /// Pages to open.
    public var urls: [String]
    /// Run without a window (CI checks); `dumpDOM` then prints the page and exits.
    public var headless: Bool
    /// With `headless`: print the first page's DOM and exit.
    public var dumpDOM: Bool

    /// Launch options.
    public init(
        proxyHost: String = "127.0.0.1", proxyPort: Int, spkiPins: [String], profile: URL,
        urls: [String] = [], headless: Bool = false, dumpDOM: Bool = false
    ) {
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        self.spkiPins = spkiPins
        self.profile = profile
        self.urls = urls
        self.headless = headless
        self.dumpDOM = dumpDOM
    }

    /// Chromium features that send background requests a test session must not record (BRW-003):
    /// translation, optimization hints, cast discovery, autofill server queries, the network-time
    /// ping (`clients2.google.com/time`), Safe Browsing's real-time key fetch
    /// (`gstatic.com/ohttp_gateway`) and the AI-mode eligibility check (`google.com/async/folae`).
    static let disabledFeatures = [
        "Translate", "OptimizationHints", "MediaRouter", "AutofillServerCommunication",
        "NetworkTimeServiceQuerying", "SafeBrowsingHashPrefixRealTimeLookups", "AimEnabled",
        "AimServerEligibilityEnabled", "AimServerRequestOnStartupEnabled",
    ]

    /// The command-line arguments.
    public var arguments: [String] {
        var args = [
            "--user-data-dir=\(profile.path)",
            "--proxy-server=http://\(proxyHost):\(proxyPort)",
            // `<-loopback>` removes Chromium's implicit bypass for localhost, so local targets
            // (VulnLab, dev servers) are proxied too; nothing else is bypassed.
            "--proxy-bypass-list=<-loopback>",
            // BRW-002: trust only certificates whose chain contains these keys (only honoured
            // together with --user-data-dir).
            "--ignore-certificate-errors-spki-list=\(spkiPins.joined(separator: ","))",
            // BRW-003: a clean, quiet test session.
            "--disable-quic",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-sync",
            "--disable-domain-reliability",
            "--disable-client-side-phishing-detection",
            "--metrics-recording-only",
            "--disable-features=" + Self.disabledFeatures.joined(separator: ","),
        ]
        if headless {
            args.append("--headless=new")
            if dumpDOM { args.append("--dump-dom") }
        }
        return args + urls
    }
}

/// A launched browser process.
public struct LaunchedBrowser: Sendable, Hashable, Identifiable {
    /// Process id.
    public var id: Int32
    /// What was launched.
    public var browser: InstalledBrowser
    /// With which options.
    public var options: BrowserLaunchOptions
}

/// Launches browsers and terminates them when asked (on app quit, BRW-004).
public final class BrowserLauncher: Sendable {
    /// The launcher the app uses.
    public static let shared = BrowserLauncher()

    // `Process` is not Sendable; it is only touched under this lock.
    private let running = NIOLockedValueBox<[Int32: ProcessBox]>([:])

    /// A launcher with nothing running.
    public init() {}

    /// Launch `browser` with `options`. Output goes to `output` (default: discarded).
    @discardableResult
    public func launch(
        _ browser: InstalledBrowser, options: BrowserLaunchOptions, output: FileHandle? = nil
    ) throws -> LaunchedBrowser {
        try FileManager.default.createDirectory(at: options.profile, withIntermediateDirectories: true)
        let process = Process()
        process.executableURL = browser.executable
        process.arguments = options.arguments
        process.standardOutput = output ?? FileHandle.nullDevice
        process.standardError = output ?? FileHandle.nullDevice
        let box = ProcessBox(process)
        process.terminationHandler = { [running] ended in
            _ = running.withLockedValue { $0.removeValue(forKey: ended.processIdentifier) }
        }
        try process.run()
        let pid = process.processIdentifier
        running.withLockedValue { $0[pid] = box }
        return LaunchedBrowser(id: pid, browser: browser, options: options)
    }

    /// Wait for a launched browser to exit; returns its exit status.
    public func wait(_ launched: LaunchedBrowser) -> Int32? {
        guard let box = running.withLockedValue({ $0[launched.id] }) else { return nil }
        box.process.waitUntilExit()
        return box.process.terminationStatus
    }

    /// The browsers still running.
    public var runningCount: Int { running.withLockedValue { $0.count } }

    /// Terminate every browser this launcher started (BRW-004: closing Gulp cleans them up).
    public func terminateAll() {
        let boxes = running.withLockedValue { state -> [ProcessBox] in
            defer { state = [:] }
            return Array(state.values)
        }
        for box in boxes where box.process.isRunning { box.process.terminate() }
    }
}

/// Holds a `Process` so it can live in a lock-protected dictionary.
// `Process` is not Sendable: every access goes through `BrowserLauncher.running`'s lock or happens
// on a process the launcher no longer shares (terminate/wait are thread-safe Foundation calls).
final class ProcessBox: @unchecked Sendable {
    let process: Process

    init(_ process: Process) {
        self.process = process
    }
}
