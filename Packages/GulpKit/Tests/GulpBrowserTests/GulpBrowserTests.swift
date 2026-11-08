import Foundation
import Testing

@testable import GulpBrowser

// F16 BRW-001…BRW-004: discovery and launch flags (the launch itself is checked by the M4b
// browser script on macOS CI, where Chrome is installed).

@Suite("GulpBrowser — launch (BRW-001…BRW-004)")
struct GulpBrowserTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpBrowser.moduleName == "GulpBrowser")
    }

    @Test("BRW-002/003: proxy, SPKI pins, isolated profile and quiet-session flags")
    func test_BRW002_arguments() {
        let options = BrowserLaunchOptions(
            proxyPort: 8080, spkiPins: ["caPin=", "leafPin="], profile: URL(fileURLWithPath: "/tmp/p"),
            urls: ["https://localhost:8443/"])
        let args = options.arguments
        #expect(args.contains("--user-data-dir=/tmp/p"))
        #expect(args.contains("--proxy-server=http://127.0.0.1:8080"))
        #expect(args.contains("--proxy-bypass-list=<-loopback>"))
        #expect(args.contains("--ignore-certificate-errors-spki-list=caPin=,leafPin="))
        #expect(!args.contains("--ignore-certificate-errors"))  // only the pinned keys are trusted
        for flag in ["--disable-quic", "--no-first-run", "--no-default-browser-check"] {
            #expect(args.contains(flag))
        }
        #expect(args.last == "https://localhost:8443/")
        #expect(!args.contains("--headless=new"))
        var headless = options
        headless.headless = true
        headless.dumpDOM = true
        #expect(headless.arguments.contains("--headless=new") && headless.arguments.contains("--dump-dom"))
    }

    @Test("BRW-001: discovery keeps existing executables, Chrome for Testing first, no duplicates")
    func test_BRW001_discovery() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let downloads = root.appendingPathComponent("cft")
        let cft = downloads.appendingPathComponent(
            "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing")
        let userChrome = root.appendingPathComponent("Applications/Chromium.app/Contents/MacOS/Chromium")
        for file in [cft, userChrome] {
            try FileManager.default.createDirectory(
                at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            FileManager.default.createFile(
                atPath: file.path, contents: Data("#!/bin/sh\n".utf8), attributes: [.posixPermissions: 0o755])
        }
        defer { try? FileManager.default.removeItem(at: root) }
        let found = InstalledBrowser.discover(home: root, downloads: downloads)
        #expect(found.first?.name == "Chrome for Testing")
        #expect(found.contains { $0.executable.path == userChrome.path })
        #expect(Set(found.map(\.id)).count == found.count)
    }

    @Test("BRW-004: launched processes are tracked and terminated together")
    func test_BRW004_terminateAll() throws {
        // A stand-in "browser": a shell that ignores the Chromium flags and keeps running.
        let script = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        FileManager.default.createFile(
            atPath: script.path, contents: Data("#!/bin/sh\nexec sleep 30\n".utf8),
            attributes: [.posixPermissions: 0o755])
        defer { try? FileManager.default.removeItem(at: script) }
        let launcher = BrowserLauncher()
        let options = BrowserLaunchOptions(
            proxyPort: 1, spkiPins: [],
            profile: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
        let first = try launcher.launch(InstalledBrowser(name: "stub", executable: script), options: options)
        try launcher.launch(InstalledBrowser(name: "stub", executable: script), options: options)
        #expect(first.id > 0)
        #expect(launcher.runningCount == 2)
        launcher.terminateAll()
        #expect(launcher.runningCount == 0)
        #expect(launcher.wait(first) == nil)  // no longer tracked
    }
}
