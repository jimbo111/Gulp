import Foundation
import XCTest

/// Smoke UI tests for the app shell (docs/06-testing-strategy.md §6).
///
/// Every launch is isolated: its own support folder (user settings, CA, temporary projects), its own
/// defaults suite for `@AppStorage` view preferences, and the proxy on a free port — so a test never
/// reads or changes the user's install, and never fights it for 127.0.0.1:8080.
///
/// `@MainActor` because `XCUIApplication`/`XCUIElement` are main-actor-isolated under Swift 6
/// strict concurrency; without it the synchronous calls below are a compile error.
@MainActor
final class GulpAppUITests: XCTestCase {
    /// The sidebar's tools (`Tool.rawValue` in App/Tool.swift), in sidebar order.
    static let tools = [
        "dashboard", "proxy", "target", "logger",
        "repeater", "fuzzer", "scanner", "beacon", "sequencer", "decoder", "comparer",
        "authzMatrix", "jwt", "graphql", "jsRecon", "domProbe",
        "notebook", "extensions", "assistant",
    ]

    /// VulnLab's port: the scheme's test pre-action starts it (project.yml), because the sandboxed
    /// UI-test runner may not listen on a port itself.
    static let vulnLabPort = 28_188

    private var app: XCUIApplication!

    override func setUp() async throws {
        continueAfterFailure = false
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "gulp-uitest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        // Port 0: the proxy listens on whatever port is free.
        let settings =
            #"{"proxy":{"listeners":[{"id":"\#(UUID().uuidString)","bindAddress":"127.0.0.1","port":0,"enabled":true}]}}"#
        try settings.write(
            to: root.appendingPathComponent("user-settings.json"), atomically: true, encoding: .utf8)
        app = XCUIApplication()
        app.launchEnvironment["GULP_SUPPORT_DIR"] = root.path
        app.launchEnvironment["GULP_DEFAULTS_SUITE"] = "com.gulp.app.uitests"
        // No window restoration from an earlier run: every test starts from one fresh window.
        app.launchArguments += ["-ApplePersistenceIgnoreState", "YES"]
    }

    override func tearDown() async throws {
        app.terminate()
    }

    func test_M0_appLaunchesAndShowsSidebar() throws {
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 10))
        // The sidebar lists the tools; Repeater is a stable anchor.
        let repeater = app.staticTexts["sidebar.repeater"]
        XCTAssertTrue(repeater.waitForExistence(timeout: 15))
        XCTAssertEqual(repeater.value as? String, "Repeater")
    }

    /// M2: launch opens a temporary project and shows Proxy → HTTP History (PRJ-001, HIS-001), with
    /// the listener status in the window toolbar (docs/05 §2).
    func test_M2_launchShowsHistory() throws {
        app.launch()
        let autoScroll = app.descendants(matching: .any)["Auto-scroll"]
        XCTAssertTrue(autoScroll.waitForExistence(timeout: 20), "History filter bar did not appear")
        let listeners = app.descendants(matching: .any)["listeners"]
        XCTAssertTrue(listeners.waitForExistence(timeout: 5), "Toolbar is missing the listener status")
    }

    /// Every sidebar tool opens its screen, and the app keeps running through all of them.
    func test_UI_everyToolOpens() throws {
        app.launch()
        XCTAssertTrue(app.descendants(matching: .any)["tool.proxy"].waitForExistence(timeout: 20))
        for tool in Self.tools {
            select(tool)
            XCTAssertTrue(
                app.descendants(matching: .any)["tool.\(tool)"].waitForExistence(timeout: 10),
                "\(tool) did not open")
            XCTAssertEqual(app.state, .runningForeground, "the app stopped after opening \(tool)")
        }
    }

    /// F06 REP-002 end to end: a Repeater tab sends to a local VulnLab and shows its 200.
    func test_REP002_repeaterSendsToVulnLab() throws {
        let port = Self.vulnLabPort
        app.launch()
        XCTAssertTrue(app.descendants(matching: .any)["tool.proxy"].waitForExistence(timeout: 20))
        select("repeater")
        app.buttons["New Tab"].firstMatch.click()
        let target = app.textFields["repeater.target"]
        XCTAssertTrue(target.waitForExistence(timeout: 10))
        target.click()
        target.typeKey("a", modifierFlags: .command)
        target.typeText("http://127.0.0.1:\(port)\r")
        XCTAssertEqual(target.value as? String, "http://127.0.0.1:\(port)")
        app.buttons["repeater.send"].click()
        let status = app.staticTexts["repeater.status"]
        XCTAssertTrue(status.waitForExistence(timeout: 30), "no response shown")
        XCTAssertEqual(status.value as? String ?? status.label, "200")
    }

    private func select(_ tool: String) {
        let row = app.descendants(matching: .any)["sidebar.\(tool)"]
        XCTAssertTrue(row.waitForExistence(timeout: 10), "sidebar has no \(tool)")
        let sidebar = app.outlines.firstMatch
        var tries = 0
        // Scroll until the whole row is inside the sidebar (a half-visible row takes no click).
        while !sidebar.frame.contains(row.frame), tries < 10 {
            sidebar.scroll(byDeltaX: 0, deltaY: -60)
            tries += 1
        }
        row.click()
    }
}
