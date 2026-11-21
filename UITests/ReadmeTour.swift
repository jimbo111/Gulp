import Foundation
import XCTest

/// The README screenshots (Scripts/readme-screenshots.sh). Opens a seeded project and attaches a
/// window screenshot of each tool to the test result; the script exports them into docs/assets.
///
/// Skipped in normal runs: it needs the project the script seeds, passed as
/// `TEST_RUNNER_GULP_README_PROJECT` (xcodebuild hands `TEST_RUNNER_*` variables to the runner).
@MainActor
final class ReadmeTour: XCTestCase {
    private var app: XCUIApplication!

    override func setUp() async throws {
        continueAfterFailure = true
        app = XCUIApplication()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "gulp-tour-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try
            #"{"proxy":{"listeners":[{"id":"\#(UUID().uuidString)","bindAddress":"127.0.0.1","port":0,"enabled":true}]}}"#
            .write(to: root.appendingPathComponent("user-settings.json"), atomically: true, encoding: .utf8)
        app.launchEnvironment["GULP_SUPPORT_DIR"] = root.path
        app.launchEnvironment["GULP_DEFAULTS_SUITE"] = "com.gulp.app.readme-tour"
        app.launchArguments += ["-ApplePersistenceIgnoreState", "YES"]
    }

    override func tearDown() async throws {
        app.terminate()
    }

    func test_README_tour() throws {
        guard let path = ProcessInfo.processInfo.environment["GULP_README_PROJECT"], !path.isEmpty else {
            throw XCTSkip("run through Scripts/readme-screenshots.sh")
        }
        app.launch()
        XCTAssertTrue(app.descendants(matching: .any)["tool.proxy"].waitForExistence(timeout: 20))
        app.typeKey("w", modifierFlags: .command)  // the launch's temporary project
        // File > Open…, then the panel's Go to Folder with the project's path.
        app.typeKey("o", modifierFlags: .command)
        XCTAssertTrue(app.sheets.firstMatch.waitForExistence(timeout: 10) || app.dialogs.firstMatch.exists)
        app.typeKey("g", modifierFlags: [.command, .shift])
        Thread.sleep(forTimeInterval: 0.6)
        app.typeText(path + "\r")
        Thread.sleep(forTimeInterval: 0.6)
        app.typeKey("\r", modifierFlags: [])
        XCTAssertTrue(app.descendants(matching: .any)["tool.proxy"].waitForExistence(timeout: 20))
        let window = app.windows.firstMatch
        // Room for the whole toolbar and filter bar: drag the bottom-right corner out.
        let corner = window.coordinate(withNormalizedOffset: CGVector(dx: 1, dy: 1)).withOffset(
            CGVector(dx: -2, dy: -2))
        corner.press(forDuration: 0.3, thenDragTo: corner.withOffset(CGVector(dx: 440, dy: 200)))

        // Proxy history with one exchange open.
        let table = app.tables.firstMatch
        XCTAssertTrue(table.tableRows.firstMatch.waitForExistence(timeout: 10))
        // A visible row near the bottom (History auto-scrolls to the newest); querying rows by index
        // or count walks the whole table and times out on a large one.
        table.coordinate(withNormalizedOffset: CGVector(dx: 0.4, dy: 0.82)).click()
        shoot(window, "proxy-history")

        for (tool, name) in [
            ("target", "target-site-map"), ("dashboard", "dashboard-issues"), ("repeater", "repeater"),
            ("scanner", "scanner"), ("decoder", "decoder"), ("notebook", "notebook"),
        ] {
            select(tool, in: window)
            XCTAssertTrue(app.descendants(matching: .any)["tool.\(tool)"].waitForExistence(timeout: 10))
            if tool == "dashboard", app.tables.firstMatch.tableRows.firstMatch.waitForExistence(timeout: 5) {
                app.tables.firstMatch.tableRows.firstMatch.click()  // an issue's detail
            }
            if tool == "repeater" {
                app.buttons["repeater.send"].firstMatch.click()
                _ = app.staticTexts["repeater.status"].waitForExistence(timeout: 15)
            }
            shoot(window, name)
        }
    }

    private func shoot(_ window: XCUIElement, _ name: String) {
        Thread.sleep(forTimeInterval: 0.8)  // let the last coalesced UI update land
        let attachment = XCTAttachment(screenshot: window.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func select(_ tool: String, in window: XCUIElement) {
        let row = window.descendants(matching: .any)["sidebar.\(tool)"].firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 10), "sidebar has no \(tool)")
        let sidebar = window.outlines.firstMatch
        var tries = 0
        while !sidebar.frame.contains(row.frame), tries < 10 {
            sidebar.scroll(byDeltaX: 0, deltaY: -60)
            tries += 1
        }
        row.click()
    }
}
