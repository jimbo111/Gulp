import XCTest

/// Smoke UI tests for the app shell (docs/06-testing-strategy.md §6).
///
/// `@MainActor` because `XCUIApplication`/`XCUIElement` are main-actor-isolated under Swift 6
/// strict concurrency; without it the synchronous calls below are a compile error.
@MainActor
final class GulpAppUITests: XCTestCase {
    func test_M0_appLaunchesAndShowsSidebar() throws {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 10))
        // The sidebar lists the tools; "Repeater" is a stable anchor.
        XCTAssertTrue(app.staticTexts["Repeater"].waitForExistence(timeout: 15))
    }

    /// M2: launch opens a temporary project and shows Proxy → HTTP History (PRJ-001, HIS-001).
    func test_M2_launchShowsHistory() throws {
        let app = XCUIApplication()
        app.launch()
        let autoScroll = app.descendants(matching: .any)["Auto-scroll"]
        XCTAssertTrue(autoScroll.waitForExistence(timeout: 20), "History filter bar did not appear")
        let listeners = app.descendants(matching: .any)["Listeners…"]
        XCTAssertTrue(listeners.exists, "Proxy toolbar is missing the Listeners… button")
    }
}
