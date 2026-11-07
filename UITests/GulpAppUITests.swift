import XCTest

/// Smoke UI tests for the app shell (docs/06-testing-strategy.md §6).
/// M0 only checks that the app launches and the tool sidebar is present.
final class GulpAppUITests: XCTestCase {
    func test_M0_appLaunchesAndShowsSidebar() throws {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 10))
        // The sidebar lists the tools; "Repeater" is a stable anchor.
        XCTAssertTrue(app.staticTexts["Repeater"].waitForExistence(timeout: 5))
    }
}
