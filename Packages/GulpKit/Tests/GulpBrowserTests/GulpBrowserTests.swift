import Testing
@testable import GulpBrowser

@Suite("GulpBrowser scaffolding")
struct GulpBrowserTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpBrowser.moduleName == "GulpBrowser")
    }
}
