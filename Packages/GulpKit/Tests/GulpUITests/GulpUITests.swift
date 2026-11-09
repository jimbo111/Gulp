import Testing

@testable import GulpUI

@Suite("GulpUI scaffolding")
struct GulpUITests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpUI.moduleName == "GulpUI")
    }
}
