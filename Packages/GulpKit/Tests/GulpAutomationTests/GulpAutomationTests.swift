import Testing
@testable import GulpAutomation

@Suite("GulpAutomation scaffolding")
struct GulpAutomationTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpAutomation.moduleName == "GulpAutomation")
    }
}
