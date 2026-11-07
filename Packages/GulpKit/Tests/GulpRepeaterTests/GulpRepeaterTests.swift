import Testing
@testable import GulpRepeater

@Suite("GulpRepeater scaffolding")
struct GulpRepeaterTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpRepeater.moduleName == "GulpRepeater")
    }
}
