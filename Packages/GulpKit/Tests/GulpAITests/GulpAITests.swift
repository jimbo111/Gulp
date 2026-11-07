import Testing
@testable import GulpAI

@Suite("GulpAI scaffolding")
struct GulpAITests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpAI.moduleName == "GulpAI")
    }
}
