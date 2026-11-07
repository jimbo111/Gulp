import Testing
@testable import GulpScript

@Suite("GulpScript scaffolding")
struct GulpScriptTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpScript.moduleName == "GulpScript")
    }
}
