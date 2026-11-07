import Testing
@testable import GulpDiff

@Suite("GulpDiff scaffolding")
struct GulpDiffTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpDiff.moduleName == "GulpDiff")
    }
}
