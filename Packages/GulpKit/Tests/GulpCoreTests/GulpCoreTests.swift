import Testing
@testable import GulpCore

@Suite("GulpCore scaffolding")
struct GulpCoreTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpCore.moduleName == "GulpCore")
    }
}
