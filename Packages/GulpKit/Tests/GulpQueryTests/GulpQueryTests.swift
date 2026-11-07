import Testing
@testable import GulpQuery

@Suite("GulpQuery scaffolding")
struct GulpQueryTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpQuery.moduleName == "GulpQuery")
    }
}
