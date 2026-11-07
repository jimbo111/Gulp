import Testing
@testable import GulpProxy

@Suite("GulpProxy scaffolding")
struct GulpProxyTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpProxy.moduleName == "GulpProxy")
    }
}
