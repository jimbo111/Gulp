import Testing
@testable import GulpTLS

@Suite("GulpTLS scaffolding")
struct GulpTLSTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpTLS.moduleName == "GulpTLS")
    }
}
