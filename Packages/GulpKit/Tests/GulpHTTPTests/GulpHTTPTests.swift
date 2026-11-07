import Testing
@testable import GulpHTTP

@Suite("GulpHTTP scaffolding")
struct GulpHTTPTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpHTTP.moduleName == "GulpHTTP")
    }
}
