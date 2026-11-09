import Testing

@testable import GulpSession

@Suite("GulpSession scaffolding")
struct GulpSessionTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpSession.moduleName == "GulpSession")
    }
}
