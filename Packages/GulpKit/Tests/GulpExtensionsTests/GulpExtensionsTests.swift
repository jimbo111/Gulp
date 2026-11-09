import Testing

@testable import GulpExtensions

@Suite("GulpExtensions scaffolding")
struct GulpExtensionsTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpExtensions.moduleName == "GulpExtensions")
    }
}
