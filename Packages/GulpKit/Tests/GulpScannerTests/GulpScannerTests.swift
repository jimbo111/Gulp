import Testing
@testable import GulpScanner

@Suite("GulpScanner scaffolding")
struct GulpScannerTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpScanner.moduleName == "GulpScanner")
    }
}
