import Testing

@testable import GulpOAST

@Suite("GulpOAST scaffolding")
struct GulpOASTTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpOAST.moduleName == "GulpOAST")
    }
}
