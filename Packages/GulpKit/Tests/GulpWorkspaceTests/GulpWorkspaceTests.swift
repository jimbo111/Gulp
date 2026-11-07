import Testing
@testable import GulpWorkspace

@Suite("GulpWorkspace scaffolding")
struct GulpWorkspaceTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpWorkspace.moduleName == "GulpWorkspace")
    }
}
