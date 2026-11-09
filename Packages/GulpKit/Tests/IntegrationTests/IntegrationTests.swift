import Testing

@testable import GulpWorkspace

@Suite("integration scaffolding")
struct IntegrationTests {
    @Test("workspace module is linkable from integration tests")
    func workspaceLinkable() {
        #expect(GulpWorkspace.moduleName == "GulpWorkspace")
    }
}
