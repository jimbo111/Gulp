import Testing
@testable import GulpStore

@Suite("GulpStore scaffolding")
struct GulpStoreTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpStore.moduleName == "GulpStore")
    }
}
