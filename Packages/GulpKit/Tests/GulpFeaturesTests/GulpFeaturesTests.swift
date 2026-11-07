import Testing
@testable import GulpFeatures

@Suite("GulpFeatures scaffolding")
struct GulpFeaturesTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpFeatures.moduleName == "GulpFeatures")
    }
}
