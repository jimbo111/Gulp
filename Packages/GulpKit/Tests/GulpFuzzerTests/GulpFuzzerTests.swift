import Testing
@testable import GulpFuzzer

@Suite("GulpFuzzer scaffolding")
struct GulpFuzzerTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpFuzzer.moduleName == "GulpFuzzer")
    }
}
