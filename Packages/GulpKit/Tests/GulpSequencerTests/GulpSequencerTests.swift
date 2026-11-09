import Testing

@testable import GulpSequencer

@Suite("GulpSequencer scaffolding")
struct GulpSequencerTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpSequencer.moduleName == "GulpSequencer")
    }
}
