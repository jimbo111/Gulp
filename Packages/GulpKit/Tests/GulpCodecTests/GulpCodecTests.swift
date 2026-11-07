import Testing
@testable import GulpCodec

@Suite("GulpCodec scaffolding")
struct GulpCodecTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpCodec.moduleName == "GulpCodec")
    }
}
