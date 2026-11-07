import Testing
@testable import GulpReport

@Suite("GulpReport scaffolding")
struct GulpReportTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpReport.moduleName == "GulpReport")
    }
}
