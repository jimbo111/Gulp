import Testing

@testable import GulpCrawler

@Suite("GulpCrawler scaffolding")
struct GulpCrawlerTests {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpCrawler.moduleName == "GulpCrawler")
    }
}
