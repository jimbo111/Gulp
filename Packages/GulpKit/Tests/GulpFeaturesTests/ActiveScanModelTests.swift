#if canImport(AppKit)
import GulpScanner
import Testing

@testable import GulpFeatures

@MainActor
@Suite("Active scan model")
struct ActiveScanModelTests {
    /// F08 §3.5: the cache-poisoning family stays off unless the user turns it on for the scan.
    @Test func test_SCN034_cachePoisoningIsOptIn() async throws {
        let session = try await openIsolatedSession()
        let model = ActiveScanModel(session: session)
        #expect(model.scanConfig.disabledFamilies.isSuperset(of: ActiveChecks.optInFamilies))
        model.cachePoisoning = true
        #expect(model.scanConfig.disabledFamilies.isDisjoint(with: ActiveChecks.optInFamilies))
        try await session.close()
    }
}
#endif
