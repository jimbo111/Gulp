import Foundation
import GulpCore
import Testing

@testable import GulpScanner

@Suite("HTTP request smuggling probes (F23 ADV-030/031)")
struct SmugglingTests {
    func base() -> RawRequest { RawRequest(Bytes("GET /x HTTP/1.1\r\nHost: h\r\n\r\n")) }

    @Test("CL.TE and TE.CL probes carry conflicting length framing against the base endpoint")
    func probes() {
        let clte = SmugglingProbe.timingProbe(.clte, base: base()).bytes.string()
        #expect(clte.hasPrefix("POST /x HTTP/1.1"))
        #expect(clte.contains("Content-Length: 4"))
        #expect(clte.contains("Transfer-Encoding: chunked"))
        let tecl = SmugglingProbe.timingProbe(.tecl, base: base()).bytes.string()
        #expect(tecl.contains("Content-Length: 6"))
        #expect(tecl.contains("Transfer-Encoding: chunked"))
        #expect(SmugglingProbe.baselineProbe(base: base()).bytes.string().contains("Content-Length: 0"))
    }

    @Test("a large timing differential classifies a vector as vulnerable, a small one does not")
    func classify() {
        #expect(SmugglingProbe.isVulnerable(baseline: 0.1, probe: 5.2))
        #expect(!SmugglingProbe.isVulnerable(baseline: 0.1, probe: 0.3))
    }
}
