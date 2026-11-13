import GulpCore
import Testing

@testable import GulpScanner

@Suite("Smuggling confirmation workbench (F23 ADV-032)")
struct SmugglingConfirmTests {
    let base = RawRequest(Bytes("GET /search HTTP/1.1\r\nHost: shop.example\r\n\r\n"))

    @Test("CL.TE confirmation smuggles a GPOST request-start and keeps the path/host")
    func test_ADV032_clteConfirmation() {
        let confirm = SmugglingProbe.confirmation(.clte, base: base)
        let attack = confirm.attack.bytes.string()
        // Conflicting framing is the whole point.
        #expect(attack.contains("Content-Length:"))
        #expect(attack.contains("Transfer-Encoding: chunked"))
        // The smuggled request-start carries the invalid marker method against the real path.
        #expect(attack.contains("GPOST /search HTTP/1.1"))
        // The back-end terminator that ends the "visible" body early.
        #expect(attack.contains("0\r\n\r\n"))
        // The follow-up is an innocuous GET to the same endpoint.
        let followUp = confirm.followUp.bytes.string()
        #expect(followUp.hasPrefix("GET /search HTTP/1.1"))
        #expect(!followUp.contains("GPOST"))
        #expect(confirm.vector == .clte)
    }

    @Test("CL.TE Content-Length equals the smuggled tail length, so the back-end stops at the terminator")
    func test_ADV032_clteFramingIsConsistent() {
        let attack = SmugglingProbe.confirmation(.clte, base: base).attack.bytes.string()
        // The declared Content-Length must equal the bytes after the header block.
        let parts = attack.components(separatedBy: "\r\n\r\n")
        let body = parts.dropFirst().joined(separator: "\r\n\r\n")
        var declared: Int?
        if let clRange = attack.range(of: #"Content-Length: (\d+)"#, options: .regularExpression) {
            let digits = String(attack[clRange]).replacingOccurrences(of: "Content-Length: ", with: "")
            declared = Int(digits)
        }
        #expect(declared == body.utf8.count)
    }

    @Test("TE.CL confirmation reads only the chunk-size line, leaving GPOST as the next request")
    func test_ADV032_teclConfirmation() {
        let confirm = SmugglingProbe.confirmation(.tecl, base: base)
        let attack = confirm.attack.bytes.string()
        #expect(attack.contains("Transfer-Encoding: chunked"))
        #expect(attack.contains("GPOST /search HTTP/1.1"))
        #expect(attack.hasSuffix("0\r\n\r\n"))
        #expect(confirm.expectedSignal.contains("4xx"))
    }
}
