// GulpScanner — cache poisoning/deception check helpers (F28 WCP-002/003). The live firing is the DoD
// (Scripts/cache-dod.sh against VulnLab's CacheLab); these cover the pure classification helpers.

import Foundation
import GulpCore
import Testing

@testable import GulpScanner

@Suite("Cache checks (F28 WCP-002/003)")
struct CacheChecksTests {
    @Test("WCP-001/002: cacheability detection")
    func cacheable() {
        func probe(_ headers: [String: String], body: String = "") -> Probe {
            let head =
                "HTTP/1.1 200 OK\r\n" + headers.map { "\($0): \($1)" }.joined(separator: "\r\n")
                + "\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
            return Probe(request: RawRequest(Bytes("GET / HTTP/1.1\r\n\r\n")), response: RawResponse(Bytes(head)), exchangeID: 0, seconds: 0)
        }
        #expect(CachePoisoningCheck.cacheable(probe(["Cache-Control": "public, max-age=60"])))
        #expect(CachePoisoningCheck.cacheable(probe(["Age": "5"])))
        #expect(CachePoisoningCheck.cacheable(probe(["X-Cache": "HIT"])))
        #expect(!CachePoisoningCheck.cacheable(probe(["Cache-Control": "private, no-store"])))
        #expect(!CachePoisoningCheck.cacheable(probe([:])))  // no cache cues
    }

    @Test("WCP-002: reflection detection in body and Location")
    func reflects() {
        func probe(location: String? = nil, body: String = "") -> Probe {
            var head = "HTTP/1.1 200 OK\r\n"
            if let location { head += "Location: \(location)\r\n" }
            head += "Content-Length: \(body.utf8.count)\r\n\r\n\(body)"
            return Probe(request: RawRequest(Bytes("GET / HTTP/1.1\r\n\r\n")), response: RawResponse(Bytes(head)), exchangeID: 0, seconds: 0)
        }
        let canary = "abcd1234.gulp-cache.test"
        #expect(CachePoisoningCheck.reflects(probe(body: "<a href=https://\(canary)/x>"), canary))
        #expect(CachePoisoningCheck.reflects(probe(location: "https://\(canary)/"), canary))
        #expect(!CachePoisoningCheck.reflects(probe(body: "nothing here"), canary))
    }

    @Test("WCP-003: private marker detection in a body")
    func privateMarker() {
        #expect(
            CacheDeceptionCheck.privateMarker("{\"user\":\"a\",\"Balance:\":\"$1\"}") == "Balance:")
        #expect(CacheDeceptionCheck.privateMarker("{\"email\":\"a@b.c\"}") == "\"email\"")
        #expect(CacheDeceptionCheck.privateMarker("<html>public page</html>") == nil)
        #expect(CacheDeceptionCheck.privateMarker(nil) == nil)
    }

    @Test("WCP-003: retarget keeps method and Host, swaps the path")
    func retarget() {
        let base = RawRequest(Bytes("GET /account HTTP/1.1\r\nHost: app.test\r\nCookie: s=1\r\n\r\n"))
        let out = CacheDeceptionCheck.retarget(base, path: "/account.css")
        let text = out.bytes.rawBytes.map { Character(UnicodeScalar($0)) }
        let s = String(text)
        #expect(s.contains("GET /account.css HTTP/1.1"))
        #expect(s.contains("Host: app.test"))
    }
}
