import Foundation
import GulpCore
import Testing

@testable import GulpScanner

// F08 §3.2 "Vulnerable JS libraries": version fingerprinting and the fixed-in comparison.

@Suite("Vulnerable JS libraries")
struct VulnLibraryTests {
    func message(_ body: String, mime: String = "text/html", path: String = "/") -> PassiveMessage {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: \(mime)\r\nContent-Length: \(body.utf8.count)\r\n"
        let exchange = Exchange(
            id: 9, source: .proxy, target: HTTPTarget(scheme: .https, host: "lab.test"),
            request: RawRequest(Bytes("GET \(path) HTTP/1.1\r\nHost: lab.test\r\n\r\n")),
            response: RawResponse(Bytes(head + "\r\n" + body)), state: .complete)
        return PassiveMessage(exchange)!
    }

    @Test("A vulnerable jQuery by filename is flagged; a fixed one is not")
    func test_jquery() {
        let old = VulnLibraryCheck.scan(message("<script src=\"/a/jquery-3.4.1.min.js\"></script>"))
        #expect(old.contains { $0.typeID == "passive.vuln-js-library" && $0.variant == "jQuery" })
        #expect(old.first?.detail.contains("Fixed in 3.5.0") == true)
        #expect(VulnLibraryCheck.scan(message("<script src=\"/a/jquery-3.7.1.min.js\"></script>")).isEmpty)
    }

    @Test("A banner comment version is detected in a JS file")
    func test_banner() {
        let js = message("/*! Bootstrap v4.1.0 */ ...", mime: "application/javascript", path: "/bootstrap.js")
        #expect(VulnLibraryCheck.scan(js).contains { $0.variant == "Bootstrap" })
    }

    @Test("version parsing and comparison")
    func test_semver() {
        #expect(VulnLibraryCheck.version("3.4.1") == [3, 4, 1])
        #expect(VulnLibraryCheck.version("2.0") == [2, 0, 0])
        #expect(VulnLibraryCheck.less([3, 4, 1], [3, 5, 0]))
        #expect(!VulnLibraryCheck.less([3, 7, 1], [3, 5, 0]))
        #expect(!VulnLibraryCheck.less([4, 17, 21], [4, 17, 21]))
    }

    @Test("AngularJS is always flagged (end of life)")
    func test_angular() {
        #expect(
            VulnLibraryCheck.scan(message("<script src=\"/angular-1.8.2.js\"></script>")).contains {
                $0.variant == "AngularJS"
            })
    }

    @Test("non-script responses are ignored")
    func test_ignore() {
        #expect(
            VulnLibraryCheck.scan(message("jquery-3.4.1", mime: "application/json", path: "/x.json")).isEmpty)
    }
}
