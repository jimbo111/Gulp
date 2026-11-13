import Foundation
import GulpCore
import Testing

@testable import GulpScanner

// F27 (M19): the passive secret & JS-endpoint recon checks.

@Suite("Recon checks (F27)")
struct ReconChecksTests {
    func message(_ body: String, mime: String = "application/javascript", path: String = "/app.js")
        -> PassiveMessage
    {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: \(mime)\r\nContent-Length: \(body.utf8.count)\r\n"
        let response = RawResponse(Bytes(head + "\r\n" + body))
        let exchange = Exchange(
            id: 1, source: .proxy, target: HTTPTarget(scheme: .https, host: "lab.test"),
            request: RawRequest(Bytes("GET \(path) HTTP/1.1\r\nHost: lab.test\r\n\r\n")),
            response: response, state: .complete)
        return PassiveMessage(exchange)!
    }

    func types(_ m: PassiveMessage) -> [String] { ReconChecks.scan(m).map(\.typeID).sorted() }

    @Test("F27: a hard-coded AWS key and a Stripe key are flagged as secrets")
    func test_F27_vendorSecrets() {
        let aws = message(
            "{\"aws_access_key_id\":\"AKIAIOSFODNN7EXAMPLE\"}", mime: "application/json", path: "/config")
        #expect(
            ReconChecks.scan(aws).contains {
                $0.typeID == "recon.secret" && $0.variant == "AWS access key id"
            })
        let stripe = message("const k = \"sk_live_51H8xR2eZvKYlo2C9bQf3mN7pL4wX\";")
        #expect(ReconChecks.scan(stripe).contains { $0.variant == "Stripe secret key" })
    }

    @Test("F27: a generic high-entropy secret is caught; a low-entropy placeholder is not")
    func test_F27_entropy() {
        let real = message("const config = { apiKey: \"a9F3kLz1QpR7sT2vW8xY4bC6\" };")
        #expect(ReconChecks.scan(real).contains { $0.typeID == "recon.secret" })
        let placeholder = message("const config = { apiKey: \"your_api_key_here_xxxx\" };")
        #expect(!ReconChecks.scan(placeholder).contains { $0.typeID == "recon.secret" })
        #expect(ReconChecks.entropy("aaaaaaaa") < 1.0)
        #expect(ReconChecks.entropy("a9F3kLz1QpR7sT2vW8xY") > 3.5)
    }

    @Test("F27: endpoints are extracted from JavaScript, not from HTML")
    func test_F27_endpoints() {
        let js = message(
            """
            fetch("/api/v2/profile"); axios.post("/api/v2/orders", {});
            const u = "/internal/admin/users";
            """)
        let endpoint = ReconChecks.scan(js).first { $0.typeID == "recon.endpoint" }
        let detail = try! #require(endpoint?.detail)
        #expect(detail.contains("/api/v2/profile") && detail.contains("/internal/admin/users"))
        // HTML isn't mined for endpoints.
        let html = message("<a href=\"/api/v2/x\">x</a>", mime: "text/html", path: "/page")
        #expect(!ReconChecks.scan(html).contains { $0.typeID == "recon.endpoint" })
    }

    @Test("F27: a clean JS file produces nothing")
    func test_F27_clean() {
        #expect(ReconChecks.scan(message("fetch(location.href);")).isEmpty)
    }
}
