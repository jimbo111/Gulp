import Foundation
import Testing

@testable import GulpCore

@Suite("GulpCore — model types (doc 04 §2)")
struct ModelTests {
    @Test("HTTPTarget parses http/https URLs, ports and IPv6 literals")
    func targetFromURL() throws {
        let local = try #require(HTTPTarget(url: "http://127.0.0.1:8088/echo?x=1"))
        #expect(local.scheme == .http && local.host == "127.0.0.1" && local.port == 8088)
        let tls = try #require(HTTPTarget(url: "https://Example.com"))
        #expect(tls.scheme == .https && tls.host == "Example.com" && tls.port == 443)
        let v6 = try #require(HTTPTarget(url: "http://[::1]:8080/"))
        #expect(v6.host == "::1" && v6.port == 8080)
        #expect(HTTPTarget(url: "http://h").map(\.port) == 80)
        for bad in ["ftp://x", "http://", "http://h:0", "http://h:abc", "http://:80", "example.com"] {
            #expect(HTTPTarget(url: bad) == nil, "\(bad) should not parse")
        }
    }

    @Test("ToolSource round-trips its stable TEXT encoding and Codable form")
    func toolSourceEncoding() throws {
        let all: [ToolSource] = [
            .proxy, .repeater, .fuzzer, .scanner, .crawler, .sequencer, .session, .browser, .automation,
            .ai, .`extension`(id: "com.example.check"),
        ]
        for source in all {
            #expect(ToolSource(rawValue: source.rawValue) == source)
            let json = try JSONEncoder().encode([source])
            let decoded = try JSONDecoder().decode([ToolSource].self, from: json)
            #expect(decoded == [source])
        }
        #expect(ToolSource.`extension`(id: "x").rawValue == "extension:x")
        #expect(ToolSource(rawValue: "extension:") == nil)
        #expect(ToolSource(rawValue: "nope") == nil)
        let encoded = try JSONEncoder().encode([ToolSource.repeater])
        #expect(String(decoding: encoded, as: UTF8.self) == #"["repeater"]"#)
    }

    @Test("GulpNetworkError has stable error tokens and round-trips through Codable")
    func networkErrorCodes() throws {
        #expect(GulpNetworkError.connectTimeout.code == "connect_timeout")
        #expect(GulpNetworkError.dnsFailure("h").code == "dns_failure")
        #expect(GulpNetworkError.tooLarge(limit: 5).code == "too_large")
        let values: [GulpNetworkError] = [.cancelled, .dnsFailure("x"), .tooLarge(limit: 9), .other("y")]
        let data = try JSONEncoder().encode(values)
        let decoded = try JSONDecoder().decode([GulpNetworkError].self, from: data)
        #expect(decoded == values)
    }

    @Test("DerivedFields extracts method, path, query, extension, status, MIME, title and cookies")
    func derivedFields() {
        let target = HTTPTarget(scheme: .http, host: "h", port: 8088)
        let requestText = "GET /dir/File.PHP?a=1&b=2 HTTP/1.1\r\nHost: h\r\nCookie: c=1\r\n\r\n"
        let request = RawRequest(Bytes(requestText))
        let body = "<html><head><TITLE> Hi there </TITLE></head></html>"
        let head = "HTTP/1.1 200 OK\r\nContent-Type: Text/HTML; charset=utf-8\r\nSet-Cookie: s=1\r\n"
        let response = RawResponse(Bytes(head + "Content-Length: \(body.utf8.count)\r\n\r\n\(body)"))
        let d = DerivedFields(target: target, request: request, response: response)
        #expect(d.method == "GET" && d.path == "/dir/File.PHP" && d.query == "a=1&b=2")
        #expect(d.ext == "php" && d.paramCount == 2 && d.hasCookies)
        #expect(d.status == 200 && d.mime == "text/html" && d.title == "Hi there" && d.setsCookies)
        #expect(d.responseLength == body.utf8.count)

        let absolute = RawRequest(Bytes("GET http://h:8080/x/y.js?q HTTP/1.1\r\n\r\n"))
        let a = DerivedFields(target: target, request: absolute, response: nil)
        #expect(a.path == "/x/y.js" && a.query == "q" && a.ext == "js" && a.status == nil)
        // A URL inside the query doesn't make the target absolute-form.
        let nested = RawRequest(Bytes("GET /fetch?url=http://example.com/a HTTP/1.1\r\n\r\n"))
        let n = DerivedFields(target: target, request: nested, response: nil)
        #expect(n.path == "/fetch" && n.query == "url=http://example.com/a")
    }

    @Test("Exchange computes derived fields and starts pending")
    func exchangeInit() {
        let target = HTTPTarget(scheme: .http, host: "h")
        let request = RawRequest(Bytes("GET /a HTTP/1.1\r\n\r\n"))
        let ex = Exchange(source: .repeater, target: target, request: request)
        #expect(ex.state == .pending && ex.response == nil && ex.derived.path == "/a")
        #expect(ExchangeState.failed(.connectionRefused) != .failed(.connectionReset))
    }
}
