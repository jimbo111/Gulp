import GulpCore
import Testing

@testable import GulpCodec

// F17 ETL-008 / doc 05 UI-040: "Copy as" snippets.

@Suite("GulpCodec — Copy as (ETL-008)")
struct RequestExportTests {
    let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: 8088)
    let post = RawRequest(
        Bytes(
            "POST /echo?a=1 HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n"
                + "X-Quote: it's\r\nContent-Length: 9\r\nConnection: close\r\n\r\nuser=a\r\nb"))

    @Test("cURL: method, exact URL, headers (minus computed ones) and the body as exact bytes")
    func curl() {
        let text = RequestExport.export(post, target: target, as: .curl)
        #expect(text.contains("-X 'POST'"))
        #expect(text.contains("'http://127.0.0.1:8088/echo?a=1'"))
        #expect(text.contains("-H 'Content-Type: application/x-www-form-urlencoded'"))
        #expect(text.contains("-H 'X-Quote: it'\\''s'"))
        #expect(!text.contains("Content-Length"))
        #expect(!text.contains("Connection"))
        #expect(!text.contains("Host:"))  // equal to the URL's authority
        #expect(text.contains("--data-binary $'user=a\\r\\nb'"))
    }

    @Test("cURL: GET has no -X; HEAD uses --head; HTTP/2 text adds --http2; binary bytes are escaped")
    func curlVariants() {
        let get = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: other.test\r\n\r\n"))
        let getText = RequestExport.export(get, target: target, as: .curl)
        #expect(!getText.contains("-X"))
        #expect(getText.contains("-H 'Host: other.test'"))  // differs from the URL: kept
        let head = RawRequest(Bytes("HEAD / HTTP/2\r\nhost: a\r\n\r\n"))
        let headText = RequestExport.export(head, target: target, as: .curl)
        #expect(headText.contains("--head") && headText.contains("--http2"))
        let binary = RawRequest(Bytes(Array("PUT / HTTP/1.1\r\n\r\n".utf8) + [0x00, 0xFF, 0x27]))
        #expect(RequestExport.export(binary, target: target, as: .curl).contains("$'\\x00\\xff\\''"))
    }

    @Test("Python, fetch, PowerShell and Go carry the same method, URL, headers and body")
    func otherFormats() {
        let python = RequestExport.export(post, target: target, as: .python)
        #expect(python.contains("requests.request(\n    \"POST\", \"http://127.0.0.1:8088/echo?a=1\""))
        #expect(python.contains("data=b\"user=a\\r\\nb\""))
        let fetch = RequestExport.export(post, target: target, as: .fetch)
        #expect(fetch.contains("method: \"POST\""))
        #expect(fetch.contains("\"X-Quote\": \"it's\""))
        #expect(fetch.contains("body: \"user=a\\r\\nb\""))
        let powershell = RequestExport.export(post, target: target, as: .powershell)
        #expect(powershell.contains("-ContentType 'application/x-www-form-urlencoded'"))
        #expect(powershell.contains("'X-Quote' = 'it''s'"))
        let go = RequestExport.export(post, target: target, as: .go)
        #expect(go.contains("http.NewRequest(\"POST\", \"http://127.0.0.1:8088/echo?a=1\""))
        #expect(go.contains("req.Header.Set(\"X-Quote\", \"it's\")"))
    }

    @Test("HTTPS on the default port omits the port")
    func defaultPort() {
        let request = RawRequest(Bytes("GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        let text = RequestExport.export(
            request, target: HTTPTarget(scheme: .https, host: "example.com", port: 443), as: .curl)
        #expect(text.contains("'https://example.com/x'"))
    }
}
