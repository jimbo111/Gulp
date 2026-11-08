import GulpCore
import Testing

@testable import GulpCodec

// F06 REP-017: paste a cURL command, a fetch call or a raw request into a Repeater tab.

@Suite("GulpCodec — Paste to request (REP-017)")
struct RequestImportTests {
    func text(_ imported: ImportedRequest) -> String { imported.request.bytes.string() }

    @Test("REP-017: Chrome's 'Copy as cURL (bash)' with continuations, cookies and a JSON body")
    func test_REP017_chromeCurl() throws {
        let paste = """
            curl 'https://api.example.com:8443/v1/items?q=a%20b' \\
              -H 'accept: application/json' \\
              -H 'content-type: application/json' \\
              -b 'session=abc; theme=dark' \\
              -H 'user-agent: Mozilla/5.0' \\
              --data-raw '{"name":"it'\\''s"}' \\
              --compressed
            """
        let imported = try RequestImport.parse(paste)
        #expect(imported.target == HTTPTarget(scheme: .https, host: "api.example.com", port: 8443))
        let expected =
            "POST /v1/items?q=a%20b HTTP/1.1\r\nHost: api.example.com:8443\r\n"
            + "accept: application/json\r\ncontent-type: application/json\r\n"
            + "Cookie: session=abc; theme=dark\r\nuser-agent: Mozilla/5.0\r\n"
            + "Accept-Encoding: gzip, deflate, br\r\nContent-Length: 15\r\n\r\n{\"name\":\"it's\"}"
        #expect(text(imported) == expected)
        #expect(imported.ignored.isEmpty)
    }

    @Test("REP-017: bundled and attached flags, -u, -X, -k, -L, --http2; unknown flags are reported")
    func test_REP017_flags() throws {
        let imported = try RequestImport.parse(
            "curl -sSkL -XPUT --http2 -u admin:s3cret -A agent/1 -e http://ref/ -o out.txt --max-time 5 "
                + "--frobnicate http://h/p -d a=1 -d 'b=2\n'")
        #expect(imported.insecure && imported.followRedirects && imported.prefersHTTP2)
        let request = text(imported)
        #expect(request.hasPrefix("PUT /p HTTP/1.1\r\nHost: h\r\n"))
        #expect(request.contains("Authorization: Basic YWRtaW46czNjcmV0\r\n"))
        #expect(request.contains("User-Agent: agent/1\r\nReferer: http://ref/\r\n"))
        #expect(request.contains("Content-Type: application/x-www-form-urlencoded\r\n"))
        #expect(request.hasSuffix("\r\n\r\na=1&b=2"))  // -d drops newlines and joins with &
        #expect(imported.ignored == ["-o out.txt", "--max-time 5", "--frobnicate"])
    }

    @Test("REP-017: $'…' ANSI-C bodies keep CRLF; --data-urlencode with -G goes to the query")
    func test_REP017_ansiAndGet() throws {
        let binary = try RequestImport.parse("curl http://h/up --data-binary $'line1\\r\\nline2\\x21'")
        #expect(text(binary).hasSuffix("Content-Length: 13\r\n\r\nline1\r\nline2!"))
        let get = try RequestImport.parse("curl -G http://h/s?x=1 --data-urlencode 'q=a b&c' -d n=2")
        #expect(text(get).hasPrefix("GET /s?x=1&q=a%20b%26c&n=2 HTTP/1.1\r\n"))
        #expect(!text(get).contains("Content-Length"))
        #expect(throws: RequestImportError.unterminatedQuote) { try RequestImport.parse("curl 'http://h") }
        #expect(throws: RequestImportError.missingURL) { try RequestImport.parse("curl -s") }
    }

    @Test("REP-017: Chrome's 'Copy as fetch' and a Node fetch call")
    func test_REP017_fetch() throws {
        let chrome = """
            fetch("https://shop.example/api/cart", {
              "headers": {
                "accept": "*/*",
                "content-type": "application/json",
                "x-csrf": "t\\u00f6ken"
              },
              "referrer": "https://shop.example/cart",
              "referrerPolicy": "strict-origin-when-cross-origin",
              "body": "{\\"sku\\":42}",
              "method": "POST",
              "mode": "cors",
              "credentials": "include"
            });
            """
        let imported = try RequestImport.parse(chrome)
        let expected =
            "POST /api/cart HTTP/1.1\r\nHost: shop.example\r\naccept: */*\r\n"
            + "content-type: application/json\r\n"
            + "x-csrf: töken\r\nReferer: https://shop.example/cart\r\nContent-Length: 10\r\n\r\n{\"sku\":42}"
        #expect(text(imported) == expected)
        #expect(imported.ignored.isEmpty)
        let node = try RequestImport.parse(
            "await fetch('http://localhost:3000/x', { method: 'delete', headers: { cookie: 'a=1' }, "
                + "body: null, signal: controller.signal, });")
        #expect(text(node) == "DELETE /x HTTP/1.1\r\nHost: localhost:3000\r\ncookie: a=1\r\n\r\n")
        #expect(node.ignored == ["signal"])
    }

    @Test("REP-017: a raw request is taken as is; the target comes from Host (443 → https)")
    func test_REP017_raw() throws {
        let raw = "GET /a HTTP/1.1\nHost: example.com:443\nX: y\n\n"
        let imported = try RequestImport.parse(raw)
        #expect(imported.request.bytes.rawBytes == Array(raw.utf8))  // exact bytes, LF endings kept
        #expect(imported.target == HTTPTarget(scheme: .https, host: "example.com", port: 443))
        let given = HTTPTarget(scheme: .http, host: "10.0.0.5", port: 8080)
        #expect(try RequestImport.parse(raw, target: given).target == given)
        #expect(throws: RequestImportError.unrecognized) { try RequestImport.parse("hello there") }
    }

    @Test("REP-017: Copy as cURL → paste gives the same request back")
    func test_REP017_roundTrip() throws {
        let original = RawRequest(
            Bytes(
                "POST /echo?x=1 HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nX-Token: a'b\"c\r\n"
                    + "Content-Type: text/plain\r\nContent-Length: 12\r\n\r\nhello\r\nworld"))
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: 8088)
        let curl = RequestExport.export(original, target: target, as: .curl)
        let imported = try RequestImport.parse(curl)
        #expect(imported.target == target)
        #expect(text(imported) == original.bytes.string(), "via: \(curl)")
        #expect(imported.ignored.isEmpty)
    }
}
