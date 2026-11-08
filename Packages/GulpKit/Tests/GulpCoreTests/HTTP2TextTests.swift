import Testing

@testable import GulpCore

// F03 HTTP-021/HTTP-022/HTTP-027 and doc 04 §3: HTTP/2 ↔ HTTP/1-style text.

@Suite("GulpCore — HTTP/2 text form (HTTP-021, HTTP-022, HTTP-027)")
struct HTTP2TextTests {
    @Test("HTTP-021: request line → pseudo-headers; Host → :authority; connection headers dropped")
    func test_HTTP021_requestParts() {
        let text =
            "POST /a?b=1 HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nKeep-Alive: 5\r\n"
            + "Upgrade: h2c\r\nProxy-Connection: x\r\nTE: trailers, gzip\r\nX-Mixed-Case: V\r\n"
            + "Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
        let request = RawRequest(Bytes(text))
        let parts = HTTP2Text.requestParts(request, scheme: .https, defaultAuthority: "fallback")
        #expect(parts.method == "POST")
        #expect(parts.scheme == "https")
        #expect(parts.authority == "example.com")
        #expect(parts.path == "/a?b=1")
        #expect(parts.headers == [H2Header("te", "trailers"), H2Header("x-mixed-case", "V")])
        #expect(parts.body == Array("abc".utf8))
    }

    @Test("HTTP-021: absolute-form targets keep only the path; a missing Host uses the default authority")
    func test_HTTP021_absoluteForm() {
        let parts = HTTP2Text.requestParts(
            RawRequest(Bytes("GET http://h.test:8080?x=1 HTTP/1.1\r\n\r\n")), scheme: .http,
            defaultAuthority: "h.test:8080")
        #expect(parts.path == "/?x=1")
        #expect(parts.authority == "h.test:8080")
        #expect(parts.headers.isEmpty)
        #expect(parts.body.isEmpty)
    }

    @Test("Doc 04 §3: an HTTP/2 request round-trips through the text form")
    func roundTripRequest() {
        let parts = H2RequestParts(
            method: "PUT", scheme: "https", authority: "api.test", path: "/v1",
            headers: [H2Header("content-type", "application/json")], body: Array("{}".utf8))
        let text = HTTP2Text.request(parts)
        let expected = "PUT /v1 HTTP/2\r\nhost: api.test\r\ncontent-type: application/json\r\n\r\n{}"
        #expect(text.bytes.string() == expected)
        #expect(HTTP2Text.requestParts(text, scheme: .https, defaultAuthority: "x") == parts)
    }

    @Test("HTTP-022: an HTTP/2 response is stored as `HTTP/2 200` text")
    func test_HTTP022_response() {
        let parts = H2ResponseParts(
            status: 200, headers: [H2Header("content-length", "2")], body: Array("ok".utf8))
        let response = HTTP2Text.response(parts)
        #expect(response.bytes.string() == "HTTP/2 200\r\ncontent-length: 2\r\n\r\nok")
        #expect(response.parsed.statusCode == 200)
        #expect(HTTP2Text.responseParts(response) == parts)
    }

    @Test("HTTP-027: trailers survive storage (chunked rendering) and come back out as trailers")
    func test_HTTP027_trailers() {
        let parts = H2ResponseParts(
            status: 200, headers: [H2Header("content-type", "application/grpc")], body: [0, 0, 0, 0, 1, 7],
            trailers: [H2Header("grpc-status", "0"), H2Header("grpc-message", "OK")])
        let response = HTTP2Text.response(parts)
        #expect(response.parsed.bodyFraming == .chunked)
        #expect(response.bytes.string().hasSuffix("0\r\ngrpc-status: 0\r\ngrpc-message: OK\r\n\r\n"))
        #expect(HTTP2Text.responseParts(response) == parts)
        // An empty body with trailers only (a gRPC error) also survives.
        let error = H2ResponseParts(
            status: 200, headers: [], body: [], trailers: [H2Header("grpc-status", "13")])
        #expect(HTTP2Text.responseParts(HTTP2Text.response(error)) == error)
    }

    @Test("HTTP/2 → HTTP/1.1 for h1 clients: status line, content-length, chunked trailers kept")
    func http1Response() {
        let plain = HTTP2Text.response(H2ResponseParts(status: 404, headers: [], body: Array("no".utf8)))
        #expect(
            String(decoding: HTTP2Text.http1Response(from: plain), as: UTF8.self)
                == "HTTP/1.1 404 Not Found\r\ncontent-length: 2\r\n\r\nno")
        let withTrailers = HTTP2Text.response(
            H2ResponseParts(
                status: 200, headers: [H2Header("content-length", "2")], body: Array("ok".utf8),
                trailers: [H2Header("x-t", "1")]))
        let wire = String(decoding: HTTP2Text.http1Response(from: withTrailers), as: UTF8.self)
        #expect(wire.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(!wire.contains("content-length"))
        #expect(wire.hasSuffix("2\r\nok\r\n0\r\nx-t: 1\r\n\r\n"))
        // HTTP/1 responses pass through untouched.
        let h1 = RawResponse(Bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        #expect(HTTP2Text.http1Response(from: h1) == h1.bytes.rawBytes)
    }

    @Test("An HTTP/2-text request sent over HTTP/1.1 gets HTTP/1.1 and a content-length")
    func http1Request() {
        let h2 = RawRequest(Bytes("POST /x HTTP/2\r\nhost: a\r\n\r\nbody"))
        let converted = HTTP2Text.http1Request(from: h2).bytes.string()
        #expect(converted == "POST /x HTTP/1.1\r\nhost: a\r\ncontent-length: 4\r\n\r\nbody")
        let get = RawRequest(Bytes("GET / HTTP/2\r\nhost: a\r\n\r\n"))
        #expect(HTTP2Text.http1Request(from: get).bytes.string() == "GET / HTTP/1.1\r\nhost: a\r\n\r\n")
        let h1 = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
        #expect(HTTP2Text.http1Request(from: h1) == h1)
    }
}
