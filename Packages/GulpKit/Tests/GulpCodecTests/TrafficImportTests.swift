import Foundation
import GulpCore
import Testing

@testable import GulpCodec

// F20 PRJ-012/PRJ-013, F05 HIS-044, F23 ADV-050…052, F04 TGT-009: the import/export formats.

func fixture(_ name: String) throws -> Data {
    let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Fixtures/import/\(name)")
    return try Data(contentsOf: url)
}

@Suite("GulpCodec — traffic import/export (PRJ-012, PRJ-013, ADV-050…052)")
struct TrafficImportTests {
    @Test("Format detection by content")
    func test_PRJ012_detect() throws {
        #expect(TrafficImport.detect(try fixture("vulnlab-browser.har")) == .har)
        #expect(TrafficImport.detect(try fixture("vulnlab-mitmproxy.har")) == .har)
        #expect(TrafficImport.detect(try fixture("vulnlab.postman_collection.json")) == .postman)
        #expect(TrafficImport.detect(try fixture("vulnlab-history.xml")) == .xmlHistory)
        #expect(TrafficImport.detect(try fixture("vulnlab-caido.json")) == .caido)
        #expect(TrafficImport.detect(try fixture("sitemap.xml")) == .sitemap)
        #expect(TrafficImport.detect(try fixture("urls.txt")) == .urlList)
        #expect(TrafficImport.detect(Data(#"{"openapi":"3.0.0","paths":{}}"#.utf8)) == .openAPI)
        #expect(TrafficImport.detect(Data("hello".utf8)) == nil)
        #expect(throws: TrafficImportError.self) { try TrafficImport.read(Data("hello".utf8)) }
    }

    @Test("PRJ-013: the XML proxy-history export keeps every byte, comments and highlights")
    func test_PRJ013_xmlHistory() throws {
        let batch = try TrafficImport.read(try fixture("vulnlab-history.xml"))
        #expect(batch.format == .xmlHistory && batch.exchanges.count == 3 && batch.skipped.isEmpty)
        let first = batch.exchanges[0]
        #expect(first.target == HTTPTarget(scheme: .http, host: "127.0.0.1", port: 8088))
        #expect(
            first.request.bytes.string()
                == "GET /echo?from=xml HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
        )
        #expect(
            first.response?.parsed.statusCode == 200
                && first.response?.bytes.string().hasSuffix("hello") == true)
        #expect(first.comment == "login & echo check" && first.highlight == .yellow)
        #expect(first.startedAt != nil)
        #expect(batch.exchanges[1].comment == nil && batch.exchanges[1].highlight == nil)
        let third = batch.exchanges[2]
        #expect(third.target == HTTPTarget(scheme: .https, host: "localhost", port: 8443))
        #expect(third.highlight == .red && third.comment == "IDOR: bob's order")
    }

    @Test("PRJ-013: a Caido export keeps raw bytes, TLS, comments and colors")
    func test_PRJ013_caido() throws {
        let batch = try TrafficImport.read(try fixture("vulnlab-caido.json"))
        #expect(batch.exchanges.count == 2 && batch.skipped.isEmpty)
        #expect(batch.exchanges[0].request.bytes.string().hasPrefix("GET /echo?from=caido HTTP/1.1\r\n"))
        #expect(batch.exchanges[0].comment == "from Caido" && batch.exchanges[0].highlight == .blue)
        #expect(batch.exchanges[1].target == HTTPTarget(scheme: .https, host: "localhost", port: 8443))
        #expect(batch.exchanges[1].response?.parsed.statusCode == 200)
    }

    @Test("PRJ-013: a mitmproxy HAR is rebuilt — decoded bodies lose Content-Encoding, lengths fixed")
    func test_PRJ013_mitmproxy() throws {
        let batch = try TrafficImport.read(try fixture("vulnlab-mitmproxy.har"))
        #expect(batch.exchanges.count == 2)
        let gzip = try #require(batch.exchanges[0].response)
        let text = gzip.bytes.string()
        #expect(!text.lowercased().contains("content-encoding") && text.contains("Content-Length: 31\r\n"))
        #expect(text.hasSuffix("Hello from Gulp VulnLab (gzip)\n"))
        #expect(batch.exchanges[0].comment == "mitmproxy flow" && batch.exchanges[0].durationMs == 12.5)
        let post = batch.exchanges[1]
        #expect(
            post.request.bytes.string()
                == "POST /echo HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                + "Content-Length: 17\r\n\r\nuser=alice&pass=x")
        let chunked = try #require(post.response).bytes.string()
        #expect(
            !chunked.lowercased().contains("transfer-encoding")
                && chunked.hasSuffix("Content-Length: 5\r\n\r\nhello"))
    }

    @Test("HAR from a browser: h2 pseudo-headers become Host, base64 bodies decode, bad URLs are skipped")
    func test_ADV051_browserHAR() throws {
        let batch = try TrafficImport.read(try fixture("vulnlab-browser.har"))
        #expect(batch.exchanges.count == 2 && batch.skipped.count == 1)
        let items = batch.exchanges[0]
        #expect(items.httpVersion == .http2)
        #expect(
            items.request.bytes.string()
                == "GET /api/items?limit=2 HTTP/2\r\nHost: localhost:8443\r\naccept: application/json\r\n\r\n"
        )
        #expect(items.response?.parsed.statusCode == 200)
        let png = try #require(batch.exchanges[1].response)
        #expect(Array(png.bytes[png.parsed.body].rawBytes) == [0x89, 0x50, 0x4E, 0x47])
        #expect(batch.skipped.first?.reason.contains("not an http(s) URL") == true)
    }

    @Test("PRJ-012 / F20 acceptance 6: Gulp's HAR export imports back byte-for-byte")
    func test_PRJ012_harRoundTrip() throws {
        var exchanges: [Exchange] = []
        for i in 0..<20 {
            // Odd bytes on purpose: lowercase/duplicate headers, bare LF, binary body, interim 1xx.
            let request = RawRequest(
                Bytes(
                    "POST /x/\(i)?a=1 HTTP/1.1\r\nhost: lab\r\nX-Dup: 1\r\nX-Dup: 2\nContent-Length: 3\r\n\r\nab\(i % 10)"
                ))
            let response = RawResponse(
                wire: Bytes(
                    Array("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".utf8)
                        + [0, 1, 2, UInt8(i)]))
            var exchange = Exchange(
                id: ExchangeID(i + 1), source: i.isMultiple(of: 2) ? .proxy : .repeater,
                target: HTTPTarget(scheme: .https, host: "lab", port: 8443), request: request,
                response: response,
                state: .complete,
                annotation: Annotation(
                    comment: i == 3 ? "note, \"quoted\"" : nil, highlight: i == 4 ? .green : nil))
            exchange.timing.totalMs = Double(i)
            exchanges.append(exchange)
        }
        let har = try HAR.export(exchanges)
        let batch = try TrafficImport.read(har)
        #expect(batch.format == .har && batch.exchanges.count == 20)
        for (original, imported) in zip(exchanges, batch.exchanges) {
            #expect(imported.request.bytes == original.request.bytes)
            #expect(imported.response?.wireBytes == original.response?.wireBytes)
            #expect(imported.target == original.target && imported.source == original.source)
        }
        #expect(batch.exchanges[3].comment == "note, \"quoted\"" && batch.exchanges[4].highlight == .green)
        // Another tool reading the same file sees standard HAR fields.
        let json = try #require(try JSONSerialization.jsonObject(with: har) as? [String: Any])
        let entry = try #require(((json["log"] as? [String: Any])?["entries"] as? [[String: Any]])?.first)
        #expect((entry["request"] as? [String: Any])?["url"] as? String == "https://lab:8443/x/0?a=1")
        #expect(
            ((entry["response"] as? [String: Any])?["content"] as? [String: Any])?["encoding"] as? String
                == "base64")
        // CSV (HIS-044).
        let csv = String(decoding: HAR.csv(exchanges), as: UTF8.self)
        #expect(csv.hasPrefix("id,time,method,url,status,length,mime,highlight,comment\r\n1,"))
        #expect(csv.contains("\"note, \"\"quoted\"\"\""))
    }

    @Test("ADV-051: Postman v2.1 — folders, variables, disabled headers, raw/urlencoded bodies")
    func test_ADV051_postman() throws {
        let batch = try TrafficImport.read(try fixture("vulnlab.postman_collection.json"))
        #expect(batch.exchanges.count == 3 && batch.skipped.count == 1)
        let me = batch.exchanges[0]
        #expect(me.comment == "API / Me")
        #expect(
            me.request.bytes.string()
                == "GET /api/me HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nAuthorization: Bearer abc123\r\n\r\n")
        let order = batch.exchanges[1].request.bytes.string()
        #expect(
            order.contains(
                "Content-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"item\":\"tea\",\"quantity\":1}"
            ))
        #expect(batch.exchanges[2].request.bytes.string().hasSuffix("\r\n\r\nuser=alice&pass=x"))
        #expect(
            batch.skipped.first?.item == "Unknown host"
                && batch.skipped.first?.reason.contains("unresolved") == true)
    }

    @Test("TGT-009: sitemap.xml and URL lists become GET requests; non-http URLs are skipped")
    func test_TGT009_urls() throws {
        let sitemap = try TrafficImport.read(try fixture("sitemap.xml"))
        #expect(sitemap.exchanges.count == 2 && sitemap.skipped.count == 1)
        #expect(
            sitemap.exchanges[1].request.bytes.string()
                == "GET /api/items?limit=1&q=a HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n")
        let list = try TrafficImport.read(try fixture("urls.txt"))
        #expect(
            list.exchanges.map(\.target.port) == [8088, 8443]
                && list.exchanges.allSatisfy { $0.response == nil })
    }
}

@Suite("GulpCodec — OpenAPI import (ADV-050, ADV-052)")
struct OpenAPIImportTests {
    static let document = #"""
        {
          "openapi": "3.0.3",
          "servers": [{"url": "{scheme}://lab:{port}/v1", "variables": {"scheme": {"default": "https"}, "port": {"default": "8443"}}}],
          "security": [{"key": []}],
          "components": {
            "securitySchemes": {"key": {"type": "apiKey", "in": "header", "name": "X-Api-Key"}},
            "parameters": {"Page": {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1}}},
            "schemas": {
              "Tag": {"type": "string", "enum": ["red", "blue"]},
              "Pet": {"allOf": [
                {"type": "object", "properties": {"name": {"type": "string", "minLength": 8}, "id": {"type": "string", "format": "uuid"}}},
                {"type": "object", "properties": {"tags": {"type": "array", "items": {"$ref": "#/components/schemas/Tag"}},
                  "born": {"type": "string", "format": "date"}, "weight": {"type": "number"}, "ok": {"type": "boolean"},
                  "owner": {"$ref": "#/components/schemas/Pet"}}}
              ]}
            }
          },
          "paths": {
            "/pets/{petId}": {
              "parameters": [{"name": "petId", "in": "path", "required": true, "schema": {"type": "integer"}}],
              "get": {"operationId": "getPet", "parameters": [{"$ref": "#/components/parameters/Page"},
                {"name": "X-Trace", "in": "header", "example": "t1"}, {"name": "sess", "in": "cookie", "schema": {"type": "string"}}]},
              "put": {"operationId": "putPet", "security": [], "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}}}
            },
            "/login": {"post": {"security": [{"basic": []}], "requestBody": {"content": {"application/x-www-form-urlencoded":
              {"schema": {"type": "object", "properties": {"user": {"type": "string", "format": "email"}, "pass": {"type": "string", "format": "password"}}}}}}}}
          }
        }
        """#

    @Test("ADV-050: one request per operation with path/query/header/cookie params, bodies and auth")
    func test_ADV050_openAPI3() throws {
        let batch = try TrafficImport.read(Data(Self.document.utf8))
        #expect(batch.format == .openAPI && batch.exchanges.count == 3 && batch.skipped.isEmpty)
        let login = batch.exchanges[0]  // paths are sorted: /login, /pets/{petId}
        #expect(login.target == HTTPTarget(scheme: .https, host: "lab", port: 8443))
        let loginText = login.request.bytes.string()
        #expect(loginText.hasPrefix("POST /v1/login HTTP/1.1\r\nHost: lab:8443\r\n"))
        #expect(loginText.hasSuffix("\r\n\r\npass=Passw0rd%21&user=user%40example.com"))
        let get = batch.exchanges[1].request.bytes.string()
        #expect(
            get.hasPrefix(
                "GET /v1/pets/1?page=1 HTTP/1.1\r\nHost: lab:8443\r\nX-Trace: t1\r\nX-Api-Key: REPLACE_ME\r\nCookie: sess=string\r\n\r\n"
            ))
        #expect(batch.exchanges[1].comment == "getPet")
        let put = batch.exchanges[2].request
        #expect(!put.bytes.string().contains("X-Api-Key"))  // security: [] turns auth off
        let body = put.bytes[put.parsed.body].rawBytes
        let pet = try #require(try JSONSerialization.jsonObject(with: Data(body)) as? [String: Any])
        #expect(
            pet["name"] as? String == "stringxx"
                && pet["id"] as? String == "00000000-0000-4000-8000-000000000001")
        #expect(pet["tags"] as? [String] == ["red"] && pet["born"] as? String == "2026-01-01")
        #expect(pet["ok"] as? Bool == true && pet["weight"] as? Double == 1.5)
        #expect(pet["owner"] is [String: Any])  // recursion is bounded, not infinite
    }

    @Test(
        "ADV-050: Swagger 2.0 — host/basePath, body and formData parameters; a relative server needs a base URL"
    )
    func test_ADV050_swagger2() throws {
        let swagger = #"""
            {"swagger": "2.0", "basePath": "/api", "definitions": {"Order": {"type": "object", "properties": {"qty": {"type": "integer", "minimum": 2}}}},
             "paths": {"/orders": {"post": {"parameters": [{"in": "body", "name": "o", "schema": {"$ref": "#/definitions/Order"}}]}},
                       "/upload": {"post": {"parameters": [{"in": "formData", "name": "kind", "type": "string", "enum": ["a", "b"]}]}}}}
            """#
        #expect(throws: TrafficImportError.self) { try TrafficImport.read(Data(swagger.utf8)) }
        let batch = try TrafficImport.read(Data(swagger.utf8), baseURL: "http://127.0.0.1:8088/swagger.json")
        #expect(batch.exchanges.count == 2)
        #expect(
            batch.exchanges[0].request.bytes.string().hasSuffix(
                "Content-Type: application/json\r\nContent-Length: 9\r\n\r\n{\"qty\":2}"))
        #expect(batch.exchanges[1].request.bytes.string().hasSuffix("\r\n\r\nkind=a"))
        #expect(batch.exchanges[1].target == HTTPTarget(scheme: .http, host: "127.0.0.1", port: 8088))
    }

    @Test("ADV-052: schema values honour example, default, enum, format and bounds")
    func test_ADV052_values() {
        let values = SchemaValues()
        #expect(values.value(for: ["type": "integer", "minimum": 5]) as? Int == 5)
        #expect(values.value(for: ["type": "string", "format": "email"]) as? String == "user@example.com")
        #expect(values.value(for: ["type": "string", "default": "x"]) as? String == "x")
        #expect(values.value(for: ["type": "string", "example": "e", "default": "x"]) as? String == "e")
        #expect(values.value(for: ["type": ["null", "integer"]]) as? Int == 1)
        #expect(
            (values.value(for: ["type": "array", "minItems": 2, "items": ["type": "boolean"]]) as? [Bool])
                == [true, true])
    }
}
