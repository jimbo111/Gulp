import Foundation
import GulpCodec
import GulpCore
import GulpStore
import Testing

@testable import GulpWorkspace

// F20 PRJ-008/PRJ-012/PRJ-013, F05 HIS-044, F23 ADV-050, F04 TGT-009: the import/export service.

func importFixture(_ name: String) throws -> Data {
    let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Fixtures/import/\(name)")
    return try Data(contentsOf: url)
}

@Suite("GulpWorkspace — import/export service (PRJ-012)", .serialized)
struct ImportExportTests {
    @Test("F20 acceptance 6: 1,000 rows → HAR → a new project, byte-for-byte; a second import adds nothing")
    func test_PRJ012_roundTrip() async throws {
        let environment = isolatedEnvironment()
        let source = try await open(environment, "har-source")
        let target = HTTPTarget(scheme: .https, host: "lab", port: 8443)
        for i in 0..<1_000 {
            let request = RawRequest(
                Bytes("GET /item/\(i)?q=\(i) HTTP/1.1\r\nHost: lab:8443\r\nX-N: \(i)\r\n\r\n"))
            let body = "row \(i)"
            let response = RawResponse(
                Bytes("HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"))
            let note = Annotation(comment: i == 7 ? "seven" : nil, highlight: i == 8 ? .purple : nil)
            _ = await source.store.writer.record(
                Exchange(
                    source: .proxy, target: target, request: request, response: response, state: .complete,
                    annotation: note))
        }
        let har = try await source.importExport.export(as: .har)
        let originals = try await source.store.exchanges(ids: try await source.store.exchangeIDs())
        try await source.close()

        let destination = try await open(environment, "har-destination")
        let report = try await destination.importExport.importFile(har)
        #expect(report.imported == 1_000 && report.duplicates == 0 && report.skipped.isEmpty)
        let copies = try await destination.store.exchanges(ids: report.ids)
        #expect(copies.count == 1_000)
        for (original, copy) in zip(originals, copies) {
            #expect(copy.request.bytes == original.request.bytes)
            #expect(copy.response?.wireBytes == original.response?.wireBytes)
            #expect(copy.target == original.target && copy.source == original.source)
            #expect(copy.annotation.tags.contains(importedTag))
        }
        #expect(copies[7].annotation.comment == "seven" && copies[8].annotation.highlight == .purple)
        let again = try await destination.importExport.importFile(har)
        #expect(again.imported == 0 && again.duplicates == 1_000)
        #expect(try await destination.store.count() == 1_000)
        try await destination.close()
    }

    @Test(
        "PRJ-012: identical requests at different times stay separate rows; files without times dedup on bytes"
    )
    func test_PRJ012_dedupIdentity() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "dedup")
        func entry(_ time: String) -> String {
            #"{"startedDateTime": "\#(time)", "time": 1, "request": {"method": "GET", "url": "http://lab/poll", "httpVersion": "HTTP/1.1", "headers": []}, "response": {"status": 204, "statusText": "No Content", "httpVersion": "HTTP/1.1", "headers": [], "content": {}}}"#
        }
        let har =
            #"{"log": {"version": "1.2", "entries": [\#(entry("2026-11-09T10:00:00.000Z")), \#(entry("2026-11-09T10:00:01.000Z")), \#(entry("2026-11-09T10:00:01.000Z"))]}}"#
        let first = try await session.importExport.importFile(Data(har.utf8))
        #expect(first.imported == 2 && first.duplicates == 1)  // the repeated entry (same time) is one event
        #expect(try await session.importExport.importFile(Data(har.utf8)).imported == 0)
        let urls = Data("http://lab/a\nhttp://lab/a\n".utf8)
        #expect(try await session.importExport.importFile(urls).imported == 1)
        #expect(try await session.importExport.importFile(urls).imported == 0)
        try await session.close()
    }

    @Test("F20 acceptance 7: the other-proxy fixtures import with their bytes, comments and highlights")
    func test_PRJ013_otherProxies() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "other-proxies")
        let xml = try await session.importExport.importFile(try importFixture("vulnlab-history.xml"))
        #expect(xml.format == "XML proxy-history export" && xml.imported == 3)
        let caido = try await session.importExport.importFile(try importFixture("vulnlab-caido.json"))
        #expect(caido.imported == 2)
        let mitm = try await session.importExport.importFile(try importFixture("vulnlab-mitmproxy.har"))
        #expect(mitm.imported == 2)
        let batch = try TrafficImport.read(try importFixture("vulnlab-history.xml"))
        let stored = try await session.store.exchanges(ids: xml.ids)
        for (file, row) in zip(batch.exchanges, stored) {
            #expect(
                row.request.bytes == file.request.bytes && row.response?.wireBytes == file.response?.wireBytes
            )
        }
        #expect(
            stored[0].annotation.comment == "login & echo check" && stored[0].annotation.highlight == .yellow)
        #expect(stored[2].annotation.highlight == .red && stored[2].target.scheme == .https)
        let caidoRows = try await session.store.exchanges(ids: caido.ids)
        #expect(caidoRows[0].annotation.comment == "from Caido" && caidoRows[0].annotation.highlight == .blue)
        try await session.close()
    }

    @Test("ADV-050 / TGT-009: OpenAPI operations land in the site map as inferred, request-only nodes")
    func test_ADV050_siteMap() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "openapi")
        let spec = #"""
            {"openapi": "3.0.0", "servers": [{"url": "/"}], "paths": {
              "/api/items": {"get": {}}, "/api/orders": {"post": {"requestBody": {"content": {"application/json":
                {"schema": {"type": "object", "properties": {"n": {"type": "integer"}}}}}}}},
              "/api/orders/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "integer", "example": 7}}]}}}}
            """#
        let report = try await session.importExport.importFile(
            Data(spec.utf8), baseURL: "http://127.0.0.1:8088/openapi.json")
        #expect(report.imported == 3)
        let map = await waitForSiteMap(session) {
            $0.node("http://127.0.0.1:8088:80/api/orders/7") != nil
                || $0.node("http://127.0.0.1:8088/api/orders/7") != nil
        }
        let host = "http://127.0.0.1:8088"
        #expect(map.node(host + "/api/items") != nil && map.node(host + "/api/orders/7") != nil)
        #expect(map.node(host + "/api/orders")?.visited == false)  // imported, never sent
        #expect(map.node(host + "/api/orders")?.exchanges.count == 1)
        try await session.close()
    }

    @Test("PRJ-008 / HIS-044: merge another project, export CSV and as a .gulp file")
    func test_PRJ008_merge() async throws {
        let environment = isolatedEnvironment()
        let other = try await open(environment, "merge-from")
        for path in ["/a", "/b"] { await recordSample(other, path: path) }
        await other.store.writer.flush()
        try await other.close()

        let session = try await open(environment, "merge-into")
        await recordSample(session, path: "/a")  // same bytes as the other project's /a, at another time
        await session.store.writer.flush()
        let report = try await session.importExport.importProject(at: projectURL(environment, "merge-from"))
        #expect(report.imported == 2 && report.duplicates == 0)  // a different time is a different event
        let again = try await session.importExport.importProject(at: projectURL(environment, "merge-from"))
        #expect(again.imported == 0 && again.duplicates == 2)
        let csv = String(decoding: try await session.importExport.export(as: .csv), as: UTF8.self)
        #expect(csv.split(separator: "\r\n").count == 4)  // header + 3 rows
        let items = projectURL(environment, "items")
        #expect(try await session.importExport.exportProject(ids: [1], to: items) == 1)
        await #expect(throws: GulpError.self) { try await session.importExport.exportProject(to: items) }
        await #expect(throws: GulpError.self) {
            try await session.importExport.importProject(at: projectURL(environment, "merge-into"))
        }
        try await session.close()
        let reopened = try ProjectStore.open(at: items)
        #expect(try await reopened.count() == 1)
        try await reopened.close()
    }
}

/// Waits (bounded) until `check` holds for the session's site map.
func waitForSiteMap(_ session: ProjectSession, _ check: @Sendable (SiteMap) -> Bool) async -> SiteMap {
    for _ in 0..<200 {
        let map = await session.siteMap.snapshot
        if check(map) { return map }
        try? await Task.sleep(for: .milliseconds(20))
    }
    return await session.siteMap.snapshot
}
