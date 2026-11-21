import Foundation
import GulpCore
import Testing

@testable import GulpScanner

@Suite("Parameter discovery (F23 ADV-020)")
struct ParamMinerTests {
    /// A page that processes two hidden params: `debug` changes behavior, `trace` is reflected.
    func app(_ request: RawRequest, safe: Bool) -> RawResponse {
        let derived = DerivedFields(
            target: HTTPTarget(scheme: .http, host: "app.test"), request: request, response: nil)
        var query: [String: String] = [:]
        for pair in (derived.query ?? "").split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            query[parts[0]] = parts.count > 1 ? parts[1] : ""
        }
        var body = "Welcome\n"
        if !safe {
            if query["debug"] != nil { body += "DEBUG: on\n" }
            if let trace = query["trace"] { body += "trace=\(trace)\n" }
        }
        let head = "HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\n\r\n"
        return RawResponse(Bytes(head + body))
    }

    func get(_ path: String) -> RawRequest {
        RawRequest(Bytes("GET \(path) HTTP/1.1\r\nHost: app.test\r\n\r\n"))
    }

    @Test("ADV-020: the processed hidden params are found (reflected and behavioral), guessable noise is not")
    func discover() async {
        let names = ["debug", "trace", "foo", "bar", "baz", "admin", "x1", "x2", "x3", "verbose"]
        let found = await ParamMiner.discover(base: get("/page"), names: names, batchSize: 4) {
            app($0, safe: false)
        }
        let byName = Dictionary(uniqueKeysWithValues: found.map { ($0.name, $0.evidence) })
        #expect(byName["trace"] == "reflected")
        #expect(byName["debug"] == "behavior change")
        #expect(found.count == 2, "\(found)")
    }

    @Test("ADV-020: a page that ignores unknown params yields nothing")
    func safePage() async {
        let names = ["debug", "trace", "foo", "admin", "verbose"]
        let found = await ParamMiner.discover(base: get("/page"), names: names) { app($0, safe: true) }
        #expect(found.isEmpty, "\(found)")
    }

    /// A page that prints its whole query string back (and, unless `quiet`, also processes `debug`).
    func echoApp(_ request: RawRequest, quiet: Bool) -> RawResponse {
        let derived = DerivedFields(
            target: HTTPTarget(scheme: .http, host: "app.test"), request: request, response: nil)
        let query = derived.query ?? ""
        var body = "Welcome\nYou asked for: \(query)\n"
        if !quiet, query.split(separator: "&").contains(where: { $0.hasPrefix("debug=") }) {
            body += "DEBUG: on\n"
        }
        return RawResponse(Bytes("HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\n\r\n" + body))
    }

    @Test(
        "ADV-020: a page that echoes its whole query string flags nothing as reflected; real behavior still shows"
    )
    func echoingPage() async {
        let names = ["debug", "trace", "foo", "admin", "verbose", "x1", "x2"]
        let quiet = await ParamMiner.discover(base: get("/page"), names: names, batchSize: 3) {
            echoApp($0, quiet: true)
        }
        #expect(quiet.isEmpty, "\(quiet)")
        let found = await ParamMiner.discover(base: get("/page"), names: names, batchSize: 3) {
            echoApp($0, quiet: false)
        }
        #expect(found == [DiscoveredParam(name: "debug", evidence: "behavior change")], "\(found)")
    }

    @Test("appendingQuery adds a ? or & correctly and keeps the rest of the request")
    func appendQuery() {
        let first = ParamMiner.appendingQuery(get("/a"), [("x", "1")])
        #expect(first.bytes.string().hasPrefix("GET /a?x=1 HTTP/1.1"))
        let second = ParamMiner.appendingQuery(get("/a?y=2"), [("x", "1")])
        #expect(second.bytes.string().hasPrefix("GET /a?y=2&x=1 HTTP/1.1"))
    }
}
