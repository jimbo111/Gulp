import Foundation
import GulpCore
import GulpQuery
import Testing

@testable import GulpStore

// GulpQL over the store (F05 HIS-024) and global search (HIS-050…053).

private func make(
    _ host: String, _ request: String, _ response: String?, source: ToolSource = .proxy, tags: [String] = [],
    comment: String? = nil, highlight: Highlight? = nil, edited: Bool = false, port: Int = 80,
    rawResponse: [UInt8]? = nil
) -> Exchange {
    let raw = RawRequest(Bytes(request))
    return Exchange(
        source: source, target: HTTPTarget(scheme: .http, host: host, port: port), request: raw,
        response: rawResponse.map { RawResponse(Bytes($0)) } ?? response.map { RawResponse(Bytes($0)) },
        state: .complete,
        edited: edited ? EditInfo(originalRequest: raw, originalResponse: nil, editedBy: .proxy) : nil,
        annotation: Annotation(comment: comment, highlight: highlight, tags: tags))
}

private func ok(_ body: String, status: Int = 200, type: String = "text/html", extra: String = "") -> String {
    "HTTP/1.1 \(status) X\r\nContent-Type: \(type)\r\n\(extra)Content-Length: \(body.utf8.count)\r\n\r\n\(body)"
}

/// A varied corpus: hosts in mixed case, every status class, request-only rows, tags, comments,
/// highlights, edits, a deflate-compressed body and several tools.
private func corpus() -> [Exchange] {
    let deflated = BlobStore.deflate(Array("<p>compressed secret token deflatedneedle</p>".utf8))!
    let deflateHead =
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: deflate\r\n"
        + "Content-Length: \(deflated.count)\r\n\r\n"
    return [
        make(
            "api.lab.test", "GET /v1/users?id=7 HTTP/1.1\r\nHost: api.lab.test\r\n\r\n",
            ok("{\"id\":7}", type: "application/json")),
        make(
            "API.Lab.Test", "GET /v1/fail HTTP/1.1\r\nHost: API.Lab.Test\r\n\r\n", ok("boom", status: 503),
            tags: ["imported"]),
        make(
            "www.lab.test", "GET /index.html HTTP/1.1\r\nHost: www.lab.test\r\n\r\n",
            ok("<title>Home</title>"), comment: "look"),
        make(
            "www.lab.test",
            "POST /login HTTP/1.1\r\nHost: www.lab.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=alice&pass=pw",
            ok("Welcome alice", extra: "Set-Cookie: s=1\r\n"), source: .repeater, highlight: .red),
        make("www.lab.test", "GET /pending HTTP/1.1\r\nHost: www.lab.test\r\n\r\n", nil),
        make(
            "cdn.other.test", "GET /app.js HTTP/1.1\r\nHost: cdn.other.test\r\n\r\n",
            ok("var x=1", type: "application/javascript"), source: .fuzzer, port: 8080),
        make(
            "api.lab.test", "GET /v1/err?q=reflectme HTTP/1.1\r\nHost: api.lab.test\r\nX-Trace: abc\r\n\r\n",
            ok("error reflectme", status: 500), tags: ["discovered", "Imported"], edited: true),
        make(
            "api.lab.test", "GET /v1/z HTTP/1.1\r\nHost: api.lab.test\r\n\r\n", nil,
            rawResponse: Array(deflateHead.utf8) + deflated),
    ]
}

@Suite("GulpQL over the store (HIS-024) and search (HIS-050…053)", .serialized)
struct QueryStoreTests {
    func seeded() async throws -> (ProjectStore, [ExchangeID]) {
        let store = try ProjectStore.open(at: temporaryProject())
        try await store.setScope([ScopeRule(host: "api.lab.test")])
        var ids: [ExchangeID] = []
        for exchange in corpus() { ids.append(await store.writer.record(exchange)) }
        await store.writer.flush()
        return (store, ids)
    }

    @Test("HIS-024: push-down + residual returns exactly what in-memory evaluation returns")
    func test_HIS024_equivalence() async throws {
        let (store, ids) = try await seeded()
        let scope = ScopeService(rules: [ScopeRule(host: "api.lab.test")])
        let expressions = [
            "resp.status >= 500", "not resp.status >= 500", #"req.host == "API.lab.test""#,
            #"req.host ~ "^api\.""#, #"req.host =~ "API""#, #"req.host !~ "api""#, "in_scope", "not in_scope",
            "matches_scope and has_response", "not has_response", "resp.status in 500..599",
            "resp.status in [200, 503]", #"req.method in [get]"#, #"source == repeater or source == fuzzer"#,
            #"tag == "imported""#, #"tag != "imported""#, #"tag ~ "^disc""#, "tag", "not tag", "comment",
            #"comment contains "LOO""#, #"highlight == red"#, "edited", "not edited", "resp.sets_cookie",
            #"resp.mime contains "json""#, #"req.path startswith "/v1/" and not resp.status == 200"#,
            #"req.ext == "js" or req.port == 8080"#, #"resp.body contains "secret token""#,
            #"resp.body contains "boom" or req.path == "/login""#, #"req.param("user") == "alice""#,
            #"reflected("q")"#, #"not (resp.status >= 500 or req.host ~ "www")"#, "resp.title == home",
            #"req.query contains "id=""#, #"req.header("x-trace") == "ABC""#, "id > 3 and id <= 6",
            #"resp.status != 200"#, #"req.path endswith ".html""#, "resp.length > 5", #"resp.mime !~ "html""#,
        ]
        var all: [Exchange] = []
        for id in ids { all.append(try #require(try await store.exchange(id: id))) }
        for text in expressions {
            let expression = try GulpQL.parse(text)
            var filter = HistoryFilter()
            filter.query = expression
            let viaStore = try await store.matchingIDs(filter: filter)
            let predicate = try GulpQLPredicate(expression)
            let context = GulpQLContext(
                scope: scope, decodeBody: { SearchDecoding.decode($0, encoding: $1) })
            let inMemory = all.filter { predicate.evaluate($0, context: context) }.map(\.id)
            #expect(viaStore == inMemory, "\(text): store \(viaStore) vs memory \(inMemory)")
            #expect(try await store.count(matching: filter) == inMemory.count, "\(text)")
        }
        try await store.close()
    }

    @Test("F05 acceptance 1: status ≥ 500 and host ~ api uses the status index and loads no bodies")
    func test_HIS024_acceptance() async throws {
        let (store, ids) = try await seeded()
        var filter = HistoryFilter()
        filter.query = try GulpQL.parse(#"resp.status >= 500 and req.host ~ "api""#)
        #expect(filter.query?.sqlLowering().residual == nil)
        #expect(try await store.matchingIDs(filter: filter) == [ids[1], ids[6]])
        // A realistic distribution (few 5xx) and fresh statistics: the planner picks the index.
        for n in 0..<300 {
            _ = await store.writer.record(
                make("www.lab.test", "GET /p\(n) HTTP/1.1\r\nHost: www.lab.test\r\n\r\n", ok("fine")))
        }
        try await store.updateStatistics()
        let plan = try await store.queryPlan(filter: filter)
        #expect(plan.contains("ix_ex_status"), "plan: \(plan)")
        var host = HistoryFilter()
        host.query = try GulpQL.parse(#"req.host == "Api.Lab.Test""#)
        #expect(try await store.queryPlan(filter: host).contains("ix_ex_host"))
        // Paging over a GulpQL result keeps its order.
        let rows = try await store.summaries(inOrder: [ids[6], ids[1]])
        #expect(rows.map(\.id) == [ids[6], ids[1]] && rows[1].host == "api.lab.test")
        try await store.close()
    }

    @Test("HIS-002 + HIS-024: History pages and counts work for a query with a residual; commits refresh it")
    func test_HIS024_residualPaging() async throws {
        let (store, ids) = try await seeded()
        var filter = HistoryFilter()
        filter.query = try GulpQL.parse(#"resp.body contains "e" and req.host contains "lab""#)
        #expect(filter.query?.sqlLowering().residual != nil)
        let all = try await store.matchingIDs(filter: filter)
        #expect(try await store.count(filter: filter) == all.count)
        let firstPage = try await store.summaries(filter: filter, offset: 0, limit: 2)
        let secondPage = try await store.summaries(filter: filter, offset: 2, limit: 2)
        #expect((firstPage + secondPage).map(\.id) == Array(all.prefix(4)))
        let descending = try await store.summaries(
            filter: filter, sort: HistorySort(column: .id, ascending: false), offset: 0, limit: 1)
        #expect(descending.first?.id == all.last)
        #expect(try await store.exchangeIDs(filter: filter) == all)
        // A new matching row is visible on the next read (the cache is keyed by commits).
        let added = await store.writer.record(
            make("x.lab.test", "GET /new HTTP/1.1\r\nHost: x.lab.test\r\n\r\n", ok("fresh")))
        #expect(try await store.count(filter: filter) == all.count + 1)
        #expect(try await store.exchangeIDs(filter: filter).last == added)
        _ = ids
        try await store.close()
    }

    @Test("HIS-050/051: indexed search finds a token in requests and responses; part and section select")
    func test_HIS050_search() async throws {
        let (store, ids) = try await seeded()
        var query = SearchQuery("REFLECTME")
        var results = try await store.search(query)
        #expect(results.usedIndex && results.hits.map(\.id) == [ids[6]])
        #expect(results.hits.first?.inRequest == true && results.hits.first?.inResponse == true)
        #expect(results.hits.first?.preview.contains("q=reflectme") == true)
        query.part = .response
        query.section = .headers
        #expect(try await store.search(query).hits.isEmpty)  // only in the response body
        query.section = .body
        #expect(try await store.search(query).hits.first?.preview == "error reflectme")
        // Compressed bodies are indexed and matched decoded.
        results = try await store.search(SearchQuery("deflatedneedle"))
        #expect(results.usedIndex && results.hits.map(\.id) == [ids[7]])
        // The current table's filter narrows the search (HIS-051).
        var scoped = SearchQuery("lab.test")
        scoped.filter.source = .repeater
        #expect(try await store.search(scoped).hits.map(\.id) == [ids[3]])
        scoped.filter = HistoryFilter()
        scoped.filter.inScopeOnly = true
        #expect(try await store.search(scoped).hits.map(\.id) == [ids[7], ids[6], ids[1], ids[0]])
        #expect(try await store.findReferences("alice").hits.map(\.id) == [ids[3]])
        try await store.close()
    }

    @Test("HIS-052: regex search prefilters on a literal; short queries fall back to a bounded scan")
    func test_HIS052_regexAndShort() async throws {
        let (store, ids) = try await seeded()
        var regex = SearchQuery(#"reflect[a-z]+"#)
        regex.regex = true
        var results = try await store.search(regex)
        #expect(results.usedIndex && results.hits.map(\.id) == [ids[6]])
        regex.text = #"user=\w+&pass"#
        results = try await store.search(regex)
        #expect(results.usedIndex && results.hits.map(\.id) == [ids[3]])
        regex.text = #"(alice|bob)"#
        results = try await store.search(regex)
        #expect(!results.usedIndex && results.hits.map(\.id) == [ids[3]] && results.hint != nil)
        let short = try await store.search(SearchQuery("pw"))
        #expect(
            !short.usedIndex && short.hits.map(\.id) == [ids[3]] && short.hint?.contains("3 or more") == true)
        #expect(try await store.rebuildSearchIndex() == ids.count)
        #expect(try await store.search(SearchQuery("deflatedneedle")).hits.map(\.id) == [ids[7]])
        try await store.close()
    }

    @Test("HIS-052: the regex prefilter only uses literals every match must contain")
    func test_HIS052_longestLiteral() {
        #expect(SearchMatcher.longestLiteral(#"token=[a-f0-9]{32}"#) == "token=")
        #expect(SearchMatcher.longestLiteral(#"(foo|bar)bazz"#) == "")
        #expect(SearchMatcher.longestLiteral(#"(abc)?defg"#) == "defg")
        #expect(SearchMatcher.longestLiteral(#"ab?cde\.php"#) == "cde.php")
        #expect(SearchMatcher.longestLiteral(#"\d+\s*items"#) == "items")
    }

    @Test("Content decoding: deflate (zlib and raw) and truncated input")
    func test_contentDecoding() {
        let text = Array(String(repeating: "gulp ", count: 1000).utf8)
        let zlib = BlobStore.deflate(text)!
        #expect(SearchDecoding.decode(zlib, encoding: "deflate") == text)
        #expect(SearchDecoding.decode(zlib, encoding: "identity, deflate") == text)
        #expect(SearchDecoding.decode(zlib, encoding: "br") == nil)
        #expect(SearchDecoding.decode(text, encoding: "gzip") == nil)
        #expect(SearchDecoding.decode(zlib, encoding: "deflate", limit: 100)?.count == 100)
    }

    @Test("HIS-042: exchanges grouped by the connection that carried them")
    func test_HIS042_connections() async throws {
        let store = try ProjectStore.open(at: temporaryProject())
        for (connection, path) in [(7, "/a"), (7, "/b"), (9, "/c")] {
            var exchange = make("lab", "GET \(path) HTTP/1.1\r\nHost: lab\r\n\r\n", ok("x"))
            exchange.connectionID = UInt64(connection)
            exchange.tls = TLSInfo(version: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256", alpn: "h2")
            _ = await store.writer.record(exchange)
        }
        _ = await store.writer.record(make("lab", "GET /none HTTP/1.1\r\nHost: lab\r\n\r\n", ok("x")))
        let connections = try await store.connectionSummaries()
        #expect(connections.map(\.id) == [9, 7] && connections.map(\.exchanges) == [1, 2])
        #expect(connections[1].alpn == "h2" && connections[1].origin == "http://lab:80")
        try await store.close()
    }
}
