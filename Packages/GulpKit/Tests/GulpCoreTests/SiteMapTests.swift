import Testing

@testable import GulpCore

// F04 TGT-001…TGT-006: the site map trie and link extraction.

@Suite("GulpCore — site map (TGT-001…TGT-006)")
struct SiteMapTests {
    let a = HTTPTarget(scheme: .https, host: "a.test", port: 443)
    let b = HTTPTarget(scheme: .http, host: "B.test", port: 8080)

    @Test("F04 acceptance 1: two hosts, nested paths, a referenced-but-unvisited URL is inferred")
    func test_TGT001_tree() {
        var map = SiteMap()
        map.add(SiteMapEntry(id: 1, target: a, path: "/app/login", inScope: true))
        map.add(SiteMapEntry(id: 2, target: a, path: "/app/login", inScope: true))
        map.add(SiteMapEntry(id: 3, target: a, path: "/static/x.js", inScope: false))
        map.add(SiteMapEntry(id: 4, target: b, path: "/", inScope: false))
        map.addInferred(url: "https://a.test/app/admin?x=1")
        #expect(map.hosts.map(\.name) == ["http://b.test:8080", "https://a.test:443"])
        let host = "https://a.test:443"
        #expect(map.children(of: host).map(\.name) == ["app", "static"])
        #expect(map.children(of: host + "/app").map(\.name) == ["admin", "login"])
        #expect(map.node(host + "/app/login")?.exchanges == [1, 2])
        #expect(map.node(host + "/app/admin")?.visited == false)  // TGT-003: inferred
        #expect(map.node(host + "/app")?.visited == true)
        #expect(map.node(host + "/static")?.inScope == false && map.node(host + "/app")?.inScope == true)
        #expect(map.exchanges(under: host) == [1, 2, 3])
        // A later real request makes the inferred node visited.
        map.add(SiteMapEntry(id: 5, target: a, path: "/app/admin", inScope: true))
        #expect(map.node(host + "/app/admin")?.visited == true)
    }

    @Test("TGT-005: filters keep matching nodes and their ancestors")
    func test_TGT005_filters() {
        var map = SiteMap()
        map.add(SiteMapEntry(id: 1, target: a, path: "/app/login", inScope: true))
        map.add(SiteMapEntry(id: 2, target: a, path: "/static/x.js", inScope: false))
        map.addInferred(url: "https://a.test/app/admin")
        let host = "https://a.test:443"
        let inScope = map.visible(SiteMapFilter(inScopeOnly: true))
        #expect(inScope.contains(host + "/app/login") && !inScope.contains(host + "/static"))
        let visited = map.visible(SiteMapFilter(visitedOnly: true))
        #expect(!visited.contains(host + "/app/admin") && visited.contains(host + "/app"))
        let search = map.visible(SiteMapFilter(search: "LOGIN"))
        #expect(search == [host, host + "/app", host + "/app/login"])
    }

    @Test("TGT-006: numeric and UUID segments fold into {id} when grouping is on")
    func test_TGT006_grouping() {
        var map = SiteMap(groupsParameterizedSegments: true)
        map.add(SiteMapEntry(id: 1, target: a, path: "/users/1/orders", inScope: true))
        map.add(SiteMapEntry(id: 2, target: a, path: "/users/2/orders", inScope: true))
        map.add(
            SiteMapEntry(id: 3, target: a, path: "/users/0f8fad5b-d9cb-469f-a165-70867728950e", inScope: true)
        )
        #expect(map.children(of: "https://a.test:443/users").map(\.name) == ["{id}"])
        #expect(map.node("https://a.test:443/users/{id}/orders")?.exchanges == [1, 2])
    }

    @Test("Links: href/src/action, Location, absolute URLs in JSON; relative paths resolved")
    func test_TGT003_links() {
        let html = RawResponse(
            Bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\nLocation: /next\r\n\r\n"
                    + "<a href=\"../up\">x</a><img src='/img/a.png'><form action=\"submit?x=1\">"
                    + "<a href=\"mailto:a@b\">m</a><a href=\"#top\">t</a>"
                    + "<script>fetch(\"https://api.other.test/v1/items\")</script>"))
        let links = LinkExtractor.urls(in: html, pageURL: "https://a.test/app/page.html")
        #expect(
            Set(links) == [
                "https://a.test/next", "https://a.test/up", "https://a.test/img/a.png",
                "https://a.test/app/submit?x=1", "https://api.other.test/v1/items",
            ])
        #expect(LinkExtractor.resolve("//cdn.test/x.js", against: "http://a.test/") == "http://cdn.test/x.js")
        #expect(LinkExtractor.resolve("./a/./b", against: "http://a.test/d/") == "http://a.test/d/a/b")
        #expect(LinkExtractor.resolve("javascript:void(0)", against: "http://a.test/") == nil)
    }

    @Test("TGT-005: hide 404-only nodes and filter by MIME; inferred nodes are not hidden as 404s")
    func test_TGT005_notFoundAndMime() {
        var map = SiteMap()
        map.add(SiteMapEntry(id: 1, target: a, path: "/gone", inScope: true, status: 404, mime: "text/html"))
        map.add(
            SiteMapEntry(
                id: 2, target: a, path: "/api/x", inScope: true, status: 200, mime: "application/json"))
        map.add(SiteMapEntry(id: 3, target: a, path: "/page", inScope: true, status: 200, mime: "text/html"))
        map.addInferred(url: "https://a.test/later")
        let host = "https://a.test:443"
        let found = map.visible(SiteMapFilter(hideNotFound: true))
        #expect(
            !found.contains(host + "/gone") && found.contains(host + "/api/x")
                && found.contains(host + "/later"))
        let json = map.visible(SiteMapFilter(mimes: ["json"]))
        #expect(json == [host, host + "/api", host + "/api/x"])
    }
}

@Suite("GulpCore — Analyze target (TGT-008)")
struct TargetAnalysisTests {
    let target = HTTPTarget(scheme: .https, host: "lab", port: 443)

    func exchange(_ request: String, response: String? = nil) -> Exchange {
        Exchange(
            source: .proxy, target: target, request: RawRequest(Bytes(request)),
            response: response.map { RawResponse(Bytes($0)) })
    }

    @Test("TGT-008: dynamic vs static endpoints, parameters by location, and observations")
    func test_TGT008_analyze() {
        let body = #"{"user":"a","sessionToken":"abc"}"#
        let analysis = TargetAnalysis.analyze([
            exchange(
                "GET /download?file=report.pdf HTTP/1.1\r\nHost: lab\r\nCookie: sid=1; theme=dark\r\n\r\n"),
            exchange("GET /download?file=a.txt HTTP/1.1\r\nHost: lab\r\n\r\n"),
            exchange(
                "GET /login?next=https%3A%2F%2Fevil.test%2F HTTP/1.1\r\nHost: lab\r\n\r\n",
                response: "HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Length: 0\r\n\r\n"),
            exchange(
                "POST /login HTTP/1.1\r\nHost: lab\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                    + "Content-Length: 13\r\n\r\nu=a&p=secret1"),
            exchange(
                "POST /api/me HTTP/1.1\r\nHost: lab\r\nContent-Type: application/json\r\n"
                    + "Content-Length: \(body.utf8.count)\r\n\r\n" + body),
            exchange("GET /api/items?api_key=0123456789abcdef0123456789 HTTP/1.1\r\nHost: lab\r\n\r\n"),
            exchange("GET /static/app.css HTTP/1.1\r\nHost: lab\r\n\r\n"),
        ])
        #expect(analysis.requestCount == 7 && analysis.redirectCount == 1)
        #expect(
            analysis.endpointCount == 6 && analysis.dynamicEndpointCount == 5
                && analysis.staticEndpointCount == 1)
        let byName = Dictionary(uniqueKeysWithValues: analysis.parameters.map { ($0.name, $0) })
        #expect(byName["file"]?.count == 2 && byName["file"]?.locations == [.query])
        #expect(byName["file"]?.endpoints == ["GET /download"] && byName["file"]?.sampleValue == "report.pdf")
        #expect(byName["next"]?.sampleValue == "https://evil.test/")
        #expect(byName["p"]?.locations == [.body] && byName["user"]?.locations == [.json])
        #expect(byName["sid"]?.locations == [.cookie])
        let observed = Set(analysis.observations.map { "\($0.kind.rawValue):\($0.parameter)" })
        #expect(observed.contains("fileParameter:file"))
        #expect(observed.contains("redirectParameter:next"))
        #expect(observed.contains("tokenInURL:api_key"))
        #expect(observed.contains("tokenParameter:sessionToken"))
        #expect(!observed.contains("fileParameter:theme") && !observed.contains("redirectParameter:u"))
    }
}
