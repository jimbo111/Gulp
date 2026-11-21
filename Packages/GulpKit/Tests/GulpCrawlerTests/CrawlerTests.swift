import Foundation
import GulpCore
import GulpHTTP
import NIOConcurrencyHelpers
import Testing

@testable import GulpCrawler

// F09 CRL-001…CRL-010 (static mode) against an in-memory site.

/// An in-memory site: path (with query) → (status, content type, body, extra headers).
final class FakeSite: Sendable {
    struct Page: Sendable {
        var status = 200
        var type = "text/html"
        var body = ""
        var headers: [String] = []
    }

    let pages: [String: Page]
    let log = NIOLockedValueBox<[String]>([])

    init(_ pages: [String: Page]) { self.pages = pages }

    var requested: [String] { log.withLockedValue { $0 } }

    /// The crawl sender: answers from `pages` (404 otherwise), recording "METHOD host/path?query".
    var sender: CrawlSender {
        { request, target in
            let line = request.bytes[request.parsed.target].string()
            let method = request.bytes[request.parsed.method].string()
            self.log.withLockedValue { $0.append("\(method) \(target.host)\(line)") }
            let page =
                target.host == "lab"
                ? (self.pages[line] ?? Page(status: 404, body: "nope")) : Page(status: 200, body: "elsewhere")
            let head =
                ([
                    "HTTP/1.1 \(page.status) X", "Content-Type: \(page.type)",
                    "Content-Length: \(page.body.utf8.count)",
                ]
                + page.headers).joined(separator: "\r\n")
            let response = RawResponse(Bytes(head + "\r\n\r\n" + page.body))
            return ExchangeResult(
                exchange: Exchange(
                    source: .crawler, target: target, request: request, response: response, state: .complete))
        }
    }
}

@Suite("Static crawler (CRL-001…010)")
struct CrawlerTests {
    static let site = FakeSite([
        "/": .init(
            body: """
                <html><head><base href="/app/"><link rel=stylesheet href="/css/site.css"></head>
                <body><a href='page1'>1</a> <A HREF="/about?utm_source=x&amp;id=2">about</A>
                <a href="http://other/out">external</a> <a href="/logout">bye</a> <a href="mailto:a@b">m</a>
                <script src="/js/app.js"></script><img srcset="/img/a.png 1x, /img/b.png 2x">
                <form action="/search" method="get"><input name=q><input type=submit name=go value=Search></form>
                <form action="/guestbook" method="post"><textarea name="message"></textarea><input type="hidden" name="csrf" value="t0k"></form>
                <!-- <a href="/commented">hidden</a> -->
                </body></html>
                """),
        "/app/page1": .init(
            body: "<meta http-equiv='refresh' content='0; url=/next'><a href='../app/page1'>self</a>"),
        "/about?id=2&utm_source=x": .init(body: "<a href='/about?id=2'>same page</a>"),
        "/css/site.css": .init(
            type: "text/css", body: "body{background:url('/img/bg.png')} @import '/css/more.css';"),
        "/js/app.js": .init(
            type: "application/javascript",
            body: "fetch('/api/items?limit=5'); const x = \"/static/logo.svg\";"),
        "/next": .init(status: 302, body: "", headers: ["Location: /final"]),
        "/robots.txt": .init(
            type: "text/plain", body: "User-agent: *\nDisallow: /private/\nSitemap: http://lab/sitemap.xml\n"),
        "/sitemap.xml": .init(
            type: "application/xml", body: "<urlset><url><loc>http://lab/from-sitemap</loc></url></urlset>"),
    ])

    func crawl(_ config: CrawlConfig, site: FakeSite = site) async -> CrawlReport {
        let crawler = Crawler(config: config, send: site.sender) { target, _ in target.host == "lab" }
        var report: CrawlReport?
        for await event in await crawler.start() {
            if case .finished(let done) = event { report = done }
        }
        return report ?? CrawlReport()
    }

    @Test(
        "CRL-001/002/005: links of every kind, robots and sitemap hints; scope and the destructive guard hold"
    )
    func test_CRL001_CRL002_crawl() async {
        let site = FakeSite(Self.site.pages)
        let report = await crawl(CrawlConfig(seeds: ["http://lab/"], concurrency: 3), site: site)
        let urls = Set(report.pages.map(\.url))
        for expected in [
            "http://lab/", "http://lab/app/page1", "http://lab/about?utm_source=x&id=2",
            "http://lab/css/site.css",
            "http://lab/js/app.js", "http://lab/img/a.png", "http://lab/img/b.png", "http://lab/img/bg.png",
            "http://lab/css/more.css", "http://lab/api/items?limit=5", "http://lab/static/logo.svg",
            "http://lab/next",
            "http://lab/final", "http://lab/robots.txt", "http://lab/private/", "http://lab/sitemap.xml",
            "http://lab/from-sitemap", "http://lab/search?q=gulp&go=Search",
        ] {
            #expect(urls.contains(expected), "missing \(expected)")
        }
        #expect(!site.requested.contains { $0.contains("other") })  // CRL-001: never fetched
        #expect(report.outOfScope == ["http://other/out"])
        #expect(report.excluded == ["http://lab/logout"])
        #expect(!urls.contains("http://lab/commented"))
        #expect(!site.requested.contains { $0.hasPrefix("POST") })  // POST forms need "submit forms"
        // CRL-003: `/about?id=2` (tracking parameter dropped) and `../app/page1` are duplicates.
        #expect(report.pages.filter { $0.url.contains("/about") }.count == 1)
        #expect(report.pages.filter { $0.url.hasSuffix("/app/page1") }.count == 1)
        #expect(report.forms.count == 2 && report.formsSubmitted == 1)
        // CRL-009: parameters.
        let names = Set(report.parameters.map { "\($0.location):\($0.name)" })
        #expect(names.isSuperset(of: ["query:q", "query:go", "query:limit", "query:id"]))
        #expect(report.stopReason == "done")
    }

    @Test("CRL-001: scope is checked when a URL is fetched, so a scope narrowed mid-crawl holds")
    func test_CRL001_scopeCheckedAtFetch() async {
        let site = FakeSite([
            "/": .init(body: "<a href='/a'>a</a> <a href='/b'>b</a>"), "/a": .init(), "/b": .init(),
        ])
        // Both links are queued while in scope; fetching /a narrows the scope (e.g. the user adds an
        // exclude rule), so the already-queued /b must not go out. One lane keeps the order fixed.
        let narrowed = NIOLockedValueBox(false)
        let crawler = Crawler(
            config: CrawlConfig(seeds: ["http://lab/"], concurrency: 1, useRobotsAndSitemap: false),
            send: { request, target in
                if request.bytes[request.parsed.target].string() == "/a" {
                    narrowed.withLockedValue { $0 = true }
                }
                return await site.sender(request, target)
            }, inScope: { _, _ in !narrowed.withLockedValue { $0 } })
        var report = CrawlReport()
        for await event in await crawler.start() { if case .finished(let done) = event { report = done } }
        #expect(site.requested == ["GET lab/", "GET lab/a"])
        #expect(report.outOfScope == ["http://lab/b"])
        #expect(report.pages.map(\.url) == ["http://lab/", "http://lab/a"])
    }

    @Test(
        "CRL-004: \"submit forms\" posts the guestbook with filled values; obeying robots skips disallowed paths"
    )
    func test_CRL004_forms() async {
        let site = FakeSite(Self.site.pages)
        var config = CrawlConfig(seeds: ["http://lab/"], forms: .all)
        config.obeyRobots = true
        let report = await crawl(config, site: site)
        #expect(site.requested.contains("POST lab/guestbook"))
        #expect(report.pages.contains { $0.method == "POST" && $0.url == "http://lab/guestbook" })
        #expect(!report.pages.contains { $0.url == "http://lab/private/" })
        #expect(report.excluded.contains("http://lab/private/"))
        let filler = FormFiller()
        let form = report.forms.first { $0.method == "POST" }!
        #expect(FormFiller.encode(filler.values(for: form)) == "message=gulp&csrf=t0k")
        let deleteForm = HTMLForm(
            action: "http://lab/account/delete", method: "POST", enctype: "application/x-www-form-urlencoded",
            fields: [], page: "http://lab/")
        #expect(!filler.shouldSubmit(deleteForm, policy: .all))
    }

    @Test("CRL-003/007/008: depth, page budget and similar-page caps stop infinite spaces")
    func test_CRL007_budgets() async {
        // A calendar: every page links to the next day, with the same structure.
        var pages: [String: FakeSite.Page] = [:]
        for day in 0..<500 {
            pages["/cal?d=\(day)"] = .init(body: "<div><a href='/cal?d=\(day + 1)'>next</a></div>")
        }
        let calendar = FakeSite(pages)
        var config = CrawlConfig(seeds: ["http://lab/cal?d=0"], useRobotsAndSitemap: false)
        config.similarPages = 5
        let similar = await crawl(config, site: calendar)
        #expect(similar.pages.count == 6)  // 5 followed + the 6th fetched but not followed
        config.similarPages = 0
        config.maxDepth = 3
        #expect(await crawl(config, site: calendar).pages.count == 4)
        config.maxDepth = 100
        config.maxPages = 10
        let budget = await crawl(config, site: calendar)
        #expect(budget.pages.count == 10 && budget.stopReason == "max pages")
    }

    @Test(
        "CRL-006: a logged-out response triggers re-authentication and a retry; repeated failure stops the crawl"
    )
    func test_CRL006_reauth() async {
        actor Session: CrawlSessionHandler {
            var logins = 0
            let succeed: Bool
            init(succeed: Bool) { self.succeed = succeed }
            nonisolated func isLoggedOut(_ exchange: Exchange) async -> Bool {
                exchange.response?.parsed.statusCode == 401 && exchange.request.headerValue("cookie") == nil
            }
            func reauthenticate() async -> Bool {
                logins += 1
                return succeed
            }
        }
        let site = FakeSite([
            "/": .init(body: "<a href=/a>a</a><a href=/b>b</a><a href=/c>c</a>"),
            "/a": .init(status: 401), "/b": .init(status: 401), "/c": .init(status: 401),
        ])
        let failing = Session(succeed: false)
        let crawler = Crawler(
            config: CrawlConfig(seeds: ["http://lab/"], concurrency: 1, useRobotsAndSitemap: false),
            send: site.sender,
            inScope: { _, _ in true }, session: failing)
        var report = CrawlReport()
        for await event in await crawler.start() { if case .finished(let done) = event { report = done } }
        #expect(report.stopReason == "session not established")
        #expect(await failing.logins == 3)
        #expect(report.authEvents.filter { $0.hasPrefix("logged out") }.count == 3)
    }

    @Test(
        "CRL-003: normalization — default ports, fragments, dot segments, trailing slash, sorted and ignored params"
    )
    func test_CRL003_normalize() {
        let options = NormalizationOptions()
        func key(_ url: String) -> String? { CrawlURL(url)?.key(options) }
        #expect(key("HTTP://Lab:80/a/./b/../c/#frag") == "http://lab/a/c")
        #expect(key("https://lab:443/x?b=2&a=1&utm_source=z&_=123") == "https://lab/x?a=1&b=2")
        #expect(key("http://lab:8088/") == "http://lab:8088/")
        #expect(key("http://[::1]:9/p") == "http://[::1]:9/p")
        #expect(key("ftp://lab/") == nil)
        #expect(CrawlURL("http://lab/a/b/c?x=1")?.directory == "/a/b/")
    }

    @Test("CRL-005: robots rules (prefix, wildcards, longest match) and hint paths")
    func test_CRL005_robots() {
        let robots = RobotsHints(
            "User-agent: *\nDisallow: /admin\nAllow: /admin/public\nDisallow: /*.bak$\nSitemap: http://lab/s.xml # map"
        )
        #expect(robots.disallows("/admin/users") && !robots.disallows("/admin/public/x"))
        #expect(robots.disallows("/db.bak") && !robots.disallows("/db.bak.txt"))
        #expect(robots.hintPaths == ["/admin/public", "/admin"] && robots.sitemaps == ["http://lab/s.xml"])
    }
}
