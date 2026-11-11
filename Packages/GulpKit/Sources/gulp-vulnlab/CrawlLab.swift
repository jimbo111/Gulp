// gulp-vulnlab — the crawl lab (F09 acceptance 1, M11a DoD) and the blind SSRF that calls the dev
// Beacon (doc 06 §3, F10 acceptance 1).
//
// `/crawl/` links every kind of reference the static crawler must follow (anchors, a stylesheet with
// `url()`, a script with a fetch string, an image, an iframe whose page meta-refreshes, a GET form,
// robots.txt and sitemap.xml hints, a JSON body with a path, a redirect, a paginated chain), plus a
// logout link the crawler must never fetch and two out-of-scope links (another host name for the
// same listener, and an external host). `Tests/Fixtures/vulnlab-crawl.txt` lists every in-scope
// route a crawl of `http://127.0.0.1:8088/` must reach.

import Foundation
import GulpCore
import NIOCore
import NIOPosix

enum CrawlLab {
    static let page = """
        <!doctype html>
        <html><head><title>Crawl lab</title>
        <link rel="stylesheet" href="/crawl/style.css"><script src="/crawl/app.js"></script></head>
        <body><h1>Crawl lab</h1>
        <ul>
        <li><a href="page/1">Pages</a></li>
        <li><a href="/crawl/moved">Moved</a></li>
        <li><img src="/crawl/logo.png" alt="logo"></li>
        <li><iframe src="/crawl/frame"></iframe></li>
        <li><a href="/crawl/logout">Log out</a></li>
        <li><a href="http://localhost:8088/crawl/elsewhere">Same server, other name (out of scope)</a></li>
        <li><a href="http://example.invalid/">External (out of scope)</a></li>
        </ul>
        <form action="/crawl/search" method="get"><input name="q"><button type="submit">Search</button></form>
        </body></html>

        """

    static let png: [UInt8] = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00,
        0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00,
        0x00,
        0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A,
        0x2D,
        0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ]

    static func html(_ body: String) -> VulnReply {
        VulnReply(
            bytes: VulnLab.response(
                200, body: Array("<!doctype html><html><body>\(body)</body></html>".utf8),
                type: "text/html; charset=utf-8"))
    }

    /// The crawl lab's routes; nil for other paths.
    static func respond(_ path: String, _ query: [String: String]) -> VulnReply? {
        switch path {
        case "/robots.txt":
            return VulnReply(
                bytes: VulnLab.response(
                    200,
                    body: Array(
                        "User-agent: *\nDisallow: /crawl/hidden-by-robots\nSitemap: http://127.0.0.1:8088/sitemap.xml\n"
                            .utf8),
                    type: "text/plain"))
        case "/sitemap.xml":
            return VulnReply(
                bytes: VulnLab.response(
                    200,
                    body: Array(
                        "<?xml version=\"1.0\"?><urlset><url><loc>http://127.0.0.1:8088/crawl/from-sitemap</loc></url></urlset>"
                            .utf8), type: "application/xml"))
        case "/crawl", "/crawl/":
            return VulnReply(
                bytes: VulnLab.response(200, body: Array(page.utf8), type: "text/html; charset=utf-8"))
        case "/crawl/slow/":
            // Slow pages for the limiter drills (not linked from /crawl/): 60 links, 400 ms each.
            return html((1...60).map { "<a href='/slow?ms=400&page=\($0)'>\($0)</a>" }.joined(separator: " "))
        case "/crawl/page/1": return html("<a href='/crawl/page/2'>next</a>")
        case "/crawl/page/2": return html("<a href='/crawl/page/3'>next</a>")
        case "/crawl/page/3": return html("<a href='/crawl/deep'>deep</a>")
        case "/crawl/moved":
            return VulnReply(bytes: VulnLab.response(302, body: [], headers: ["Location: /crawl/landed"]))
        case "/crawl/style.css":
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: Array("body { background: url('/crawl/bg.png') }".utf8), type: "text/css"))
        case "/crawl/app.js":
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: Array("fetch('/crawl/api/data').then(r => r.json());".utf8),
                    type: "application/javascript"))
        case "/crawl/api/data":
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: Array(#"{"next":"/crawl/api/more"}"#.utf8), type: "application/json"))
        case "/crawl/api/more":
            return VulnReply(
                bytes: VulnLab.response(200, body: Array(#"{"done":true}"#.utf8), type: "application/json"))
        case "/crawl/logo.png", "/crawl/bg.png":
            return VulnReply(bytes: VulnLab.response(200, body: png, type: "image/png"))
        case "/crawl/frame":
            return VulnReply(
                bytes: VulnLab.response(
                    200,
                    body: Array(
                        "<html><head><meta http-equiv='refresh' content='0; url=/crawl/refreshed'></head></html>"
                            .utf8),
                    type: "text/html"))
        case "/crawl/search":
            let term = query["q"] ?? ""
            return html(
                "Results for \(term.isEmpty ? "nothing" : "a term"): <a href='/crawl/result?id=1'>result 1</a>"
            )
        case "/crawl/logout":
            // Never fetched by the crawler (destructive-link guard); a fetch here is a crawler bug.
            return html("Logged out.")
        case "/crawl/landed", "/crawl/deep", "/crawl/refreshed", "/crawl/result", "/crawl/from-sitemap",
            "/crawl/hidden-by-robots":
            return html("\(path)")
        default:
            return nil
        }
    }
}

/// Blind SSRF (doc 06 §3): `/fetch?url=` really fetches only the dev Beacon's domain — a DNS lookup
/// and an HTTP GET to the Beacon — and answers at once without the fetched content, so only an OAST
/// interaction reveals it. Anything else is simulated. `/safe/fetch` refuses hosts outside its
/// allowlist and never fetches.
enum OASTLab {
    static let environment = ProcessInfo.processInfo.environment
    static let domain = (environment["GULP_VULNLAB_BEACON_DOMAIN"] ?? "oast.test").lowercased()
    static let httpAddress = environment["GULP_VULNLAB_BEACON_HTTP"] ?? "127.0.0.1:8090"
    static let dnsAddress = environment["GULP_VULNLAB_BEACON_DNS"] ?? "127.0.0.1:8053"

    static func fetch(_ query: [String: String], safe: Bool) -> VulnReply {
        guard let raw = query["url"], let url = URLComponents(string: raw), let host = url.host?.lowercased()
        else {
            return VulnReply(bytes: VulnLab.response(400, body: Array("url required\n".utf8)))
        }
        if safe {
            guard ["example.com", "www.example.com"].contains(host) else {
                return VulnReply(bytes: VulnLab.response(403, body: Array("host not allowed\n".utf8)))
            }
            return VulnReply(bytes: VulnLab.response(200, body: Array("fetched (simulated)\n".utf8)))
        }
        if host.hasSuffix("." + domain) {
            let path =
                (url.percentEncodedPath.isEmpty ? "/" : url.percentEncodedPath)
                + (url.percentEncodedQuery.map { "?" + $0 } ?? "")
            Task.detached {
                await lookup(host)
                await get(host: host, path: path)
            }
        }
        return VulnReply(bytes: VulnLab.response(200, body: Array("queued\n".utf8)))
    }

    static func split(_ address: String) -> (String, Int)? {
        let parts = address.split(separator: ":")
        guard parts.count == 2, let port = Int(parts[1]) else { return nil }
        return (String(parts[0]), port)
    }

    /// A DNS A query for `host` to the Beacon (fire and forget, 500 ms at most).
    static func lookup(_ host: String) async {
        guard let (address, port) = split(dnsAddress),
            let remote = try? SocketAddress(ipAddress: address, port: port)
        else { return }
        var packet: [UInt8] = [0x47, 0x55, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in host.split(separator: ".") {
            let bytes = Array(label.utf8.prefix(63))
            packet.append(UInt8(bytes.count))
            packet += bytes
        }
        packet += [0, 0, 1, 0, 1]
        guard
            let channel = try? await DatagramBootstrap(group: MultiThreadedEventLoopGroup.singleton)
                .bind(host: "0.0.0.0", port: 0).get()
        else { return }
        let envelope = AddressedEnvelope(remoteAddress: remote, data: channel.allocator.buffer(bytes: packet))
        try? await channel.writeAndFlush(envelope).get()
        try? await Task.sleep(for: .milliseconds(200))
        try? await channel.close().get()
    }

    /// GET `path` with `Host: host` from the Beacon's HTTP listener (2 s at most).
    static func get(host: String, path: String) async {
        guard let (address, port) = split(httpAddress),
            let channel = try? await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
                .connectTimeout(.seconds(2)).connect(host: address, port: port).get()
        else { return }
        let request =
            "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: VulnLab-fetch\r\nConnection: close\r\n\r\n"
        try? await channel.writeAndFlush(channel.allocator.buffer(string: request)).get()
        try? await Task.sleep(for: .milliseconds(500))
        try? await channel.close().get()
    }
}

/// `/lab/burst?key=K&ok=MS&bad=MS` (F03 test 7): per key, 200 for `ok` ms after the first request,
/// then 503 for `bad` ms, then 200 again — a time-boxed 503 burst for the backoff drill.
enum BurstLab {
    private static let starts = NSLockedDictionary()

    static func respond(_ query: [String: String]) -> VulnReply {
        let key = query["key"] ?? "default"
        let ok = Double(query["ok"] ?? "") ?? 1_000
        let bad = Double(query["bad"] ?? "") ?? 2_000
        let elapsed = (Date().timeIntervalSince1970 - starts.start(key)) * 1_000
        let failing = elapsed >= ok && elapsed < ok + bad
        return VulnReply(
            bytes: VulnLab.response(failing ? 503 : 200, body: Array((failing ? "busy\n" : "ok\n").utf8)))
    }
}

/// A key → first-seen time map behind a lock.
final class NSLockedDictionary: @unchecked Sendable {
    // @unchecked: `values` is only touched while holding `lock`.
    private let lock = NSLock()
    private var values: [String: Double] = [:]

    func start(_ key: String) -> Double {
        lock.withLock {
            if let start = values[key] { return start }
            let now = Date().timeIntervalSince1970
            values[key] = now
            return now
        }
    }
}
