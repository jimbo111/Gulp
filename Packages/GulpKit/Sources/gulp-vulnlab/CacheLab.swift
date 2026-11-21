// gulp-vulnlab — web cache poisoning & deception fixtures (F28 WCP-002/003). `/cache/poison` is a
// URL-keyed cache: the FIRST request for a URL is computed (reflecting an unkeyed `X-Forwarded-Host`
// into the body) and stored; later requests for the same URL are served the stored copy regardless of
// their headers — so a header-less victim gets the poison a prior request planted (WCP-002's clean
// follow-up). The `/safe/` twin never reflects the header, so there is nothing to cache. `/cache/acct`
// is private content that the vulnerable app also serves — cacheable — at a static-looking suffix
// (`.css`), landing private data in a shared cache (WCP-003 deception); the safe twin stays no-store.

import Foundation
import GulpCore

enum CacheLab {
    /// A tiny URL-keyed response cache (what a shared CDN would do), reset per process.
    private static let cache = CacheStore()

    static func respond(_ request: RawRequest, path: String, query: [String: String]) -> VulnReply? {
        let (route, safe) = SafeTwin.split(path)

        switch route {
        case "/cache/poison":
            // Cache keyed on the full request target (path and query, like a CDN's default key), not
            // on the header. A request that carries the unkeyed `X-Forwarded-Host` reflects it AND
            // fills the cache (the poisoning request); a later request for the same URL *without* the
            // header is served that cached, poisoned copy (the victim) — the whole point of WCP-002.
            // The safe twin never reflects the header and never caches anything attacker-controlled.
            let key = request.bytes[request.parsed.target].string()
            let forwarded = request.headerValue("x-forwarded-host")?.string()
            func page(_ host: String) -> String { "<script src=\"https://\(host)/app.js\"></script>\n" }
            if let forwarded, !safe {
                let body = page(forwarded)
                cache.set(key, body)  // the poisoning request fills the shared cache
                return VulnReply(
                    bytes: VulnLab.response(
                        200, body: Array(body.utf8), type: "text/html; charset=utf-8",
                        headers: ["Cache-Control: public, max-age=60", "X-Cache: MISS"]))
            }
            if !safe, let hit = cache.get(key) {
                return VulnReply(
                    bytes: VulnLab.response(
                        200, body: Array(hit.utf8), type: "text/html; charset=utf-8",
                        headers: ["Cache-Control: public, max-age=60", "X-Cache: HIT"]))
            }
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: Array(page("cdn.vulnlab.test").utf8), type: "text/html; charset=utf-8",
                    headers: ["Cache-Control: public, max-age=60", "X-Cache: MISS"]))

        case let r where r.hasPrefix("/cache/acct"):
            // Private account content. The vulnerable app serves it cacheable when the path carries a
            // static-looking suffix (the CDN caches by extension — deception); the safe app is always
            // no-store, so the suffix never makes private content cacheable.
            let body = "{\"user\":\"alice\",\"Balance:\":\"$4,210.00\",\"account_number\":\"00012345\"}\n"
            let looksStatic =
                r.hasSuffix(".css") || r.hasSuffix(".js") || r.contains(".css") || r.contains(".js")
            let cacheControl = (!safe && looksStatic) ? "public, max-age=120" : "private, no-store"
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: Array(body.utf8), type: "application/json",
                    headers: ["Cache-Control: \(cacheControl)"]))

        default:
            return nil
        }
    }
}

/// A process-wide URL→body cache (thread-safe), emulating a shared CDN for the poison fixture.
private final class CacheStore: @unchecked Sendable {
    // @unchecked: `map` is only touched while holding `lock`.
    private let lock = NSLock()
    private var map: [String: String] = [:]
    func get(_ key: String) -> String? { lock.withLock { map[key] } }
    func set(_ key: String, _ value: String) { lock.withLock { if map[key] == nil { map[key] = value } } }
}
