import Foundation
import GulpCore
import Testing

@testable import GulpScanner

// F08 §3.4/§3.5 precision: each test pairs a false positive that must stay quiet with the true
// positive that must still be found, against a small in-process app. Time is simulated as in
// ActiveScanTests (the app reports the seconds a real server would have taken).

/// The app's mutable state: a request counter, a URL-keyed shared cache and a guestbook.
actor AccuracyState {
    var requests = 0
    var cache: [String: String] = [:]
    var messages: [String] = []

    func count() -> Int {
        requests += 1
        return requests
    }

    func cached(_ key: String) -> String? { cache[key] }

    func store(_ key: String, _ body: String) { cache[key] = cache[key] ?? body }

    func sign(_ message: String) { messages.append(message) }
}

/// Vulnerable routes and their safe twins (`safe: true`) for the accuracy tests.
struct AccuracyApp: Sendable {
    var safe = false
    /// Extra seconds the very first request takes (a cold start).
    var coldStart: Double = 0
    let state = AccuracyState()

    func respond(_ request: RawRequest) async -> (RawResponse, Double) {
        let cold = await state.count() == 1 ? coldStart : 0
        let derived = DerivedFields(
            target: HTTPTarget(scheme: .http, host: "app.test"), request: request, response: nil)
        var query: [String: String] = [:]
        for pair in (derived.query ?? "").split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            let value = parts.count > 1 ? parts[1] : ""
            query[parts[0]] = value.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? value
        }
        let q = query["q"] ?? ""
        switch derived.path ?? "/" {
        case "/ping":
            let host = query["host"] ?? ""
            var seconds = 0.01 + cold
            if !safe, let range = host.range(of: #"sleep (\d+)"#, options: .regularExpression) {
                seconds += Double(host[range].split(separator: " ")[1]) ?? 0
            }
            return (FakeApp.text("PING ok"), seconds)
        case "/login":
            // Echoes `returnUrl` into a link and mentions `location` in a script: no redirect at all.
            let back = query["returnUrl"] ?? ""
            return (
                FakeApp.html(
                    "<a href=\"/next?returnUrl=\(back)\">Continue</a><script>var q = location.search;</script>"
                ),
                0.01
            )
        case "/jsgo":
            let next = safe ? "/home" : query["next"] ?? ""
            return (FakeApp.html("<script>window.location.href = \"\(next)\";</script>"), 0.01)
        case "/meta":
            let next = safe ? "/home" : query["next"] ?? ""
            return (FakeApp.html("<meta http-equiv=\"refresh\" content=\"0; url=\(next)\">"), 0.01)
        case "/xss/url1":
            return (FakeApp.html("<a href='\(safe ? Self.link(q) : q)'>go</a>"), 0.01)
        case "/xss/url0":
            return (FakeApp.html("<a href=\(safe ? Self.link(q) : q)>go</a>"), 0.01)
        case "/xss/urltext":
            // A sanitized link plus a text echo that leaves quotes alone (harmless in a text node).
            let text = q.replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(
                of: ">", with: "&gt;")
            return (FakeApp.html("<a href=\"\(Self.link(q))\">go</a><p>Your link: \"\(text)\"</p>"), 0.01)
        case "/xss/json":
            // An HTML link for plain values; anything else is rejected as JSON that echoes it.
            if q.allSatisfy({ $0.isLetter || $0.isNumber }) {
                return (FakeApp.html("<a href=\"\(q)\">go</a>"), 0.01)
            }
            return (
                FakeApp.response(
                    400, headers: ["Content-Type: application/json"], body: #"{"bad":"\#(q)"}"#), 0.01
            )
        case "/cache-shared":
            // A shared cache keyed on the full request target: a request carrying the unkeyed
            // X-Forwarded-Host reflects it and fills the entry; later requests for that URL get it.
            let key = request.bytes[request.parsed.target].string()
            let page = { (host: String) in "<script src=\"https://\(host)/app.js\"></script>" }
            let body: String
            if !safe, let forwarded = request.headerValue("x-forwarded-host")?.string() {
                body = page(forwarded)
                await state.store(key, body)
            } else {
                body = await state.cached(key) ?? page("app.test")
            }
            return (FakeApp.response(200, headers: ["Cache-Control: public, max-age=60"], body: body), 0.01)
        case "/me", "/me-unverified":
            // `/me` verifies the HS256 signature (the vulnerable twin also takes alg:none);
            // `/me-unverified` takes any non-empty signature. Both reject a missing token.
            let token = (request.headerValue("authorization")?.string() ?? "").replacingOccurrences(
                of: "Bearer ", with: "")
            let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            let header = parts.first.flatMap { Data(base64Encoded: FakeApp.pad($0)) }
                .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            let alg = (header?["alg"] as? String ?? "").lowercased()
            let signed = derived.path == "/me" ? parts.last == "c2ln" : parts.last?.isEmpty == false
            let valid = parts.count == 3 && (alg == "hs256" ? signed : alg == "none" && !safe)
            return (
                valid ? FakeApp.text(#"{"user":"alice"}"#) : FakeApp.response(401, headers: [], body: "no"),
                0.01
            )
        case "/guestbook":
            // POST stores the message; every page renders them unencoded.
            if request.bytes[request.parsed.method].string() == "POST" {
                let form = request.bytes[request.parsed.body].string()
                await state.sign(
                    form.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? form)
            }
            return (FakeApp.html(await state.messages.joined(separator: "<br>")), 0.01)
        case "/public":
            return (FakeApp.text(#"{"news":[]}"#), 0.01)  // never looks at the token
        case let path where path.hasPrefix("/account"):
            // Private for the signed-in user; the vulnerable app lets a CDN cache it at a static-looking path.
            guard request.headerValue("cookie")?.string() == "s=1" else {
                return (
                    FakeApp.response(200, headers: ["Cache-Control: no-store"], body: "Please log in"), 0.01
                )
            }
            let control = !safe && path != "/account" ? "public, max-age=120" : "private, no-store"
            return (
                FakeApp.response(
                    200, headers: ["Cache-Control: \(control)"], body: #"{"email":"a@app.test"}"#), 0.01
            )
        case let path where path.hasPrefix("/banner"):
            // Never cacheable when signed in; the signed-out page is public and greets everyone.
            if request.headerValue("cookie")?.string() == "s=1" {
                return (
                    FakeApp.response(200, headers: ["Cache-Control: no-store"], body: "Welcome back, alice"),
                    0.01
                )
            }
            return (
                FakeApp.response(
                    200, headers: ["Cache-Control: public, max-age=60"],
                    body: "Welcome back! Sign in to continue."),
                0.01
            )
        default:
            return (FakeApp.response(404, headers: [], body: "not found"), 0.01)
        }
    }

    /// A link target that only keeps http(s) URLs and plain words, HTML-encoded.
    static func link(_ value: String) -> String {
        let allowed =
            value.hasPrefix("http://") || value.hasPrefix("https://")
            || value.allSatisfy { $0.isLetter || $0.isNumber }
        return allowed ? FakeApp.escape(value) : "#"
    }
}

/// Scan `requests` against `app`. With `pointsOnly`, request-level checks don't run (so the first
/// request the app sees is the insertion point's baseline).
func scanApp(
    _ requests: [RawRequest], app: AccuracyApp, config: ScanConfig = .preset(.balanced),
    pointsOnly: Bool = false
) async -> [IssueFinding] {
    let target = HTTPTarget(scheme: .http, host: "app.test")
    let everyPoint: @Sendable (InsertionPoint) -> Bool = { _ in true }
    let scan = ActiveScan(
        requests: requests.map { ($0, target) }, config: config,
        send: { request, _ in
            let (response, seconds) = await app.respond(request)
            return Probe(request: request, response: response, exchangeID: 0, seconds: seconds)
        }, inScope: { _, _ in true }, points: pointsOnly ? everyPoint : nil)
    var findings: [IssueFinding] = []
    for await event in await scan.start() {
        if case .finding(let finding) = event { findings.append(finding) }
    }
    return findings
}

@Suite("Scanner accuracy (F08 §3.4, §3.5)")
struct ScannerAccuracyTests {
    @Test("SCN-032: a value with % format characters is sent literally and its time-based injection found")
    func test_SCN032_formatCharactersInValue() async {
        let findings = await scanApp([get("/ping?host=10%25%40%25d%25s")], app: AccuracyApp())
        #expect(findings.contains { $0.typeID == "active.cmd.time" }, "\(pairs(findings))")
    }

    @Test("SCN-032: one slow (cold) baseline request does not hide a time-based injection")
    func test_SCN032_coldBaselineDoesNotHideDelay() async {
        let findings = await scanApp(
            [get("/ping?host=127.0.0.1")], app: AccuracyApp(coldStart: 6), pointsOnly: true)
        #expect(findings.contains { $0.typeID == "active.cmd.time" }, "\(pairs(findings))")
        let safe = await scanApp(
            [get("/ping?host=127.0.0.1")], app: AccuracyApp(safe: true, coldStart: 6), pointsOnly: true)
        #expect(!safe.contains { $0.typeID.hasSuffix(".time") }, "\(pairs(safe))")
    }

    @Test(
        "SCN-030 §3.4: a reflected returnUrl is not a client-side redirect; meta refresh and JS location are")
    func test_SCN030_clientSideRedirectNeedsARealRedirect() async {
        let reflected = await scanApp([get("/login?returnUrl=/home")], app: AccuracyApp())
        #expect(!reflected.contains { $0.typeID == "active.open-redirect" }, "\(pairs(reflected))")
        for path in ["/jsgo?next=/home", "/meta?next=/home"] {
            let found = await scanApp([get(path)], app: AccuracyApp())
            #expect(
                found.contains { $0.typeID == "active.open-redirect" && $0.variant == "client-side" },
                "\(path): \(pairs(found))")
            let safe = await scanApp([get(path)], app: AccuracyApp(safe: true))
            #expect(!safe.contains { $0.typeID == "active.open-redirect" }, "safe \(path): \(pairs(safe))")
        }
    }

    @Test("SCN-030 §3.4: URL-context XSS uses the attribute's own quoting and is confirmed at the reflection")
    func test_SCN030_urlContextXSS() async {
        for path in ["/xss/url1?q=hello", "/xss/url0?q=hello"] {
            let found = await scanApp([get(path)], app: AccuracyApp())
            #expect(
                found.contains { $0.typeID == "active.xss.reflected" && $0.variant == "url" },
                "\(path): \(pairs(found))")
            let safe = await scanApp([get(path)], app: AccuracyApp(safe: true))
            #expect(!safe.contains { $0.typeID == "active.xss.reflected" }, "safe \(path): \(pairs(safe))")
        }
        // The breakout only shows up in a text node, or in a JSON error: neither is the URL context.
        for path in ["/xss/urltext?q=hello", "/xss/json?q=hello"] {
            let quiet = await scanApp([get(path)], app: AccuracyApp())
            #expect(!quiet.contains { $0.typeID == "active.xss.reflected" }, "\(path): \(pairs(quiet))")
        }
    }
}

@Suite("Unsafe gate (F08 SCN-038, §6)")
struct UnsafeGateTests {
    @Test("SCN-038: stored XSS writes data, so it runs only with the unsafe gate")
    func test_SCN038_storedXSSIsUnsafeGated() async {
        let request = post("/guestbook", type: "application/x-www-form-urlencoded", body: "message=hello")
        let gated = await scanApp([request], app: AccuracyApp())
        #expect(!gated.contains { $0.typeID == "active.xss.stored" }, "\(pairs(gated))")
        var unsafe = ScanConfig.preset(.balanced)
        unsafe.unsafe = true
        let found = await scanApp([request], app: AccuracyApp(), config: unsafe)
        #expect(found.contains { $0.typeID == "active.xss.stored" }, "\(pairs(found))")
    }
}

@Suite("JWT check accuracy (F08 SCN-074)")
struct JWTAccuracyTests {
    /// `Bearer` header with an HS256 token for alice whose signature the fake app accepts (`c2ln`).
    static let bearer: String = {
        func b64(_ s: String) -> String {
            Data(s.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        return
            "Authorization: Bearer \(b64(#"{"alg":"HS256","typ":"JWT"}"#)).\(b64(#"{"user":"alice"}"#)).c2ln"
    }()

    @Test("SCN-074: an endpoint that ignores the token is not an alg:none finding; real ones still are")
    func test_SCN074_jwtNegativeControls() async {
        let ignored = await scanApp([get("/public", extra: [Self.bearer])], app: AccuracyApp())
        #expect(!ignored.contains { $0.typeID == "active.jwt" }, "\(pairs(ignored))")
        let algNone = await scanApp([get("/me", extra: [Self.bearer])], app: AccuracyApp())
        #expect(
            algNone.contains { $0.typeID == "active.jwt" && $0.variant == "alg:none" }, "\(pairs(algNone))")
        let safe = await scanApp([get("/me", extra: [Self.bearer])], app: AccuracyApp(safe: true))
        #expect(!safe.contains { $0.typeID == "active.jwt" }, "\(pairs(safe))")
        let unverified = await scanApp([get("/me-unverified", extra: [Self.bearer])], app: AccuracyApp())
        #expect(
            unverified.contains { $0.typeID == "active.jwt" && $0.variant == "unverified signature" },
            "\(pairs(unverified))")
    }
}

/// The balanced preset with the opt-in cache family enabled (F08 §3.5).
func withCacheFamily() -> ScanConfig {
    var config = ScanConfig.preset(.balanced)
    config.disabledFamilies.remove("cache-poisoning")
    return config
}

@Suite("Cache poisoning & deception accuracy (F08 §3.5)")
struct CacheAccuracyTests {
    @Test("WCP-007/002: cache poisoning is opt-in, and its probes use a cache-buster no victim requests")
    func test_WCP002_optInAndCacheBuster() async {
        let app = AccuracyApp()
        let defaults = await scanApp([get("/cache-shared")], app: app)
        #expect(!defaults.contains { $0.typeID.hasPrefix("active.cache-") }, "\(pairs(defaults))")
        let found = await scanApp([get("/cache-shared")], app: app, config: withCacheFamily())
        #expect(
            found.contains { $0.typeID == "active.cache-poisoning" && $0.variant == "confirmed-cached" },
            "\(pairs(found))")
        // A real user's request for the page (no cache-buster) is served the clean page.
        let (victim, _) = await app.respond(get("/cache-shared"))
        #expect(!victim.bytes.string().contains(".gulp-ca"), "\(victim.bytes.string())")
        let safe = await scanApp(
            [get("/cache-shared")], app: AccuracyApp(safe: true), config: withCacheFamily())
        #expect(!safe.contains { $0.typeID == "active.cache-poisoning" }, "\(pairs(safe))")
    }

    @Test("WCP-003: cache deception keeps the request's credentials; a public greeting isn't deception")
    func test_WCP003_deceptionKeepsCredentials() async {
        let account = get("/account", extra: ["Cookie: s=1"])
        let found = await scanApp([account], app: AccuracyApp(), config: withCacheFamily())
        #expect(found.contains { $0.typeID == "active.cache-deception" }, "\(pairs(found))")
        let safe = await scanApp([account], app: AccuracyApp(safe: true), config: withCacheFamily())
        #expect(!safe.contains { $0.typeID == "active.cache-deception" }, "\(pairs(safe))")
        let banner = await scanApp(
            [get("/banner", extra: ["Cookie: s=1"])], app: AccuracyApp(), config: withCacheFamily())
        #expect(!banner.contains { $0.typeID == "active.cache-deception" }, "\(pairs(banner))")
    }
}
