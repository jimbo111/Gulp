import Foundation
import GulpCodec
import GulpCore
import Testing

@testable import GulpScanner

// F08 §3.2–§3.4 (M11b): insertion points, the active engine and the P0 checks, run against an
// in-process fake application. Time is simulated (the fake reports the delay a real server would
// have caused), so dose-response timing is tested deterministically and instantly.

/// Records the OAST hosts the fake app "contacted".
actor FakeOAST: OASTProvider {
    var minted = 0
    var hits: Set<String> = []

    func mint(note: String) async -> String? {
        minted += 1
        return "g\(minted)x.oast.test"
    }

    func interactions(forHost host: String) async -> [String] { hits.contains(host) ? ["dns"] : [] }

    func settle(seconds: Double) async {}

    func hit(_ host: String) { hits.insert(host) }
}

/// The shared key→value store the `/pp/merge` prototype-pollution twin writes into. A reference type
/// so a value-type `FakeApp` copy still sees the writes made across the check's three sends, while a
/// fresh `FakeApp()` starts with an empty store (per-scan isolation).
final class PollutionBox: @unchecked Sendable {
    // @unchecked: `store` is only touched while holding `lock`.
    private let lock = NSLock()
    private var store: [String: String] = [:]
    func set(_ key: String, _ value: String) { lock.withLock { store[key] = value } }
    func all() -> [String: String] { lock.withLock { store } }
}

/// A tiny vulnerable application (and its safe twin). Returns the response and the seconds a real
/// server would have taken.
struct FakeApp: Sendable {
    var safe = false
    var oast: FakeOAST?
    /// Delay every request containing "sleep" by a constant (a slow endpoint, not an injection).
    var constantSlowness: Double = 0
    /// Shared mutable store the `/pp/merge` prototype-pollution twin writes into; one per `FakeApp`.
    let pollution = PollutionBox()

    static let products = ["1": "Gulp T-shirt", "2": "Gulp mug"]

    func respond(_ request: RawRequest) async -> (RawResponse, Double) {
        let derived = DerivedFields(
            target: HTTPTarget(scheme: .http, host: "app.test"), request: request, response: nil)
        let path = derived.path ?? "/"
        let raw = derived.query ?? ""
        var query: [String: String] = [:]
        var rawQuery: [String: String] = [:]
        for pair in raw.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            let value = parts.count > 1 ? parts[1] : ""
            rawQuery[parts[0]] = value
            query[parts[0]] = value.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? value
        }
        // OAST: the command route runs lookups/fetches; the fetch route fetches http URLs.
        if let oast, !safe,
            let value = path == "/ping" ? query["host"] : path == "/fetch" ? query["url"] : nil,
            let range = value.range(of: #"g\d+x\.oast\.test"#, options: .regularExpression)
        {
            let command = value.contains("nslookup ") || value.contains("curl ")
            let fetched = value.range(of: #"^https?://g\d+x\.oast\.test"#, options: .regularExpression) != nil
            if path == "/ping" ? command : fetched { await oast.hit(String(value[range])) }
        }
        let slow = query.values.contains { $0.lowercased().contains("sleep") } ? constantSlowness : 0
        switch path {
        case "/search":
            let q = query["q"] ?? ""
            return (Self.html("<p>Results for \(safe ? Self.escape(q) : q)</p>"), 0.01)
        case "/item":
            return (sqli(query["id"] ?? ""), 0.01 + slow)
        case "/tpl":
            let name = query["name"] ?? ""
            return (Self.text("Hello \(safe ? name : Self.evaluate(name))"), 0.01)
        case "/file":
            let name = query["name"] ?? ""
            let traversal = name.contains("../") || name.hasPrefix("/etc/")
            return (Self.text(!safe && traversal ? "root:x:0:0:root:/root:/bin/sh" : "file: \(name)"), 0.01)
        case "/go":
            let next = query["next"] ?? "/"
            // Vulnerable to open redirect only; line breaks are dropped (no header injection here).
            let location = safe ? "/home" : String(next.unicodeScalars.filter { $0 != "\r" && $0 != "\n" })
            return (Self.response(302, headers: ["Location: \(location)"], body: ""), 0.01)
        case "/lang":
            // The vulnerable twin decodes the raw value into a header (CRLF survives).
            let value = rawQuery["l"] ?? ""
            let decoded = safe ? Self.escape(value) : (value.removingPercentEncoding ?? value)
            return (Self.response(200, headers: ["Content-Language: \(decoded)"], body: "ok"), 0.01)
        case "/tpl2":
            return (
                Self.text(query.values.sorted().map { safe ? $0 : Self.evaluate($0) }.joined(separator: ",")),
                0.01
            )
        case "/fetch":
            return (Self.text("fetched"), 0.01)
        case "/cors":
            let origin = request.headerValue("origin")?.string() ?? ""
            let allow = safe ? (origin == "https://trusted.test") : !origin.isEmpty
            let headers =
                allow
                ? ["Access-Control-Allow-Origin: \(origin)", "Access-Control-Allow-Credentials: true"] : []
            return (Self.response(200, headers: headers, body: "{}"), 0.01)
        case "/hosthdr":
            let host = safe ? "app.test" : (request.headerValue("x-forwarded-host")?.string() ?? "app.test")
            return (Self.text("Reset: http://\(host)/r"), 0.01)
        case "/me":
            // JWT auth: the vulnerable twin accepts alg:none; the safe twin requires a real signature.
            let token = (request.headerValue("authorization")?.string() ?? "").replacingOccurrences(
                of: "Bearer ", with: "")
            let segments = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            let headerJSON = segments.first.flatMap { Data(base64Encoded: Self.pad($0)) }
                .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            let alg = (headerJSON?["alg"] as? String ?? "").lowercased()
            let valid =
                safe
                ? (alg == "hs256" && !segments.last!.isEmpty)
                : (alg == "none" || (alg == "hs256" && !segments.last!.isEmpty))
            return (
                valid
                    ? Self.text("{\"user\":\"alice\"}")
                    : Self.response(401, headers: [], body: "unauthorized"), 0.01
            )
        case "/pp/merge":
            // Server-side prototype pollution: the vulnerable twin follows `__proto__` into a shared
            // store and enriches later responses with the inherited keys; the safe twin ignores it.
            let input =
                (try? JSONSerialization.jsonObject(with: Data(request.bytes.rawBytes[request.parsed.body])))
                as? [String: Any] ?? [:]
            if !safe, let proto = input["__proto__"] as? [String: Any] {
                for (key, value) in proto { pollution.set(key, "\(value)") }
            }
            var object = input.filter { $0.key != "__proto__" }
            if !safe { for (key, value) in pollution.all() where object[key] == nil { object[key] = value } }
            let merged =
                (try? JSONSerialization.data(withJSONObject: object)).map {
                    String(decoding: $0, as: UTF8.self)
                } ?? "{}"
            return (Self.response(200, headers: ["Content-Type: application/json"], body: merged), 0.01)
        case "/profile/update":
            let object =
                (try? JSONSerialization.jsonObject(with: Data(request.bytes.rawBytes[request.parsed.body])))
                as? [String: Any] ?? [:]
            let bound = safe ? object.filter { ["name"].contains($0.key) } : object
            let json =
                (try? JSONSerialization.data(withJSONObject: bound)).map {
                    String(decoding: $0, as: UTF8.self)
                } ?? "{}"
            return (Self.response(200, headers: ["Content-Type: application/json"], body: json), 0.01)
        case "/ping":
            let host = query["host"] ?? ""
            var seconds = 0.01 + slow
            if !safe, constantSlowness == 0,
                let range = host.range(of: #"sleep (\d+)"#, options: .regularExpression)
            {
                seconds += Double(host[range].split(separator: " ")[1]) ?? 0
            }
            return (Self.text("PING ok"), seconds)
        default:
            return (Self.response(404, headers: [], body: "not found"), 0.01)
        }
    }

    func sqli(_ id: String) -> RawResponse {
        let product = { (key: String) in
            Self.text(Self.products[key].map { "Product: \($0)" } ?? "No product.")
        }
        if safe { return product(id) }
        let quotes = id.filter { $0 == "'" }.count
        if quotes % 2 == 1, !id.contains("--") {
            return Self.response(500, headers: [], body: "SQLite error: unrecognized token near '\(id)'")
        }
        guard let quote = id.firstIndex(of: "'") else { return product(id) }
        let value = String(id[..<quote])
        let condition = id[id.index(after: quote)...]
        guard let match = condition.firstMatch(of: #/^\s*AND\s+'([^']*)'\s*=\s*'([^']*)$/#) else {
            return product("none")
        }
        return match.1 == match.2 ? product(value) : product("none")
    }

    static func evaluate(_ text: String) -> String {
        guard let match = text.firstMatch(of: #/\{\{(\d+)\*(\d+)\}\}/#), let a = Int(match.1),
            let b = Int(match.2)
        else {
            return text
        }
        return text.replacingCharacters(in: match.range, with: String(a * b))
    }

    static func pad(_ s: String) -> String {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return t
    }

    static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;").replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "%", with: "")
    }

    static func html(_ body: String) -> RawResponse {
        response(
            200, headers: ["Content-Type: text/html; charset=utf-8"],
            body: "<html><body>\(body)</body></html>")
    }

    static func text(_ body: String) -> RawResponse {
        response(200, headers: ["Content-Type: text/plain"], body: body)
    }

    static func response(_ status: Int, headers: [String], body: String) -> RawResponse {
        let head = (["HTTP/1.1 \(status) X"] + headers + ["Content-Length: \(body.utf8.count)"]).joined(
            separator: "\r\n")
        return RawResponse(Bytes(Array((head + "\r\n\r\n" + body).utf8)))
    }
}

func get(_ target: String, extra: [String] = []) -> RawRequest {
    RawRequest(
        Bytes(
            Array((["GET \(target) HTTP/1.1", "Host: app.test"] + extra).joined(separator: "\r\n").utf8)
                + Array("\r\n\r\n".utf8)))
}

func post(_ target: String, type: String, body: String) -> RawRequest {
    let head = [
        "POST \(target) HTTP/1.1", "Host: app.test", "Content-Type: \(type)",
        "Content-Length: \(body.utf8.count)",
    ]
    return RawRequest(Bytes(Array((head.joined(separator: "\r\n") + "\r\n\r\n" + body).utf8)))
}

/// Run a scan of `requests` against `app`; returns the findings and the summary.
func scan(
    _ requests: [RawRequest], app: FakeApp, config: ScanConfig = .preset(.balanced),
    inScope: @escaping @Sendable (HTTPTarget, String) async -> Bool = { _, _ in true }
) async -> (findings: [IssueFinding], summary: ScanSummary?) {
    let target = HTTPTarget(scheme: .http, host: "app.test")
    let scan = ActiveScan(
        requests: requests.map { ($0, target) }, config: config,
        send: { request, _ in
            let (response, seconds) = await app.respond(request)
            return Probe(request: request, response: response, exchangeID: 0, seconds: seconds)
        }, inScope: inScope, oast: app.oast)
    var findings: [IssueFinding] = []
    var summary: ScanSummary?
    for await event in await scan.start() {
        switch event {
        case .finding(let finding): findings.append(finding)
        case .finished(let done): summary = done
        default: break
        }
    }
    return (findings, summary)
}

func pairs(_ findings: [IssueFinding]) -> Set<String> { Set(findings.map { "\($0.path) \($0.typeID)" }) }

let plantedRequests = [
    get("/search?q=shoes"), get("/item?id=1"), get("/tpl?name=bob"), get("/file?name=report.txt"),
    get("/go?next=/home"), get("/lang?l=en"), get("/ping?host=127.0.0.1"),
    get("/fetch?url=http://example.com/"),
]

@Suite("Active scanning (F08 §3.2–§3.4, M11b)")
struct ActiveScanTests {
    @Test("SCN-020: insertion points cover query, cookies, chosen headers, form, JSON, XML and multipart")
    func test_SCN020_insertionPoints() {
        let query = InsertionPoints.derive(
            get("/a?x=1&csrf=t&y=two", extra: ["Cookie: s=abc; t=1", "User-Agent: ua"]))
        let labels = Set(query.map(\.label))
        #expect(
            labels.isSuperset(of: ["url param x", "url param y", "cookie s", "cookie t", "header User-Agent"])
        )
        #expect(!labels.contains("url param csrf"), "framework/CSRF tokens are skipped")
        #expect(
            !query.contains { $0.kind == .pathSegment }, "path segments only when there are no parameters")
        #expect(query.first { $0.name == "y" }?.baseValue == "two")

        let form = InsertionPoints.derive(
            post("/f", type: "application/x-www-form-urlencoded", body: "a=1&b=hello"))
        #expect(Set(form.filter { $0.kind == .bodyParam }.map(\.name)) == ["a", "b"])

        let json = InsertionPoints.derive(
            post("/j", type: "application/json", body: #"{"user":{"name":"ann","age":3}}"#))
        #expect(Set(json.filter { $0.kind == .jsonValue }.map(\.baseValue)).isSuperset(of: ["ann", "3"]))

        let xml = InsertionPoints.derive(post("/x", type: "application/xml", body: "<r><n>v</n></r>"))
        #expect(xml.contains { $0.kind == .xmlValue && $0.baseValue == "v" })
        #expect(xml.contains { $0.kind == .wholeBody })

        let boundary = "XyZ"  // mixed case: boundaries are case-sensitive
        let multipart =
            "--\(boundary)\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n--\(boundary)--\r\n"
        let parts = InsertionPoints.derive(
            post("/m", type: "multipart/form-data; boundary=\(boundary)", body: multipart))
        #expect(parts.contains { $0.kind == .multipartField && $0.name == "note" && $0.baseValue == "hi" })

        let rest = InsertionPoints.derive(get("/api/users/42"))
        #expect(rest.contains { $0.kind == .pathSegment && $0.baseValue == "42" })

        let limited = InsertionPoints.derive(
            get("/a?x=1&y=2&z=3", extra: ["Cookie: s=1"]),
            policy: InsertionPolicy(kinds: [.urlParam], maxPerRequest: 2))
        #expect(limited.count == 2 && limited.allSatisfy { $0.kind == .urlParam })
    }

    @Test("SCN-020: payloads are encoded for their context and Content-Length follows")
    func test_SCN020_buildEncodesAndUpdatesLength() throws {
        let form = post("/f", type: "application/x-www-form-urlencoded", body: "a=1&b=x")
        let point = try #require(InsertionPoints.derive(form).first { $0.name == "a" })
        let built = point.build(form, payload: "1' OR 'a b&")
        let text = String(decoding: built.bytes.rawBytes, as: UTF8.self)
        #expect(text.hasSuffix("\r\n\r\na=1%27%20OR%20%27a%20b%26&b=x"))
        #expect(text.contains("Content-Length: \("a=1%27%20OR%20%27a%20b%26&b=x".utf8.count)\r\n"))

        let json = post("/j", type: "application/json", body: #"{"q":"x"}"#)
        let jsonPoint = try #require(InsertionPoints.derive(json).first { $0.kind == .jsonValue })
        let jsonText = String(
            decoding: jsonPoint.build(json, payload: #"a"b\c"#).bytes.rawBytes, as: UTF8.self)
        #expect(jsonText.hasSuffix(#"{"q":"a\"b\\c"}"#), "JSON strings stay valid")

        // Raw bytes elsewhere are untouched (CLAUDE.md: raw bytes are the truth).
        let odd = RawRequest(
            Bytes(Array("GET /a?x=1 HTTP/1.1\r\nHost: app.test\r\nX-Odd:  spaced \r\n\r\n".utf8)))
        let oddPoint = try #require(InsertionPoints.derive(odd).first { $0.name == "x" })
        #expect(
            String(decoding: oddPoint.build(odd, payload: "2").bytes.rawBytes, as: UTF8.self).contains(
                "X-Odd:  spaced \r\n"))
    }

    @Test("SCN-030…033: every planted vulnerability is found, with OAST and dose-response timing")
    func test_SCN030_findsPlanted() async {
        let oast = FakeOAST()
        let (findings, summary) = await scan(plantedRequests, app: FakeApp(oast: oast))
        let found = pairs(findings)
        let expected: Set<String> = [
            "/search active.xss.reflected", "/item active.sqli.error", "/item active.sqli.boolean",
            "/tpl active.ssti", "/file active.path-traversal", "/go active.open-redirect",
            "/lang active.crlf",
            "/ping active.cmd.time", "/ping active.cmd.oast", "/fetch active.ssrf.oast",
        ]
        #expect(
            found == expected,
            "missing: \(expected.subtracting(found)), unexpected: \(found.subtracting(expected))")
        #expect(summary?.stopReason == "done")
        #expect(summary?.findings == findings.count)
        // Evidence: response markers point at the proof.
        let xss = findings.first { $0.typeID == "active.xss.reflected" }
        #expect(xss?.evidence.responseMarkers.isEmpty == false)
        #expect(xss?.insertionPoint == "url param q")
    }

    @Test("M11c: CORS reflection with credentials and host-header injection are flagged")
    func test_M11c_corsAndHostHeader() async {
        let cors = get("/cors", extra: ["Origin: https://caller.test"])
        let host = get("/hosthdr")
        let (findings, _) = await scan([cors, host], app: FakeApp())
        let found = pairs(findings)
        #expect(found.contains("/cors active.cors"), "\(found)")
        #expect(found.contains("/hosthdr active.host-header"), "\(found)")
        // Safe twins are clean.
        let (safe, _) = await scan([cors, host], app: FakeApp(safe: true))
        #expect(!safe.contains { $0.typeID == "active.cors" || $0.typeID == "active.host-header" })
    }

    @Test("M11c: a JWT with alg:none accepted by the server is flagged, not on the safe twin")
    func test_M11c_jwt() async {
        // A real-looking HS256 token: header {alg:HS256}, payload {user:alice}, a dummy signature.
        func b64(_ s: String) -> String {
            Data(s.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let token = "\(b64(#"{"alg":"HS256","typ":"JWT"}"#)).\(b64(#"{"user":"alice"}"#)).c2ln"
        let request = get("/me", extra: ["Authorization: Bearer \(token)"])
        let (findings, _) = await scan([request], app: FakeApp())
        #expect(
            findings.contains { $0.typeID == "active.jwt" && $0.variant == "alg:none" }, "\(pairs(findings))")
        let (safe, _) = await scan([request], app: FakeApp(safe: true))
        #expect(!safe.contains { $0.typeID == "active.jwt" })
    }

    @Test("M11c: mass assignment is flagged only with the unsafe gate, not on the safe twin")
    func test_M11c_massAssignment() async {
        let request = post("/profile/update", type: "application/json", body: #"{"name":"bob"}"#)
        var unsafeConfig = ScanConfig.preset(.balanced)
        unsafeConfig.unsafe = true
        let (findings, _) = await scan([request], app: FakeApp(), config: unsafeConfig)
        #expect(findings.contains { $0.typeID == "active.mass-assignment" }, "\(pairs(findings))")
        // Off without the unsafe gate.
        let (safeGate, _) = await scan([request], app: FakeApp(), config: .preset(.balanced))
        #expect(!safeGate.contains { $0.typeID == "active.mass-assignment" })
        // The /safe twin only binds name, so role isn't echoed.
        let (safe, _) = await scan([request], app: FakeApp(safe: true), config: unsafeConfig)
        #expect(!safe.contains { $0.typeID == "active.mass-assignment" })
    }

    @Test("M11c: server-side prototype pollution is flagged only with the unsafe gate, not on the safe twin")
    func test_M11c_prototypePollution() async {
        let request = post("/pp/merge", type: "application/json", body: "{}")
        var unsafeConfig = ScanConfig.preset(.balanced)
        unsafeConfig.unsafe = true
        let (findings, _) = await scan([request], app: FakeApp(), config: unsafeConfig)
        #expect(findings.contains { $0.typeID == "active.prototype-pollution" }, "\(pairs(findings))")
        // Off without the unsafe gate (it writes server state).
        let (safeGate, _) = await scan([request], app: FakeApp(), config: .preset(.balanced))
        #expect(!safeGate.contains { $0.typeID == "active.prototype-pollution" })
        // The safe twin ignores `__proto__`, so a later clean response never inherits the marker.
        let (safe, _) = await scan([request], app: FakeApp(safe: true), config: unsafeConfig)
        #expect(!safe.contains { $0.typeID == "active.prototype-pollution" })
    }

    @Test("SCN-030: the safe twins produce nothing")
    func test_SCN030_safeTwinsQuiet() async {
        let (findings, _) = await scan(plantedRequests, app: FakeApp(safe: true, oast: FakeOAST()))
        #expect(findings.isEmpty, "unexpected: \(pairs(findings))")
    }

    @Test("SCN-032: a constant delay is not a time-based injection (dose-response required)")
    func test_SCN032_constantDelayIsNotTiming() async {
        let (findings, _) = await scan([get("/ping?host=127.0.0.1")], app: FakeApp(constantSlowness: 3))
        #expect(!findings.contains { $0.typeID.hasSuffix(".time") }, "\(pairs(findings))")
    }

    @Test("SCN-036: duplicate requests produce one finding per issue and location")
    func test_SCN036_dedupWithinScan() async {
        let (findings, _) = await scan(
            [get("/tpl?name=a"), get("/tpl?name=b"), get("/tpl?name=a")], app: FakeApp())
        #expect(findings.filter { $0.typeID == "active.ssti" }.count == 1)
    }

    @Test("SCN-012 / CLAUDE.md scope safety: out-of-scope requests are never sent")
    func test_SCN012_outOfScopeSkipped() async {
        let (findings, summary) = await scan(
            plantedRequests, app: FakeApp(), inScope: { _, path in path.hasPrefix("/tpl") })
        #expect(summary?.outOfScope == plantedRequests.count - 1)
        #expect(Set(findings.map(\.path)) == ["/tpl"])
    }

    @Test("SCN-038: the per-point budget caps probes")
    func test_SCN038_budget() async {
        var config = ScanConfig.preset(.balanced)
        config.maxRequestsPerPoint = 5
        // Disable the request-level families so only the `id` insertion point's budget is measured.
        config.disabledFamilies = ["cors", "host-header", "jwt", "mass-assignment"]
        let (_, summary) = await scan([get("/item?id=1")], app: FakeApp(), config: config)
        // The one insertion point is capped at 5 probes; the request-level unit now sends nothing.
        #expect((summary?.probes ?? 99) <= 5)
    }

    @Test("SCN-034: presets enable different families and insertion kinds")
    func test_SCN034_presets() async {
        let passive = ScanConfig.preset(.passiveOnly)
        let (findings, summary) = await scan(plantedRequests, app: FakeApp(), config: passive)
        #expect(findings.isEmpty && summary?.probes == 0)
        #expect(
            ScanConfig.preset(.light).insertion.kinds == [
                .urlParam, .bodyParam, .jsonValue, .protobufField, .custom,
            ])
        // Saved configs missing newer keys still load (defaults of their preset).
        let decoded = try? JSONDecoder().decode(
            ScanConfig.self, from: Data(#"{"preset":"light","concurrency":3}"#.utf8))
        #expect(decoded?.concurrency == 3 && decoded?.timingSamples == 1 && decoded?.maxRequests == 0)
        #expect(ScanConfig.preset(.thorough).intensity == .thorough)
    }

    @Test("SCN-035: cancelling stops the scan and reports it")
    func test_SCN035_cancel() async {
        let target = HTTPTarget(scheme: .http, host: "app.test")
        let app = FakeApp()
        let scan = ActiveScan(
            requests: Array(repeating: (get("/item?id=1&a=2&b=3&c=4"), target), count: 20),
            config: .preset(.balanced),
            send: { request, _ in
                let (response, seconds) = await app.respond(request)
                return Probe(request: request, response: response, exchangeID: 0, seconds: seconds)
            }, inScope: { _, _ in true })
        var reason: String?
        var cancelled = false
        for await event in await scan.start() {
            if case .progress = event, !cancelled {
                cancelled = true
                await scan.cancel()
            }
            if case .finished(let summary) = event { reason = summary.stopReason }
        }
        #expect(reason == "cancelled")
    }

    @Test("SCN-038: the scan-wide budget stops the scan")
    func test_SCN038_globalBudget() async {
        var config = ScanConfig.preset(.balanced)
        config.maxRequests = 10
        config.concurrency = 1
        let (_, summary) = await scan(plantedRequests, app: FakeApp(), config: config)
        #expect(summary?.stopReason == "budget")
        #expect((summary?.probes ?? 99) <= 10)
    }

    @Test("SCN-036: consolidation reports one issue per type and path, listing the insertion points")
    func test_SCN036_consolidation() async {
        let request = get("/tpl?name=a&title=b")
        let separate = await scan([request], app: FakeApp(), config: .preset(.balanced))
        #expect(
            separate.findings.filter { $0.typeID == "active.ssti" }.count == 1,
            "only `name` is evaluated by the fake")
        // A second evaluating parameter: the fake evaluates every value on /tpl2.
        var config = ScanConfig.preset(.balanced)
        config.consolidate = true
        let merged = await scan([get("/tpl2?a=x&b=y")], app: FakeApp(), config: config)
        let ssti = merged.findings.filter { $0.typeID == "active.ssti" }
        #expect(ssti.count == 1)
        #expect(ssti.first?.detail.contains("Also found at:") == true)
        let plain = await scan([get("/tpl2?a=x&b=y")], app: FakeApp())
        #expect(plain.findings.filter { $0.typeID == "active.ssti" }.count == 2)
    }

    @Test("SCN-037: a re-test finds the check that reports an issue type")
    func test_SCN037_retestCheck() {
        #expect(ActiveRetest.check(for: "active.sqli.boolean")?.id == "active.sqli")
        #expect(ActiveRetest.check(for: "active.xss.reflected")?.id == "active.xss.reflected")
        #expect(ActiveRetest.check(for: "active.cmd.oast")?.id == "active.cmd")
        #expect(ActiveRetest.check(for: "passive.csp.missing") == nil)
    }

    @Test("GRP-005: protobuf fields of a gRPC request are insertion points; probes re-encode the message")
    func test_GRP005_protobufPoints() throws {
        let inner = Protobuf.encode(ProtoField(1, .bytes(Array("deep".utf8))))
        let message =
            Protobuf.encode(ProtoField(1, .bytes(Array("42".utf8))))
            + Protobuf.encode(ProtoField(2, .varint(7)))
            + Protobuf.encode(ProtoField(3, .bytes(inner)))
        let body = RPC.frame(message)
        let head =
            [
                "POST /vulnlab.Orders/Get HTTP/1.1", "Host: app.test", "Content-Type: application/grpc",
                "TE: trailers", "Content-Length: \(body.count)",
            ].joined(separator: "\r\n") + "\r\n\r\n"
        let request = RawRequest(Bytes(Array(head.utf8) + body))
        let points = InsertionPoints.derive(request)
        #expect(points.allSatisfy { $0.kind == .protobufField })
        #expect(Set(points.map(\.name)) == ["1", "2", "3.1"])
        let id = try #require(points.first { $0.name == "1" })
        #expect(id.baseValue == "42" && id.label == "protobuf field 1")
        let probe = id.build(request, payload: "42' OR 'a'='a")
        let call = try #require(RPC.parse(request: probe, response: nil))
        let decoded = try Protobuf.decode(call.requests[0].payload)
        #expect(decoded.value(at: [1]) == .bytes(Array("42' OR 'a'='a".utf8)))
        #expect(decoded.value(at: [3, 1]) == .bytes(Array("deep".utf8)), "other fields kept")
        let deep = try #require(points.first { $0.name == "3.1" })
        let nested = try Protobuf.decode(
            RPC.parse(request: deep.build(request, payload: "x"), response: nil)!.requests[0].payload)
        #expect(nested.value(at: [3, 1]) == .bytes(Array("x".utf8)))
        #expect(probe.headerValue("content-length")?.string() == String(probe.parsed.body.count))
    }

    @Test("Redirect host parsing handles the browser's quirks")
    func test_SCN030_redirectHostParsing() {
        #expect(OpenRedirectCheck.host(of: "https://evil.test/x") == "evil.test")
        #expect(OpenRedirectCheck.host(of: "//evil.test") == "evil.test")
        #expect(OpenRedirectCheck.host(of: "/\\evil.test/") == "evil.test", "browsers treat /\\ as //")
        #expect(OpenRedirectCheck.host(of: "https:evil.test") == "evil.test")
        #expect(OpenRedirectCheck.host(of: "/home") == nil)
    }

    @Test("XSS contexts are told apart")
    func test_SCN030_xssContexts() {
        let c = "gcanary1"
        #expect(ReflectedXSSCheck.contexts(of: c, in: "<p>\(c)</p>").map(\.0) == [.html])
        #expect(ReflectedXSSCheck.contexts(of: c, in: "<input value=\"\(c)\">").map(\.0) == [.attribute])
        #expect(ReflectedXSSCheck.contexts(of: c, in: "<a href=\"\(c)\">x</a>").map(\.0) == [.url])
        let script = ReflectedXSSCheck.contexts(of: c, in: "<script>var a = \"\(c)\";</script>")
        #expect(script.map(\.0) == [.script] && script.first?.1 == "\"")
    }
}
