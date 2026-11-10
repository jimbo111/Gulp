import Foundation
import GulpCore
import Testing

@testable import GulpScanner

// F08 §3.1 passive checks: each family on crafted exchanges, plus a hardened response that must
// produce nothing.

/// The headers a well-configured page sends (VulnLab's baseline, doc 06 §3).
let hardened = [
    "Content-Type: text/html; charset=utf-8",
    "Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'self'; object-src 'none'",
    "X-Content-Type-Options: nosniff", "X-Frame-Options: DENY", "Referrer-Policy: no-referrer",
    "Permissions-Policy: camera=(), geolocation=()", "Cache-Control: no-store",
]

func exchange(
    _ request: String, status: Int = 200, headers: [String] = hardened, body: String = "<p>hi</p>",
    scheme: Scheme = .http, host: String = "lab.test", tls: TLSInfo? = nil
) -> Exchange {
    let head = (["HTTP/1.1 \(status) X"] + headers + ["Content-Length: \(body.utf8.count)"]).joined(
        separator: "\r\n")
    return Exchange(
        id: 7, source: .proxy, target: HTTPTarget(scheme: scheme, host: host),
        request: RawRequest(Bytes(request.replacingOccurrences(of: "\n", with: "\r\n") + "\r\n\r\n")),
        response: RawResponse(Bytes(head + "\r\n\r\n" + body)), state: .complete, tls: tls)
}

func types(_ exchange: Exchange) -> [String] {
    PassiveScanner().scan(exchange).map(\.typeID).sorted()
}

func without(_ names: String...) -> [String] {
    hardened.filter { header in !names.contains { header.lowercased().hasPrefix($0.lowercased()) } }
}

@Suite("Passive checks (F08 §3.1)")
struct PassiveCheckTests {
    @Test("A hardened page produces nothing; every definition used exists")
    func test_hardenedIsClean() {
        #expect(types(exchange("GET / HTTP/1.1\nHost: lab.test")).isEmpty)
        #expect(Set(IssueDefinitions.all.map(\.id)).count == IssueDefinitions.all.count)
    }

    @Test("Security headers: CSP missing/weak, clickjacking, nosniff, referrer, permissions, charset, HSTS")
    func test_securityHeaders() {
        let bare = exchange("GET /page HTTP/1.1\nHost: lab.test", headers: ["Content-Type: text/html"])
        #expect(
            types(bare) == [
                "passive.charset.missing", "passive.clickjacking", "passive.csp.missing",
                "passive.nosniff.missing",
                "passive.permissions-policy.missing", "passive.referrer-policy.missing",
            ])
        let weak = exchange(
            "GET / HTTP/1.1\nHost: lab.test",
            headers: without("Content-Security-Policy") + [
                "Content-Security-Policy: script-src 'self' 'unsafe-inline'"
            ])
        #expect(types(weak) == ["passive.csp.weak"])  // X-Frame-Options: DENY still stops framing
        #expect(PassiveChecks.weakCSP("script-src 'nonce-abc' 'unsafe-inline'") == nil)
        #expect(PassiveChecks.weakCSP("default-src *") == "`*`")
        #expect(PassiveChecks.weakCSP("script-src 'strict-dynamic' 'nonce-x' https:") == nil)
        let https = exchange("GET / HTTP/1.1\nHost: lab.test", scheme: .https)
        let hsts = PassiveScanner().scan(https)
        #expect(hsts.map(\.typeID) == ["passive.hsts.missing"] && hsts.first?.path == "/")
        // A redirect or error page isn't held to the page-header rules.
        #expect(
            types(exchange("GET /x HTTP/1.1\nHost: lab.test", status: 302, headers: [], body: "")).isEmpty)
    }

    @Test("Cookies: HttpOnly, Secure (HTTPS only), SameSite, parent domain; deletions ignored")
    func test_cookies() {
        let cookies = exchange(
            "GET /login HTTP/1.1\nHost: app.lab.test",
            headers: hardened + [
                "Set-Cookie: sid=abc; Path=/", "Set-Cookie: pref=1; HttpOnly; SameSite=Lax; Domain=.lab.test",
                "Set-Cookie: old=; Max-Age=0", "Set-Cookie: track=1; HttpOnly; SameSite=None",
            ], host: "app.lab.test")
        let findings = PassiveScanner().scan(cookies)
        let summary = findings.map { "\($0.typeID):\($0.insertionPoint ?? "")" }.sorted()
        #expect(
            summary == [
                "passive.cookie.broad-domain:pref", "passive.cookie.no-httponly:sid",
                "passive.cookie.no-samesite:sid",
                "passive.cookie.no-samesite:track",
            ])
        #expect(findings.allSatisfy { $0.path == "/" && !$0.evidence.responseMarkers.isEmpty })
        let secure = exchange(
            "GET / HTTP/1.1\nHost: lab.test",
            headers: hardened + [
                "Strict-Transport-Security: max-age=1", "Set-Cookie: s=1; HttpOnly; SameSite=Lax",
            ],
            scheme: .https)
        #expect(types(secure) == ["passive.cookie.no-secure"])
    }

    @Test(
        "Disclosure: stack traces, versions, private IPs, listings, .git, .env, backups, comments, autocomplete"
    )
    func test_disclosure() {
        let trace = "<pre>Traceback (most recent call last):\n  File \"app.py\", line 3</pre>"
        let error = exchange("GET /err HTTP/1.1\nHost: lab.test", status: 500, body: trace)
        let stack = PassiveScanner().scan(error).first { $0.typeID == "passive.disclosure.stack-trace" }
        #expect(stack?.variant == "Python" && stack?.evidence.responseMarkers.isEmpty == false)
        let banner = exchange(
            "GET / HTTP/1.1\nHost: lab.test",
            headers: hardened + ["Server: Apache/2.4.41 (Ubuntu)", "X-Powered-By: PHP/8.1.2"])
        #expect(
            PassiveScanner().scan(banner).map { $0.insertionPoint ?? "" }.sorted() == [
                "server", "x-powered-by",
            ])
        #expect(
            types(exchange("GET / HTTP/1.1\nHost: lab.test", headers: hardened + ["Server: gulp-vulnlab"]))
                .isEmpty)
        #expect(
            types(exchange("GET /i HTTP/1.1\nHost: lab.test", body: "<p>db at 10.0.3.4</p>")) == [
                "passive.disclosure.internal-ip"
            ])
        #expect(
            types(exchange("GET /files/ HTTP/1.1\nHost: lab.test", body: "<title>Index of /files</title>"))
                == ["passive.disclosure.directory-listing"])
        let git = PassiveScanner().scan(
            exchange(
                "GET /.git/HEAD HTTP/1.1\nHost: lab.test",
                headers: ["Content-Type: text/plain", "X-Content-Type-Options: nosniff"],
                body: "ref: refs/heads/main\n"))
        #expect(git.map(\.typeID) == ["passive.disclosure.git"] && git.first?.path == "/.git")
        #expect(
            types(
                exchange(
                    "GET /.env HTTP/1.1\nHost: lab.test",
                    headers: ["Content-Type: text/plain", "X-Content-Type-Options: nosniff"],
                    body: "DB_PASSWORD=hunter2\n"))
                == ["passive.disclosure.env-file"])
        #expect(
            types(
                exchange(
                    "GET /index.html.bak HTTP/1.1\nHost: lab.test",
                    headers: ["Content-Type: text/plain", "X-Content-Type-Options: nosniff"], body: "x"))
                == ["passive.disclosure.backup-file"])
        #expect(
            types(
                exchange(
                    "GET /backup.zip HTTP/1.1\nHost: lab.test",
                    headers: ["Content-Type: application/zip", "X-Content-Type-Options: nosniff"], body: "PK")
            )
                == ["passive.disclosure.backup-file"])
        #expect(
            types(
                exchange(
                    "GET /app.zip HTTP/1.1\nHost: lab.test",
                    headers: ["Content-Type: application/zip", "X-Content-Type-Options: nosniff"], body: "PK")
            ).isEmpty)
        #expect(
            types(exchange("GET / HTTP/1.1\nHost: lab.test", body: "<!-- api_key = sk_live_123 --><p>x</p>"))
                == ["passive.disclosure.secret-in-comment"])
        let login =
            "<form method=post action=/login><input name=csrf type=hidden><input type=password name=pw></form>"
        // On loopback, so the cleartext-password check (meaningless there) stays quiet.
        #expect(
            types(exchange("GET /login HTTP/1.1\nHost: 127.0.0.1", body: login, host: "127.0.0.1"))
                == ["passive.form.password-autocomplete"])
    }

    @Test("Reflection: plain reflection is a signpost; unencoded special characters are potential XSS")
    func test_reflection() {
        let plain = PassiveScanner().scan(
            exchange("GET /s?q=gulpfish HTTP/1.1\nHost: lab.test", body: "<p>You searched gulpfish</p>"))
        #expect(plain.map(\.typeID) == ["passive.reflection"] && plain.first?.variant == "HTML")
        #expect(plain.first?.evidence.requestMarkers.isEmpty == false)
        let raw = "<p>x\"'probe"
        let encoded = "gp%3Cp%3Ex%22%27probe"
        let vulnerable = PassiveScanner().scan(
            exchange("GET /s?q=\(encoded) HTTP/1.1\nHost: lab.test", body: "<div>gp\(raw)</div>"))
        #expect(vulnerable.map(\.typeID) == ["passive.reflection.unencoded"])
        let safe = exchange(
            "GET /s?q=\(encoded) HTTP/1.1\nHost: lab.test", body: "<div>gp&lt;p&gt;x&quot;&#39;probe</div>")
        #expect(types(safe).isEmpty)
        let attribute = PassiveScanner().scan(
            exchange("GET /s?q=gulpfish HTTP/1.1\nHost: lab.test", body: "<input value=\"gulpfish\">"))
        #expect(attribute.first?.variant == "attribute")
        let script = PassiveScanner().scan(
            exchange("GET /s?q=gulpfish HTTP/1.1\nHost: lab.test", body: "<script>var s='gulpfish';</script>")
        )
        #expect(script.first?.variant == "script")
        let url = PassiveScanner().scan(
            exchange("GET /s?q=gulpfish HTTP/1.1\nHost: lab.test", body: "<a href=\"gulpfish\">go</a>"))
        #expect(url.first?.variant == "URL attribute")
    }

    @Test("Open redirects, forms (CSRF, cross-domain, cleartext password)")
    func test_redirectsAndForms() {
        let redirect = exchange(
            "GET /go?next=https%3A%2F%2Fevil.example%2Fx HTTP/1.1\nHost: lab.test", status: 302,
            headers: ["Location: https://evil.example/x"], body: "")
        #expect(types(redirect) == ["passive.open-redirect"])
        let local = exchange(
            "GET /go?next=%2Fhome HTTP/1.1\nHost: lab.test", status: 302, headers: ["Location: /home"],
            body: "")
        #expect(types(local).isEmpty)
        let forms = """
            <form method="post" action="/guestbook"><input name="message"></form>
            <form method="post" action="https://other.example/collect"><input name="csrf_token" type="hidden"></form>
            """
        #expect(
            types(exchange("GET / HTTP/1.1\nHost: lab.test", body: forms))
                == ["passive.form.cross-domain-action", "passive.form.no-csrf-token"])
        let password =
            "<form method=post action=/login><input name=csrf><input type=password name=pw autocomplete=current-password></form>"
        #expect(
            types(exchange("GET /login HTTP/1.1\nHost: lab.test", body: password)) == [
                "passive.form.password-cleartext"
            ])
        #expect(
            types(exchange("GET /login HTTP/1.1\nHost: 127.0.0.1", body: password, host: "127.0.0.1")).isEmpty
        )
    }

    @Test("CORS, caching of sensitive responses, TLS and mixed content")
    func test_corsCachingTransport() {
        let reflected = exchange(
            "GET /api/cors HTTP/1.1\nHost: lab.test\nOrigin: https://evil.example",
            headers: hardened + [
                "Access-Control-Allow-Origin: https://evil.example", "Access-Control-Allow-Credentials: true",
            ])
        let cors = PassiveScanner().scan(reflected)
        #expect(cors.map(\.typeID) == ["passive.cors.credentials-reflected"] && cors.first?.severity == .high)
        #expect(cors.first?.evidence.requestMarkers.isEmpty == false)
        let fixed = exchange(
            "GET /safe/api/cors HTTP/1.1\nHost: lab.test\nOrigin: https://evil.example",
            headers: hardened + [
                "Access-Control-Allow-Origin: https://lab.test", "Access-Control-Allow-Credentials: true",
            ])
        #expect(types(fixed).isEmpty)
        #expect(
            types(
                exchange(
                    "GET / HTTP/1.1\nHost: lab.test", headers: hardened + ["Access-Control-Allow-Origin: *"]))
                == ["passive.cors.wildcard"])
        let cached = exchange(
            "GET /me HTTP/1.1\nHost: lab.test\nAuthorization: Bearer x", headers: without("Cache-Control"))
        #expect(types(cached) == ["passive.cache.sensitive"])
        let old = exchange(
            "GET / HTTP/1.1\nHost: lab.test", headers: hardened + ["Strict-Transport-Security: max-age=1"],
            body: "<script src=\"http://cdn.example/a.js\"></script>", scheme: .https,
            tls: TLSInfo(version: "TLSv1.1", cipherSuite: "x"))
        #expect(types(old) == ["passive.mixed-content", "passive.tls.weak-protocol"])
    }

    @Test("SCN-002: markers point at the proof in the stored bytes; settings disable types")
    func test_markersAndSettings() throws {
        let message = exchange(
            "GET / HTTP/1.1\nHost: lab.test", headers: hardened + ["Set-Cookie: sid=1"], body: "<p>x</p>")
        let finding = try #require(
            PassiveScanner().scan(message).first { $0.typeID == "passive.cookie.no-httponly" })
        let wire = try #require(message.response?.wireBytes)
        let marker = try #require(finding.evidence.responseMarkers.first)
        #expect(wire[marker.range].string() == "Set-Cookie: sid=1")
        var settings = PassiveScanSettings()
        settings.disabled = ["passive.cookie.no-httponly", "passive.cookie.no-samesite"]
        #expect(PassiveScanner(settings: settings).scan(message).isEmpty)
    }
}
