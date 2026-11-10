// gulp-vulnlab — planted passive issues (doc 06 §3 "Header issues", "Clickjacking", "CORS", "Open
// redirect"; F08 §3.1). Every route leaves out exactly one protection from the baseline that all
// other responses carry, and its `/safe/…` twin keeps it, so a passive scan of VulnLab yields exactly
// the issues listed in `Tests/Fixtures/vulnlab-issues.json` and none on `/safe/*`. The `/tls/…`
// routes are meant for the HTTPS listener (:8443): HSTS, `Secure` and mixed content mean nothing on
// plaintext.

import Foundation
import GulpCore

enum PassiveLab {
    static func page(_ title: String, _ body: String) -> [UInt8] {
        Array("<!doctype html><html><head><title>\(title)</title></head><body>\(body)</body></html>\n".utf8)
    }

    static func html(
        _ title: String, _ body: String, code: Int = 200, type: String = "text/html; charset=utf-8",
        headers: [String] = [], omit: Set<String> = []
    ) -> VulnReply {
        VulnReply(
            bytes: VulnLab.response(code, body: page(title, body), type: type, headers: headers, omit: omit))
    }

    static func text(_ body: String, code: Int = 200, headers: [String] = [], omit: Set<String> = [])
        -> VulnReply
    {
        VulnReply(bytes: VulnLab.response(code, body: Array(body.utf8), headers: headers, omit: omit))
    }

    /// The planted route for `path` (or its `/safe/` twin), or nil.
    static func respond(_ path: String, _ query: [String: String], _ request: RawRequest) -> VulnReply? {
        let safe = path.hasPrefix("/safe/")
        let route = safe ? String(path.dropFirst(5)) : path
        let csrf = #"<input type="hidden" name="csrf" value="9c1f0e2a">"#
        switch route {
        case "/headers/no-csp":
            return html(
                "No CSP", "<p>No Content-Security-Policy.</p>", omit: safe ? [] : ["content-security-policy"])
        case "/headers/weak-csp":
            let policy =
                "default-src 'self'; script-src 'self'" + (safe ? "" : " 'unsafe-inline'")
                + "; object-src 'none'; frame-ancestors 'self'"
            return html(
                "Weak CSP", "<p>Inline scripts allowed.</p>", headers: ["Content-Security-Policy: \(policy)"])
        case "/frameable":
            // No X-Frame-Options and a CSP without frame-ancestors.
            return safe
                ? html("Frameable", "<p>Not frameable.</p>")
                : html(
                    "Frameable", "<p>Frame me.</p>",
                    headers: [
                        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"
                    ],
                    omit: ["x-frame-options"])
        case "/headers/no-nosniff":
            return html("Sniffable", "<p>No nosniff.</p>", omit: safe ? [] : ["x-content-type-options"])
        case "/headers/no-referrer-policy":
            return html("Referrer", "<p>No Referrer-Policy.</p>", omit: safe ? [] : ["referrer-policy"])
        case "/headers/no-permissions-policy":
            return html(
                "Permissions", "<p>No Permissions-Policy.</p>", omit: safe ? [] : ["permissions-policy"])
        case "/headers/version":
            return html(
                "Version", "<p>Banner.</p>",
                headers: safe ? [] : ["Server: Apache/2.4.41 (Ubuntu)", "X-Powered-By: PHP/8.1.2"])
        case "/cookies/insecure":
            let flags = safe ? "; HttpOnly; SameSite=Lax" : ""
            return html(
                "Cookie", "<p>Cookie set.</p>",
                headers: ["Set-Cookie: sessionid=4f2a9c\(safe ? "-safe" : ""); Path=/\(flags)"])
        case "/error/stack":
            let trace = """
                java.lang.NullPointerException: order was null
                \tat com.vulnlab.orders.OrderService.total(OrderService.java:42)
                \tat com.vulnlab.web.OrderController.show(OrderController.java:17)

                """
            return safe ? text("Something went wrong (reference 7f3a).\n", code: 500) : text(trace, code: 500)
        case "/.git/HEAD" where !safe:
            return text("ref: refs/heads/main\n")
        case "/.git/config" where !safe:
            return text("[core]\n\trepositoryformatversion = 0\n\tbare = false\n")
        case "/.env" where !safe:
            return text("APP_ENV=production\nDB_PASSWORD=vulnlab-db-secret\nAPI_KEY=gulp_test_key_4b1d\n")
        case "/info/internal-ip":
            return html("Upstream", "<p>Served by \(safe ? "app-server" : "10.0.4.12:8080").</p>")
        case "/files/":
            return safe
                ? text("Forbidden\n", code: 403)
                : html(
                    "Index of /files/",
                    "<h1>Index of /files/</h1><ul><li><a href=\"report.pdf\">report.pdf</a></li></ul>")
        case "/comment-secret":
            let comment =
                safe
                ? "<!-- page footer -->" : "<!-- TODO remove before launch: api_key = gulp_test_9f2c1a7b -->"
            return html("Comment", "\(comment)<p>Welcome.</p>")
        case "/forms/no-csrf":
            return html(
                "Profile",
                "<form method=\"post\" action=\"/profile\">\(safe ? csrf : "")<input name=\"email\"><button>Save</button></form>"
            )
        case "/forms/cross-domain":
            let action = safe ? "/subscribe" : "https://collector.example/subscribe"
            return html(
                "Newsletter",
                "<form method=\"post\" action=\"\(action)\">\(csrf)<input name=\"email\"><button>Join</button></form>"
            )
        case "/forms/password-autocomplete":
            let attribute = safe ? " autocomplete=\"current-password\"" : ""
            return html(
                "Sign in",
                "<form method=\"post\" action=\"/login\">\(csrf)<input name=\"username\">"
                    + "<input type=\"password\" name=\"password\"\(attribute)><button>Sign in</button></form>"
            )
        case "/api/cors":
            let origin = request.headerValue("origin")?.string() ?? ""
            let allowed = safe ? "http://127.0.0.1:8088" : origin
            var headers = ["Access-Control-Allow-Credentials: true"]
            if !allowed.isEmpty { headers.append("Access-Control-Allow-Origin: \(allowed)") }
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: Array(#"{"user":"alice","email":"alice@vulnlab.test"}"#.utf8),
                    type: "application/json", headers: headers))
        case "/api/cors-wildcard":
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: Array(#"{"status":"public"}"#.utf8), type: "application/json",
                    headers: safe ? [] : ["Access-Control-Allow-Origin: *"]))
        case "/go":
            let next = query["next"] ?? "/"
            let local = next.hasPrefix("/") && !next.hasPrefix("//")
            let location = safe && !local ? "/" : next
            return VulnReply(bytes: VulnLab.response(302, body: [], headers: ["Location: \(location)"]))
        case "/cache/sensitive":
            return html(
                "Preferences", "<p>Saved.</p>",
                headers: ["Set-Cookie: prefs=dark; Path=/; HttpOnly; SameSite=Lax"]
                    + (safe ? [] : ["Cache-Control: public, max-age=600"]))
        case "/charset":
            return html(
                "Charset", "<p>No charset.</p>", type: safe ? "text/html; charset=utf-8" : "text/html")
        case "/no-content-type":
            return text("raw data\n", omit: safe ? [] : ["content-type"])
        case "/tls/no-hsts":
            return html("HSTS", "<p>No HSTS.</p>", omit: safe ? [] : ["strict-transport-security"])
        case "/tls/cookie":
            return html(
                "TLS cookie", "<p>Token set.</p>",
                headers: [
                    "Set-Cookie: tlstoken=7d1e; Path=/; HttpOnly; SameSite=Lax\(safe ? "; Secure" : "")"
                ])
        case "/tls/mixed":
            let scheme = safe ? "https" : "http"
            return html("Mixed", "<script src=\"\(scheme)://cdn.vulnlab.test/app.js\"></script><p>Mixed.</p>")
        default:
            return nil
        }
    }
}
