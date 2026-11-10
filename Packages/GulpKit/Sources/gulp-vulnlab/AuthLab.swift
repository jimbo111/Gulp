// gulp-vulnlab — the Auth lab and discovery fixtures (doc 06 §3; F07 tests 1–3 and 6).
//
//   GET  /login     a form with a fresh single-use CSRF token (name="csrf")
//   POST /login     username/password/csrf: a bad/missing/used token → 403 "Invalid CSRF token";
//                   an unknown user → 200 "Invalid username"; a wrong password → 200 "Invalid password"
//                   (the username-enumeration bug); alice/wonderland → 302 /account + session cookie
//   GET  /account   needs the session cookie
//   GET  /admin     unlinked; 403 unless the cookie role=admin
//   /index.html (+ .bak), /backup.zip, /.old/ (403, no listing), /.old/config.php~ — unlinked backups

import Foundation
import GulpCore
import NIOConcurrencyHelpers

enum AuthLab {
    static let users = ["alice": "wonderland", "bob": "builder"]
    private static let tokens = NIOLockedValueBox<Set<String>>([])
    private static let sessions = NIOLockedValueBox<[String: String]>([:])

    static func token() -> String {
        String((0..<24).map { _ in "abcdefghijklmnopqrstuvwxyz0123456789".randomElement()! })
    }

    static func loginForm() -> VulnReply {
        let csrf = token()
        tokens.withLockedValue { _ = $0.insert(csrf) }
        let page = """
            <!doctype html><html><head><title>Login</title></head><body>
            <form method="post" action="/login">
            <input type="hidden" name="csrf" value="\(csrf)">
            <input name="username"><input name="password" type="password" autocomplete="current-password"><button>Sign in</button>
            </form></body></html>

            """
        return VulnReply(
            bytes: VulnLab.response(200, body: Array(page.utf8), type: "text/html; charset=utf-8"))
    }

    static func form(_ body: String) -> [String: String] {
        var fields: [String: String] = [:]
        for pair in body.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map {
                String($0).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? String($0)
            }
            if let name = parts.first { fields[name] = parts.count > 1 ? parts[1] : "" }
        }
        return fields
    }

    static func login(_ request: RawRequest) -> VulnReply {
        guard request.bytes[request.parsed.method].string() == "POST" else { return loginForm() }
        let fields = form(request.bytes[request.parsed.body].string())
        let csrf = fields["csrf"] ?? ""
        let valid = tokens.withLockedValue { $0.remove(csrf) != nil }
        guard valid else { return text(403, "Invalid CSRF token\n") }
        let user = fields["username"] ?? ""
        guard let password = users[user] else { return text(200, "Invalid username\n") }
        guard fields["password"] == password else { return text(200, "Invalid password\n") }
        let session = token()
        sessions.withLockedValue { $0[session] = user }
        return VulnReply(
            bytes: VulnLab.response(
                302, body: [],
                headers: [
                    "Location: /account", "Set-Cookie: session=\(session); Path=/; HttpOnly; SameSite=Lax",
                ]))
    }

    static func cookie(_ request: RawRequest, _ name: String) -> String? {
        guard let header = request.headerValue("cookie")?.string() else { return nil }
        for pair in header.split(separator: ";") {
            let parts = pair.trimmingCharacters(in: .whitespaces).split(separator: "=", maxSplits: 1)
            if parts.count == 2, parts[0] == name { return String(parts[1]) }
        }
        return nil
    }

    static func account(_ request: RawRequest) -> VulnReply {
        guard let session = cookie(request, "session"), let user = sessions.withLockedValue({ $0[session] })
        else {
            return VulnReply(bytes: VulnLab.response(302, body: [], headers: ["Location: /login"]))
        }
        return text(200, "Welcome, \(user)\n")
    }

    static func admin(_ request: RawRequest) -> VulnReply {
        cookie(request, "role") == "admin"
            ? text(200, "Admin panel: 3 users, 0 alerts\n") : text(403, "Forbidden: admins only\n")
    }

    static func text(_ code: Int, _ body: String) -> VulnReply {
        VulnReply(bytes: VulnLab.response(code, body: Array(body.utf8)))
    }

    /// Unlinked files for content discovery (F07 test 6).
    static func discovery(_ path: String) -> VulnReply? {
        switch path {
        case "/index.html":
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: Array(VulnLab.homePage.utf8), type: "text/html; charset=utf-8"))
        case "/index.html.bak":
            return text(200, "<!-- old home page, 2024 -->\n<a href=\"/admin\">Admin</a>\n")
        case "/backup.zip":
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: [0x50, 0x4B, 0x05, 0x06] + [UInt8](repeating: 0, count: 18),
                    type: "application/zip"))
        case "/.old", "/.old/": return text(403, "Directory listing is forbidden\n")
        case "/.old/config.php~":
            return text(200, "<?php $db_user = 'vulnlab'; $db_password = 'hunter2'; ?>\n")
        default: return nil
        }
    }
}
