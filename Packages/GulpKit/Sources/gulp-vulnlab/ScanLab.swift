// gulp-vulnlab — the active-scanner labs (doc 06 §3, F08 §3.2 [P0], M11b). Each vulnerable route has
// a `/safe/` twin of the same shape that is implemented correctly; `Tests/Fixtures/vulnlab-active.json`
// lists the exact issue types each must yield. Nothing here runs a real shell, database or XML
// parser: each route emulates the vulnerable behavior (errors, conditions, delays, file reads, OAST
// lookups to the dev Beacon) so results are deterministic. Each route is vulnerable in one intended
// way (e.g. the time-based SQLi route hides errors and returns constant output).

import Foundation
import GulpCore

extension VulnLab {
    /// `text` without CR and LF. (Filtering `Character`s misses CRLF: `"\r\n"` is one grapheme.)
    static func withoutLineBreaks(_ text: String) -> String {
        String(String.UnicodeScalarView(text.unicodeScalars.filter { $0 != "\r" && $0 != "\n" }))
    }
}

enum ScanLab {
    static let products = ["1": "Gulp T-shirt", "2": "Gulp mug"]
    static let passwd =
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\ngulp:x:1000:1000::/home/gulp:/bin/sh\n"
    static let files = [
        "readme.txt": "Welcome to the VulnLab file area.\n", "notes.txt": "Nothing to see.\n",
    ]

    static func text(_ body: String, status: Int = 200, headers: [String] = [], delay: Int = 0) -> VulnReply {
        VulnReply(
            bytes: VulnLab.response(status, body: Array(body.utf8), headers: headers),
            delayMilliseconds: delay)
    }

    /// `/scanlab/`: links to every crawlable vulnerable route and its safe twin (with parameters)
    /// and the guestbook forms, so a crawl from here reaches them (the M11c crawl-and-audit DoD).
    static let index: String = {
        let gets = [
            "/xss/html?q=hello", "/xss/attr?q=hello", "/xss/js?q=hello", "/xss/url?q=https://example.com/",
            "/sqli/error?id=1", "/sqli/bool?id=1", "/sqli/time?id=1", "/cmd/ping?host=127.0.0.1",
            "/ssti?name=gulp",
            "/file?name=readme.txt", "/fetch?url=http://example.com/", "/go?next=/", "/crlf?lang=en",
        ]
        var links = gets.flatMap { [$0, "/safe" + $0] }.map {
            "<li><a href=\"\($0.replacingOccurrences(of: "&", with: "&amp;"))\">\($0)</a></li>"
        }
        links += ["", "/safe"].map { prefix in
            """
            <li><form method="post" action="\(prefix)/guestbook"><input name="message" value="hello"><button>Sign</button></form></li>
            """
        }
        return "<!doctype html><html><head><title>Scan lab</title></head><body><h1>Scan lab</h1><ul>"
            + links.joined(separator: "\n") + "</ul></body></html>"
    }()

    static func respond(_ request: RawRequest, path: String, query: [String: String]) -> VulnReply? {
        if path == "/scanlab/" || path == "/scanlab" {
            return VulnReply(
                bytes: VulnLab.response(200, body: Array(index.utf8), type: "text/html; charset=utf-8"))
        }
        // `/lab/patch?route=/ssti`: from now on the route behaves like its safe twin (the re-test
        // demonstration: a re-test after the patch reports the issue fixed).
        if path == "/lab/patch", let route = query["route"] {
            patched.insert(route)
            return text("patched \(route)\n")
        }
        let safe = path.hasPrefix("/safe/") || patched.contains(path)
        let route = path.hasPrefix("/safe/") ? String(path.dropFirst(5)) : path
        let body = String(decoding: request.bytes.rawBytes[request.parsed.body], as: UTF8.self)
        switch route {
        case "/sqli/error": return sqli(query["id"] ?? "", safe: safe, showErrors: true)
        case "/sqli/bool": return sqli(query["id"] ?? "", safe: safe, showErrors: false)
        case "/sqli/time":
            // Output and errors are constant; only the time tells.
            let id = query["id"] ?? ""
            let delay = safe ? 0 : sleepSeconds(id)
            return text("Request received.\n", delay: delay * 1_000)
        case "/sqli/json":
            let object = (try? JSONSerialization.jsonObject(with: Data(body.utf8))) as? [String: Any]
            let id = (object?["id"]).map { "\($0)" } ?? ""
            return sqli(id, safe: safe, showErrors: true)
        case "/cmd/ping":
            return ping(query["host"] ?? "", safe: safe)
        case "/ssti":
            let name = query["name"] ?? "guest"
            return text("Hello \(safe ? name : evaluate(name))!\n")
        case "/file":
            return file(query["name"] ?? "", safe: safe)
        case "/xml":
            return xml(body, safe: safe)
        case "/crlf":
            var lang = query["lang"] ?? "en"
            if safe { lang = VulnLab.withoutLineBreaks(lang) }
            return text("Language set.\n", headers: ["Content-Language: \(lang)"])
        case "/guestbook":
            return guestbook(request, body: body, safe: safe)
        default:
            return nil
        }
    }

    // MARK: SQL

    /// `SELECT name FROM products WHERE id = '<id>'`, emulated: odd quotes are a syntax error; a
    /// trailing `AND '<a>'='<b>` or `OR …` condition is evaluated; the safe twin binds the value.
    static func sqli(_ id: String, safe: Bool, showErrors: Bool) -> VulnReply {
        if safe {
            return text(products[id].map { "Product: \($0)\n" } ?? "No product.\n")
        }
        let quotes = id.filter { $0 == "'" }.count
        let commented = id.contains("--")
        if quotes % 2 == 1, !commented {
            guard showErrors else { return text("No product.\n") }
            let tail = id.split(separator: "'", omittingEmptySubsequences: false).last ?? ""
            return text(
                "SQLite error: unrecognized token: \"'\(tail)'\" in SELECT name FROM products WHERE id = '\(id)'\n",
                status: 500)
        }
        // Split the leading value from an injected condition.
        guard let quote = id.firstIndex(of: "'") else {
            return text(products[id].map { "Product: \($0)\n" } ?? "No product.\n")
        }
        let value = String(id[..<quote])
        let condition = String(id[id.index(after: quote)...])
        let pattern = #"^\s*(AND|OR)\s+'([^']*)'\s*=\s*'([^']*)$"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]),
            let match = regex.firstMatch(
                in: condition, range: NSRange(condition.startIndex..., in: condition)),
            let op = Range(match.range(at: 1), in: condition),
            let a = Range(match.range(at: 2), in: condition),
            let b = Range(match.range(at: 3), in: condition)
        else {
            return text("No product.\n")
        }
        let holds = condition[a] == condition[b]
        if condition[op].uppercased() == "OR", holds {
            return text(products.values.sorted().map { "Product: \($0)" }.joined(separator: "\n") + "\n")
        }
        guard holds, let name = products[value] else { return text("No product.\n") }
        return text("Product: \(name)\n")
    }

    /// `SLEEP(n)`, `pg_sleep(n)` or `WAITFOR DELAY '0:0:n'` in the input (capped at 10 s).
    static func sleepSeconds(_ input: String) -> Int {
        for pattern in [#"(?i)sleep\((\d+)\)"#, #"(?i)WAITFOR DELAY '0:0:(\d+)'"#] {
            if let regex = try? NSRegularExpression(pattern: pattern),
                let match = regex.firstMatch(in: input, range: NSRange(input.startIndex..., in: input)),
                let range = Range(match.range(at: 1), in: input), let seconds = Int(input[range])
            {
                return min(seconds, 10)
            }
        }
        return 0
    }

    // MARK: OS command

    /// `ping -c 3 <host>`, emulated: after a shell metacharacter, `sleep n` delays and
    /// `nslookup`/`curl`/`ping <host>` look the host up (and fetch it) at the dev Beacon.
    static func ping(_ host: String, safe: Bool) -> VulnReply {
        if safe {
            guard host.range(of: #"^[A-Za-z0-9.-]{1,253}$"#, options: .regularExpression) != nil else {
                return text("Invalid host.\n", status: 400)
            }
            return text("PING \(host): 3 packets transmitted, 3 received\n")
        }
        let injected = [";", "|", "$(", "`", "&&"].compactMap { host.range(of: $0) }.min {
            $0.lowerBound < $1.lowerBound
        }
        var delay = 0
        if let injected {
            let command = String(host[injected.upperBound...])
            if let regex = try? NSRegularExpression(pattern: #"sleep (\d+)"#),
                let match = regex.firstMatch(in: command, range: NSRange(command.startIndex..., in: command)),
                let range = Range(match.range(at: 1), in: command)
            {
                delay = min(Int(command[range]) ?? 0, 10) * 1_000
            }
            if let regex = try? NSRegularExpression(
                pattern: #"(nslookup|curl|ping|wget)\s+(?:https?://)?([A-Za-z0-9.-]+)"#),
                let match = regex.firstMatch(in: command, range: NSRange(command.startIndex..., in: command)),
                let tool = Range(match.range(at: 1), in: command),
                let target = Range(match.range(at: 2), in: command)
            {
                let name = command[target].lowercased()
                let fetch = command[tool] == "curl" || command[tool] == "wget"
                if name.hasSuffix("." + OASTLab.domain) {
                    Task.detached {
                        await OASTLab.lookup(name)
                        if fetch { await OASTLab.get(host: name, path: "/") }
                    }
                }
            }
        }
        return text("PING 127.0.0.1: 3 packets transmitted, 3 received\n", delay: delay)
    }

    // MARK: SSTI

    /// A tiny template engine that evaluates `{{ a*b }}` / `{{ a+b }}` (the vulnerable route
    /// renders the input as a template).
    static func evaluate(_ template: String) -> String {
        guard let regex = try? NSRegularExpression(pattern: #"\{\{\s*(\d+)\s*([*+])\s*(\d+)\s*\}\}"#) else {
            return template
        }
        var out = template
        while let match = regex.firstMatch(in: out, range: NSRange(out.startIndex..., in: out)),
            let whole = Range(match.range, in: out), let a = Range(match.range(at: 1), in: out),
            let op = Range(match.range(at: 2), in: out), let b = Range(match.range(at: 3), in: out),
            let x = Int(out[a]), let y = Int(out[b])
        {
            let value = out[op] == "*" ? x * y : x + y
            out.replaceSubrange(whole, with: String(value))
        }
        return out
    }

    // MARK: files

    /// Files under `/srv/files`; the vulnerable route resolves `..` naively, so `/etc/passwd` is
    /// reachable; the safe twin only serves names from its list.
    static func file(_ name: String, safe: Bool) -> VulnReply {
        if safe {
            let base = name.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init) ?? ""
            return files[base].map { text($0) } ?? text("Not found.\n", status: 404)
        }
        var components = ["srv", "files"]
        let absolute = name.hasPrefix("/")
        if absolute { components = [] }
        for part in name.split(whereSeparator: { $0 == "/" || $0 == "\\" }) {
            switch part {
            case ".": continue
            case "..": _ = components.popLast()
            default: components.append(String(part))
            }
        }
        let path = "/" + components.joined(separator: "/")
        if path == "/etc/passwd" { return text(passwd) }
        if path.hasPrefix("/srv/files/"), let content = files[String(path.dropFirst("/srv/files/".count))] {
            return text(content)
        }
        return text("Not found.\n", status: 404)
    }

    // MARK: XML

    /// `<order><item>…</item></order>` → "Ordered: …". The vulnerable route expands a DOCTYPE's
    /// external entities (a `file:///etc/passwd` general entity; an `http://` parameter entity is
    /// fetched — really, when it points at the dev Beacon); the safe twin refuses DTDs.
    static func xml(_ body: String, safe: Bool) -> VulnReply {
        if safe, body.range(of: "<!DOCTYPE", options: .caseInsensitive) != nil {
            return text("DTDs are not allowed.\n", status: 400)
        }
        var document = body
        if !safe,
            let regex = try? NSRegularExpression(
                pattern: #"<!ENTITY\s+(%\s+)?(\w+)\s+SYSTEM\s+"([^"]+)"\s*>"#)
        {
            for match in regex.matches(in: body, range: NSRange(body.startIndex..., in: body)) {
                guard let nameRange = Range(match.range(at: 2), in: body),
                    let urlRange = Range(match.range(at: 3), in: body)
                else { continue }
                let parameter = match.range(at: 1).location != NSNotFound
                let name = String(body[nameRange])
                let url = String(body[urlRange])
                if url == "file:///etc/passwd", !parameter {
                    document = document.replacingOccurrences(of: "&\(name);", with: passwd)
                } else if let host = URLComponents(string: url)?.host?.lowercased(),
                    host.hasSuffix("." + OASTLab.domain)
                {
                    let path = URLComponents(string: url)?.path ?? "/"
                    Task.detached {
                        await OASTLab.lookup(host)
                        await OASTLab.get(host: host, path: path.isEmpty ? "/" : path)
                    }
                }
            }
        }
        let item: String
        if let start = document.range(of: "<item>"),
            let end = document.range(of: "</item>", range: start.upperBound..<document.endIndex)
        {
            item = String(document[start.upperBound..<end.lowerBound])
        } else {
            item = "nothing"
        }
        return text("Ordered: \(item)\n")
    }

    // MARK: guestbook

    private static let book = NSLockedMessages()
    private static let patched = LockedRoutes()

    /// POST stores `message`; GET renders the messages — unencoded here, encoded on the safe twin.
    static func guestbook(_ request: RawRequest, body: String, safe: Bool) -> VulnReply {
        let method = request.bytes[request.parsed.method].string().uppercased()
        if method == "POST" {
            let message = VulnLab.queryItems("/?" + body)["message"] ?? ""
            book.add(message, safe: safe)
            return text("Thanks for signing.\n")
        }
        let rows = book.messages(safe: safe).map { "<li>\(safe ? XSSLab.html($0) : $0)</li>" }.joined()
        let action = safe ? "/safe/guestbook" : "/guestbook"
        let page =
            "<!doctype html><html><head><title>Guestbook</title></head><body><h1>Guestbook</h1><ul>\(rows)</ul>"
            + "<form method=\"post\" action=\"\(action)\"><textarea name=\"message\"></textarea><button>Sign</button></form></body></html>"
        return VulnReply(
            bytes: VulnLab.response(200, body: Array(page.utf8), type: "text/html; charset=utf-8"))
    }
}

/// The guestbook's messages (the newest 50 per book).
final class NSLockedMessages: @unchecked Sendable {
    // @unchecked: `vulnerable`/`safe` are only touched while holding `lock`.
    private let lock = NSLock()
    private var vulnerable: [String] = []
    private var safe: [String] = []

    func add(_ message: String, safe isSafe: Bool) {
        lock.withLock {
            if isSafe {
                safe = Array((safe + [message]).suffix(50))
            } else {
                vulnerable = Array((vulnerable + [message]).suffix(50))
            }
        }
    }

    func messages(safe isSafe: Bool) -> [String] { lock.withLock { isSafe ? safe : vulnerable } }
}

/// Routes patched with `/lab/patch`.
final class LockedRoutes: @unchecked Sendable {
    // @unchecked: `routes` is only touched while holding `lock`.
    private let lock = NSLock()
    private var routes: Set<String> = []

    func insert(_ route: String) { lock.withLock { _ = routes.insert(route) } }
    func contains(_ route: String) -> Bool { lock.withLock { routes.contains(route) } }
}
