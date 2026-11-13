// GulpScanner — the passive checks (F08 §3.1). Each inspects one exchange and returns findings; none
// sends anything. Page-level header issues are per path; host-wide ones (HSTS, version banners,
// cookies, TLS) use the path `/` so they are reported once per origin. Checks that only make sense on
// a real network (cleartext password, HSTS, Secure cookies) don't fire on plaintext loopback, where
// every route would trip them (doc 06 §3, "plaintext-localhost checks").

import Foundation
import GulpCore

/// Passive-scan settings.
public struct PassiveScanSettings: Sendable, Hashable, Codable {
    /// Issue type ids not to report.
    public var disabled: Set<String> = []
    /// Run the secret & JS-endpoint recon checks (F27). Off by default (it is noisier and opt-in).
    public var recon: Bool = false
    /// User-authored Check Recipes to run alongside the built-ins (SCN-064).
    public var recipes: [CheckRecipe] = []

    /// All checks on.
    public init() {}
}

/// Runs every passive check on an exchange.
public struct PassiveScanner: Sendable {
    /// Settings.
    public var settings: PassiveScanSettings

    /// A scanner.
    public init(settings: PassiveScanSettings = PassiveScanSettings()) {
        self.settings = settings
    }

    /// The findings for `exchange` (none without a response).
    public func scan(_ exchange: Exchange) -> [IssueFinding] {
        guard let message = PassiveMessage(exchange) else { return [] }
        var findings: [IssueFinding] = []
        findings += PassiveChecks.securityHeaders(message)
        findings += PassiveChecks.cookies(message)
        findings += PassiveChecks.disclosure(message)
        findings += PassiveChecks.reflection(message)
        findings += PassiveChecks.redirects(message)
        findings += PassiveChecks.forms(message)
        findings += PassiveChecks.cors(message)
        findings += PassiveChecks.caching(message)
        findings += PassiveChecks.transport(message)
        findings += VulnLibraryCheck.scan(message)
        if settings.recon { findings += ReconChecks.scan(message) }
        if !settings.recipes.isEmpty { findings += CheckRecipes.scan(settings.recipes, message) }
        return findings.filter { !settings.disabled.contains($0.typeID) }
    }
}

enum PassiveChecks {
    static func d(_ id: String) -> IssueDefinition {
        guard let definition = IssueDefinitions.named(id) else {
            preconditionFailure("unknown definition \(id)")
        }
        return definition
    }

    static func isLoopback(_ host: String) -> Bool {
        let host = host.lowercased()
        return host == "localhost" || host.hasPrefix("127.") || host == "::1" || host == "[::1]"
            || host.hasSuffix(".localhost")
    }

    static func matches(
        _ pattern: String, _ text: String, options: NSRegularExpression.Options = [.caseInsensitive]
    )
        -> String?
    {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: options),
            let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
            let range = Range(match.range, in: text)
        else { return nil }
        return String(text[range])
    }

    // MARK: security headers

    static func securityHeaders(_ m: PassiveMessage) -> [IssueFinding] {
        var findings: [IssueFinding] = []
        let ok = (200..<300).contains(m.status) && m.status != 204
        let hasBody = !m.body.isEmpty
        if ok, hasBody, m.header("x-content-type-options")?.lowercased().contains("nosniff") != true {
            findings.append(
                m.finding(
                    d("passive.nosniff.missing"),
                    detail: "The response has no `X-Content-Type-Options: nosniff`.",
                    responseMarkers: [m.statusLineMarker]))
        }
        if hasBody, m.header("content-type") == nil {
            findings.append(
                m.finding(
                    d("passive.content-type.missing"),
                    detail: "The response has a body but no `Content-Type`.",
                    responseMarkers: [m.statusLineMarker]))
        }
        if m.isHTML, ok, let type = m.headers("content-type").last,
            !type.value.lowercased().contains("charset"),
            !m.body.lowercased().contains("<meta charset")
        {
            findings.append(
                m.finding(
                    d("passive.charset.missing"),
                    detail: "`Content-Type: \(type.value)` names no character set.",
                    responseMarkers: [type.marker]))
        }
        if m.isHTTPS, ok, m.header("strict-transport-security") == nil {
            findings.append(
                m.finding(
                    d("passive.hsts.missing"), path: "/",
                    detail: "HTTPS responses from `\(m.origin)` carry no `Strict-Transport-Security` header.",
                    responseMarkers: [m.statusLineMarker]))
        }
        guard m.isHTML, ok, hasBody else { return findings }
        let csp = m.headers("content-security-policy")
        if csp.isEmpty {
            findings.append(
                m.finding(
                    d("passive.csp.missing"),
                    detail: "The HTML page has no `Content-Security-Policy` header.",
                    responseMarkers: [m.statusLineMarker]))
        } else if let weakness = weakCSP(csp.map(\.value).joined(separator: "; ")) {
            findings.append(
                m.finding(
                    d("passive.csp.weak"), detail: "The policy's script sources allow \(weakness).",
                    responseMarkers: csp.map(\.marker)))
        }
        let frameAncestors = csp.contains { $0.value.lowercased().contains("frame-ancestors") }
        let xfo = m.header("x-frame-options")?.lowercased() ?? ""
        if !frameAncestors, !(xfo.contains("deny") || xfo.contains("sameorigin")) {
            findings.append(
                m.finding(
                    d("passive.clickjacking"),
                    detail:
                        "Neither `X-Frame-Options` nor a CSP `frame-ancestors` directive stops other sites framing this page.",
                    responseMarkers: [m.statusLineMarker]))
        }
        if m.header("referrer-policy") == nil {
            findings.append(
                m.finding(
                    d("passive.referrer-policy.missing"),
                    detail: "The HTML page has no `Referrer-Policy` header.",
                    responseMarkers: [m.statusLineMarker]))
        }
        if m.header("permissions-policy") == nil {
            findings.append(
                m.finding(
                    d("passive.permissions-policy.missing"),
                    detail: "The HTML page has no `Permissions-Policy` header.",
                    responseMarkers: [m.statusLineMarker]))
        }
        return findings
    }

    /// What makes a policy's script sources weak, or nil.
    static func weakCSP(_ policy: String) -> String? {
        var directives: [String: [String]] = [:]
        for part in policy.split(separator: ";") {
            let tokens = part.split(whereSeparator: \.isWhitespace).map { $0.lowercased() }
            guard let name = tokens.first, directives[name] == nil else { continue }
            directives[name] = Array(tokens.dropFirst())
        }
        guard let sources = directives["script-src"] ?? directives["default-src"] else {
            return "anything (no `script-src` or `default-src`)"
        }
        let hasNonceOrHash = sources.contains { $0.hasPrefix("'nonce-") || $0.hasPrefix("'sha") }
        let strictDynamic = sources.contains("'strict-dynamic'")
        if sources.contains("'unsafe-inline'"), !hasNonceOrHash { return "`'unsafe-inline'`" }
        if sources.contains("'unsafe-eval'") { return "`'unsafe-eval'`" }
        if !strictDynamic,
            let wide = sources.first(where: { ["*", "http:", "https:", "data:"].contains($0) })
        {
            return "`\(wide)`"
        }
        return nil
    }

    // MARK: cookies

    static func cookies(_ m: PassiveMessage) -> [IssueFinding] {
        var findings: [IssueFinding] = []
        let host = m.exchange.target.host.lowercased()
        for header in m.headers("set-cookie") {
            let parts = header.value.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
            guard let pair = parts.first, let name = pair.split(separator: "=").first.map(String.init),
                !name.isEmpty
            else { continue }
            var attributes: [String: String] = [:]
            for attribute in parts.dropFirst() {
                let kv = attribute.split(separator: "=", maxSplits: 1).map(String.init)
                attributes[kv[0].lowercased()] = kv.count > 1 ? kv[1] : ""
            }
            // A cookie being deleted (expired / Max-Age=0) protects nothing.
            if attributes["max-age"] == "0" { continue }
            func report(_ id: String, _ detail: String) {
                findings.append(
                    m.finding(
                        d(id), path: "/", insertionPoint: name, detail: detail,
                        responseMarkers: [header.marker],
                        note: "Set-Cookie: \(name)"))
            }
            if attributes["httponly"] == nil {
                report("passive.cookie.no-httponly", "Cookie `\(name)` is set without `HttpOnly`.")
            }
            if m.isHTTPS, attributes["secure"] == nil {
                report("passive.cookie.no-secure", "Cookie `\(name)` is set over HTTPS without `Secure`.")
            }
            let sameSite = attributes["samesite"]?.lowercased()
            if sameSite == nil {
                report("passive.cookie.no-samesite", "Cookie `\(name)` has no `SameSite` attribute.")
            } else if sameSite == "none", attributes["secure"] == nil {
                report(
                    "passive.cookie.no-samesite", "Cookie `\(name)` uses `SameSite=None` without `Secure`.")
            }
            if let domain = attributes["domain"]?.lowercased().trimmingCharacters(
                in: CharacterSet(charactersIn: ".")),
                !domain.isEmpty, domain != host, host.hasSuffix("." + domain)
            {
                report(
                    "passive.cookie.broad-domain",
                    "Cookie `\(name)` is scoped to `\(domain)`, a parent of `\(host)`.")
            }
        }
        return findings
    }

    // MARK: information disclosure

    static let stackTraces: [(String, String)] = [
        ("Java", #"\bat [\w$.]+\([\w$]+\.java:\d+\)"#),
        ("Python", #"Traceback \(most recent call last\)"#),
        (".NET", #"(\bat [\w.<>]+\(.*\) in .+:line \d+|Server Error in '/' Application)"#),
        ("PHP", #"(Fatal error|Parse error|Warning)(</b>)?:.+ on line (<b>)?\d+"#),
        ("Node.js", #"\n\s+at .+ \((/|[A-Za-z]:\\)[^)]+:\d+:\d+\)"#),
        ("Ruby", #"\.rb:\d+:in `"#),
        ("Go", #"goroutine \d+ \[running\]"#),
    ]

    static func disclosure(_ m: PassiveMessage) -> [IssueFinding] {
        var findings: [IssueFinding] = []
        for (language, pattern) in stackTraces {
            if let found = matches(pattern, m.body, options: []) {
                findings.append(
                    m.finding(
                        d("passive.disclosure.stack-trace"), variant: language,
                        detail: "The response contains a \(language) stack trace or debug error.",
                        responseMarkers: m.bodyMarker(found).map { [$0] } ?? []))
                break
            }
        }
        for name in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"] {
            guard let header = m.headers(name).last, header.value.contains(where: \.isNumber),
                matches(#"[A-Za-z][\w.\- ]*/?\s*v?\d+(\.\d+)+"#, header.value) != nil
            else { continue }
            findings.append(
                m.finding(
                    d("passive.disclosure.server-version"), path: "/", insertionPoint: name,
                    detail: "`\(name): \(header.value)` names the software and its version.",
                    responseMarkers: [header.marker]))
        }
        let privateIP =
            #"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"#
        let headerText = m.response.bytes[0..<m.response.parsed.headerBlockEnd].string()
        if let ip = matches(privateIP, headerText + "\n" + m.body), ip != m.exchange.target.host {
            findings.append(
                m.finding(
                    d("passive.disclosure.internal-ip"),
                    detail: "The response mentions the private address `\(ip)`.",
                    responseMarkers: m.bodyMarker(ip).map { [$0] } ?? []))
        }
        guard m.status == 200 else { return findings }
        if m.isHTML, let found = matches(#"<title>\s*(Index of /|Directory listing for /)"#, m.body) {
            findings.append(
                m.finding(
                    d("passive.disclosure.directory-listing"),
                    detail: "The page is a server-generated directory listing.",
                    responseMarkers: m.bodyMarker(found).map { [$0] } ?? []))
        }
        let lowerPath = m.path.lowercased()
        if lowerPath.contains("/.git/") || lowerPath.hasSuffix("/.git"),
            m.body.hasPrefix("ref: refs/") || m.body.contains("repositoryformatversion")
                || m.body.contains("[core]")
        {
            findings.append(
                m.finding(
                    d("passive.disclosure.git"), path: "/.git",
                    detail: "`\(m.path)` serves Git repository metadata.",
                    responseMarkers: m.bodyMarker(String(m.body.prefix(40))).map { [$0] } ?? []))
        }
        let last = lowerPath.split(separator: "/").last.map(String.init) ?? ""
        if last == ".env" || last.hasPrefix(".env."),
            let line = matches(#"(?m)^[A-Z_][A-Z0-9_]*=.*$"#, m.body, options: [])
        {
            findings.append(
                m.finding(
                    d("passive.disclosure.env-file"), detail: "`\(m.path)` serves an environment file.",
                    responseMarkers: m.bodyMarker(line).map { [$0] } ?? []))
        }
        let backupSuffixes = ["~", ".bak", ".old", ".orig", ".swp", ".save", ".tmp"]
        let isArchiveBackup =
            matches(
                #"(backup|bak|old|dump|db|site|www|src|source)[^/]*\.(zip|tar|tar\.gz|tgz|7z|rar|gz)$"#, last)
            != nil
        if backupSuffixes.contains(where: { last.hasSuffix($0) }) || isArchiveBackup {
            findings.append(
                m.finding(
                    d("passive.disclosure.backup-file"),
                    detail: "`\(m.path)` looks like a backup or temporary file.",
                    responseMarkers: [m.statusLineMarker]))
        }
        if m.isHTML {
            let secret =
                #"<!--(?:(?!-->).)*?((password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\s*[:=]\s*\S+|AKIA[0-9A-Z]{16})(?:(?!-->).)*-->"#
            if let comment = matches(secret, m.body, options: [.caseInsensitive, .dotMatchesLineSeparators]) {
                findings.append(
                    m.finding(
                        d("passive.disclosure.secret-in-comment"),
                        detail: "An HTML comment looks like it holds a secret.",
                        responseMarkers: m.bodyMarker(comment).map { [$0] } ?? []))
            }
            for input in m.tags("input") where input["type"]?.lowercased() == "password" {
                let autocomplete = input["autocomplete"]?.lowercased()
                guard autocomplete == nil || autocomplete == "on" else { continue }
                findings.append(
                    m.finding(
                        d("passive.form.password-autocomplete"), insertionPoint: input["name"],
                        detail: "Password field `\(input["name"] ?? "?")` doesn't set `autocomplete`."))
                break
            }
        }
        return findings
    }

    // MARK: input reflection and redirects

    static func reflection(_ m: PassiveMessage) -> [IssueFinding] {
        guard
            m.isHTML || m.mime.contains("javascript") || m.mime.contains("json") || m.mime.hasPrefix("text/")
        else { return [] }
        var findings: [IssueFinding] = []
        for param in m.params where param.value.count >= 4 {
            guard let found = m.body.range(of: param.value) else { continue }
            let context = reflectionContext(m.body, at: found.lowerBound)
            let special = param.value.contains { "<>\"'".contains($0) }
            let requestMarkers = m.requestMarker(param.raw).map { [$0] } ?? []
            let responseMarkers = m.bodyMarker(param.value).map { [$0] } ?? []
            if special {
                findings.append(
                    m.finding(
                        d("passive.reflection.unencoded"), insertionPoint: param.name, variant: context,
                        detail:
                            "`\(param.name)` is reflected in \(context) context with `<`, `>` or quotes intact.",
                        requestMarkers: requestMarkers, responseMarkers: responseMarkers))
            } else {
                findings.append(
                    m.finding(
                        d("passive.reflection"), insertionPoint: param.name, variant: context,
                        detail: "The value of `\(param.name)` appears in the response (\(context) context).",
                        requestMarkers: requestMarkers, responseMarkers: responseMarkers))
            }
        }
        return findings
    }

    /// Where `index` sits in an HTML document: script, attribute or HTML text.
    static func reflectionContext(_ html: String, at index: String.Index) -> String {
        let before = html[..<index]
        if let open = before.range(of: "<script", options: [.backwards, .caseInsensitive]),
            before[open.upperBound...].range(of: "</script", options: .caseInsensitive) == nil
        {
            return "script"
        }
        if let lt = before.lastIndex(of: "<"), before[lt...].lastIndex(of: ">") == nil {
            let tag = before[lt...]
            if tag.range(
                of: #"(href|src|action)\s*=\s*["']?$"#, options: [.regularExpression, .caseInsensitive])
                != nil
            {
                return "URL attribute"
            }
            return "attribute"
        }
        return "HTML"
    }

    static func redirects(_ m: PassiveMessage) -> [IssueFinding] {
        guard (300..<400).contains(m.status), let location = m.headers("location").last else { return [] }
        let target = location.value.trimmingCharacters(in: .whitespaces)
        let ownHost = m.exchange.target.host.lowercased()
        return m.params.compactMap { param in
            let value = param.value
            guard value.hasPrefix("http://") || value.hasPrefix("https://") || value.hasPrefix("//"),
                target.hasPrefix(value),
                let host = URLComponents(string: value.hasPrefix("//") ? "http:" + value : value)?.host,
                host.lowercased() != ownHost
            else { return nil }
            return m.finding(
                d("passive.open-redirect"), insertionPoint: param.name,
                detail: "`\(param.name)=\(value)` became the redirect target `Location: \(target)`.",
                requestMarkers: m.requestMarker(param.raw).map { [$0] } ?? [],
                responseMarkers: [location.marker])
        }
    }

    // MARK: forms

    static let csrfNames = #"(csrf|xsrf|token|authenticity|nonce|__requestverificationtoken)"#

    static func forms(_ m: PassiveMessage) -> [IssueFinding] {
        guard m.isHTML, m.status == 200 else { return [] }
        var findings: [IssueFinding] = []
        let ownHost = m.exchange.target.host.lowercased()
        for (attributes, inner) in m.forms() {
            let action = attributes["action"] ?? ""
            let method = attributes["method"]?.lowercased() ?? "get"
            let inputs = PassiveMessage.tags("input", in: inner)
            let actionHost = URLComponents(string: action)?.host?.lowercased()
            let hasPassword = inputs.contains { $0["type"]?.lowercased() == "password" }
            if method == "post", !inputs.contains(where: { matches(csrfNames, $0["name"] ?? "") != nil }) {
                findings.append(
                    m.finding(
                        d("passive.form.no-csrf-token"), variant: action,
                        detail:
                            "The POST form to `\(action.isEmpty ? m.path : action)` has no anti-CSRF token field.",
                        responseMarkers: m.bodyMarker("<form").map { [$0] } ?? []))
            }
            if let actionHost, actionHost != ownHost {
                findings.append(
                    m.finding(
                        d("passive.form.cross-domain-action"), variant: actionHost,
                        detail: "A form submits to `\(action)`, another host."))
            }
            let cleartextAction = action.lowercased().hasPrefix("http://")
            let cleartextPage =
                !m.isHTTPS && !action.lowercased().hasPrefix("https://") && !isLoopback(ownHost)
            if hasPassword, cleartextAction || cleartextPage {
                findings.append(
                    m.finding(
                        d("passive.form.password-cleartext"), variant: action,
                        detail:
                            "A password field is submitted to `\(action.isEmpty ? m.path : action)` over HTTP."
                    ))
            }
        }
        return findings
    }

    // MARK: CORS, caching, transport

    static func cors(_ m: PassiveMessage) -> [IssueFinding] {
        guard let allow = m.headers("access-control-allow-origin").last else { return [] }
        let credentials = m.header("access-control-allow-credentials")?.lowercased() == "true"
        let origin = m.exchange.request.headerValue("origin")?.string()
        let value = allow.value.trimmingCharacters(in: .whitespaces)
        if credentials,
            value == "null" || (origin != nil && value == origin && value.lowercased() != m.origin)
        {
            return [
                m.finding(
                    d("passive.cors.credentials-reflected"),
                    detail: value == "null"
                        ? "`Access-Control-Allow-Origin: null` with credentials allowed."
                        : "The request's `Origin: \(origin ?? "")` is echoed in `Access-Control-Allow-Origin` with credentials allowed.",
                    requestMarkers: origin.flatMap { m.requestMarker($0) }.map { [$0] } ?? [],
                    responseMarkers: [allow.marker])
            ]
        }
        if value == "*" {
            return [
                m.finding(
                    d("passive.cors.wildcard"), detail: "`Access-Control-Allow-Origin: *`.",
                    responseMarkers: [allow.marker])
            ]
        }
        return []
    }

    static func caching(_ m: PassiveMessage) -> [IssueFinding] {
        guard m.status == 200 else { return [] }
        let authenticated = m.exchange.request.headerValue("authorization") != nil
        let setsSession = !m.headers("set-cookie").isEmpty
        guard authenticated || setsSession else { return [] }
        let cacheControl = m.header("cache-control")?.lowercased() ?? ""
        guard !cacheControl.contains("no-store"), !cacheControl.contains("private") else { return [] }
        return [
            m.finding(
                d("passive.cache.sensitive"),
                detail: authenticated
                    ? "An authenticated response has no `Cache-Control: no-store` or `private`."
                    : "A response that sets a cookie has no `Cache-Control: no-store` or `private`.",
                responseMarkers: [m.statusLineMarker])
        ]
    }

    static func transport(_ m: PassiveMessage) -> [IssueFinding] {
        var findings: [IssueFinding] = []
        if let version = m.exchange.tls?.version.lowercased().replacingOccurrences(of: " ", with: ""),
            ["tlsv1", "tlsv1.0", "tlsv1.1", "tls1.0", "tls1.1", "sslv3"].contains(version)
        {
            findings.append(
                m.finding(
                    d("passive.tls.weak-protocol"), path: "/",
                    detail: "The connection to `\(m.origin)` used \(m.exchange.tls?.version ?? version)."))
        }
        if m.isHTTPS, m.isHTML {
            let insecure =
                #"<(script|iframe|frame|embed|object)\b[^>]*\bsrc\s*=\s*["']?http://[^"'\s>]+|<link\b[^>]*\bhref\s*=\s*["']?http://[^"'\s>]+"#
            if let found = matches(insecure, m.body) {
                findings.append(
                    m.finding(
                        d("passive.mixed-content"), detail: "The HTTPS page loads `\(found)` over HTTP.",
                        responseMarkers: m.bodyMarker(found).map { [$0] } ?? []))
            }
        }
        return findings
    }
}
