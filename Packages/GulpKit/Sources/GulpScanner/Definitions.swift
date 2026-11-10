// GulpScanner — the built-in issue definitions (F08 SCN-006): stable ids, names, default severity
// and confidence, and the background/remediation/reference texts every finding of that type carries.
// Passive definitions (F08 §3.1, M10a) are here; active ones join them in M11b/M11c. Texts are Gulp's
// own wording.

import GulpCore

/// One issue type.
public struct IssueDefinition: Sendable, Hashable, Identifiable {
    /// Stable id (`passive.cookie.no-httponly`).
    public var id: String
    /// Display name.
    public var name: String
    /// Family, for the "known issues" browser.
    public var family: String
    /// Default severity.
    public var severity: IssueSeverity
    /// Default confidence.
    public var confidence: IssueConfidence
    /// Why it matters (markdown).
    public var background: String
    /// How to fix it (markdown).
    public var remediation: String
    /// Links (markdown).
    public var references: String
}

/// The catalog (SCN-006).
public enum IssueDefinitions {
    /// Every built-in definition.
    public static let all: [IssueDefinition] = headers + cookies + disclosure + input + other + manual

    static let byID: [String: IssueDefinition] = Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) })

    /// The definition with `id`.
    public static func named(_ id: String) -> IssueDefinition? { byID[id] }

    static func def(
        _ id: String, _ name: String, _ family: String, _ severity: IssueSeverity,
        _ confidence: IssueConfidence,
        _ background: String, _ remediation: String, _ references: String = ""
    ) -> IssueDefinition {
        IssueDefinition(
            id: id, name: name, family: family, severity: severity, confidence: confidence,
            background: background,
            remediation: remediation, references: references)
    }

    static let mdn = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
    static let owasp = "https://cheatsheetseries.owasp.org/cheatsheets/"

    static let headers: [IssueDefinition] = [
        def(
            "passive.csp.missing", "Content Security Policy missing", "Security headers", .low, .certain,
            "Without a `Content-Security-Policy`, the browser runs any script an injection manages to place in the page, so a single XSS bug has full effect.",
            "Send a CSP that allows only the scripts the page needs (nonces or hashes for inline code), with `object-src 'none'` and `base-uri 'self'`.",
            "- [CSP](\(mdn)Content-Security-Policy)\n- [OWASP CSP cheat sheet](\(owasp)Content_Security_Policy_Cheat_Sheet.html)"
        ),
        def(
            "passive.csp.weak", "Weak Content Security Policy", "Security headers", .low, .firm,
            "The policy allows `'unsafe-inline'`, `'unsafe-eval'`, a wildcard or a scheme-wide script source, which lets injected scripts run anyway.",
            "Remove `'unsafe-inline'`/`'unsafe-eval'` and wildcard sources from `script-src` (or `default-src`); use nonces or hashes.",
            "- [CSP](\(mdn)Content-Security-Policy)"),
        def(
            "passive.hsts.missing", "Strict-Transport-Security missing", "Security headers", .low, .certain,
            "Without HSTS, a user who types the host name or follows an `http://` link can be intercepted before the redirect to HTTPS (SSL stripping).",
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses.",
            "- [HSTS](\(mdn)Strict-Transport-Security)"),
        def(
            "passive.nosniff.missing", "X-Content-Type-Options missing", "Security headers", .info, .certain,
            "Browsers may guess (sniff) a response's type from its content, which can turn an uploaded or reflected text file into executable script or HTML.",
            "Send `X-Content-Type-Options: nosniff` on every response.",
            "- [X-Content-Type-Options](\(mdn)X-Content-Type-Options)"),
        def(
            "passive.clickjacking", "Frameable response (clickjacking)", "Security headers", .low, .firm,
            "The page can be shown inside a frame on another site, where an attacker can overlay it and trick the user into clicking its controls.",
            "Send `Content-Security-Policy: frame-ancestors 'self'` (or `'none'`), and `X-Frame-Options: DENY` for older browsers.",
            "- [frame-ancestors](\(mdn)Content-Security-Policy/frame-ancestors)\n- [OWASP clickjacking](\(owasp)Clickjacking_Defense_Cheat_Sheet.html)"
        ),
        def(
            "passive.referrer-policy.missing", "Referrer-Policy missing", "Security headers", .info, .certain,
            "Without a policy, older browsers send the full URL (with query parameters that may hold tokens) to other sites in the `Referer` header.",
            "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
            "- [Referrer-Policy](\(mdn)Referrer-Policy)"),
        def(
            "passive.permissions-policy.missing", "Permissions-Policy missing", "Security headers", .info,
            .certain,
            "Without a Permissions-Policy, embedded content may request powerful features (camera, geolocation…) the page never needs.",
            "Send a `Permissions-Policy` that disables the features the page doesn't use.",
            "- [Permissions-Policy](\(mdn)Permissions-Policy)"),
    ]

    static let cookies: [IssueDefinition] = [
        def(
            "passive.cookie.no-httponly", "Cookie without HttpOnly", "Cookies", .low, .certain,
            "Scripts can read the cookie, so an XSS bug can steal it (session hijacking).",
            "Set the `HttpOnly` attribute on cookies scripts don't need, and always on session cookies.",
            "- [Set-Cookie](\(mdn)Set-Cookie)"),
        def(
            "passive.cookie.no-secure", "Cookie without Secure", "Cookies", .low, .certain,
            "The cookie is also sent over plain HTTP, where anyone on the network path can read it.",
            "Set the `Secure` attribute on cookies issued over HTTPS.",
            "- [Set-Cookie](\(mdn)Set-Cookie)"),
        def(
            "passive.cookie.no-samesite", "Cookie without SameSite", "Cookies", .info, .certain,
            "Without an explicit `SameSite`, the cookie's cross-site behaviour depends on the browser; `SameSite=None` without `Secure` is rejected.",
            "Set `SameSite=Lax` (or `Strict`) on session cookies; use `None` only with `Secure` when cross-site use is required.",
            "- [SameSite](\(mdn)Set-Cookie#samesitesamesite-value)"),
        def(
            "passive.cookie.broad-domain", "Cookie scoped to a parent domain", "Cookies", .info, .firm,
            "A `Domain` attribute naming a parent domain sends the cookie to every sibling subdomain, any of which could read or overwrite it.",
            "Omit `Domain` (host-only cookie) unless sharing is required.",
            "- [Set-Cookie Domain](\(mdn)Set-Cookie#domaindomain-value)"),
    ]

    static let disclosure: [IssueDefinition] = [
        def(
            "passive.disclosure.stack-trace", "Stack trace or debug error", "Information disclosure", .low,
            .firm,
            "Error pages with stack traces reveal frameworks, versions, file paths and code structure that help an attacker.",
            "Show a generic error page in production and log details on the server.",
            "- [OWASP error handling](\(owasp)Error_Handling_Cheat_Sheet.html)"),
        def(
            "passive.disclosure.server-version", "Server version disclosed", "Information disclosure", .info,
            .certain,
            "A `Server` or `X-Powered-By` header with a version number tells an attacker which known vulnerabilities to try.",
            "Remove version numbers (or the headers) from responses."),
        def(
            "passive.disclosure.internal-ip", "Private IP address disclosed", "Information disclosure", .info,
            .firm,
            "A private (RFC 1918) address in a response reveals internal network layout.",
            "Remove internal addresses from responses (proxies, error pages, headers)."),
        def(
            "passive.disclosure.directory-listing", "Directory listing", "Information disclosure", .low,
            .firm,
            "The server lists a directory's files, exposing content that was never linked.",
            "Disable directory listings."),
        def(
            "passive.disclosure.git", "Exposed Git repository", "Information disclosure", .high, .certain,
            "A readable `.git` directory lets anyone download the source code and its history, often with secrets.",
            "Block access to `.git` (and other VCS directories) on the web server, and don't deploy them."),
        def(
            "passive.disclosure.env-file", "Exposed environment file", "Information disclosure", .high,
            .certain,
            "A readable `.env` file usually holds credentials, API keys and connection strings.",
            "Remove the file from the web root and rotate every secret it contained."),
        def(
            "passive.disclosure.backup-file", "Backup or temporary file served", "Information disclosure",
            .low, .firm,
            "Backup copies (`~`, `.bak`, `.old`, archives) are served as plain files, often exposing source code or configuration.",
            "Remove backup files from the web root and block such extensions."),
        def(
            "passive.disclosure.secret-in-comment", "Secret in an HTML comment", "Information disclosure",
            .low, .tentative,
            "An HTML comment contains what looks like a credential or key, readable by every visitor.",
            "Remove secrets from markup and rotate them."),
        def(
            "passive.form.password-autocomplete", "Password field with autocomplete",
            "Information disclosure", .info, .certain,
            "Browsers may store the password; on shared machines another user can recover it.",
            "Use `autocomplete=\"current-password\"`/`\"new-password\"` deliberately, or `off` where storage isn't wanted."
        ),
    ]

    static let input: [IssueDefinition] = [
        def(
            "passive.reflection", "Input reflected in the response", "Input handling", .info, .certain,
            "A request parameter's value appears in the response. Reflection is where injection bugs (XSS, header or template injection) start; this is a signpost for testing, not proof.",
            "Encode output for its context (HTML text, attribute, script, URL)."),
        def(
            "passive.reflection.unencoded", "Input reflected without encoding (potential XSS)",
            "Input handling", .low, .firm,
            "Characters that are special in the reflection's context (`<`, `>`, quotes) come back unencoded, which usually allows script injection.",
            "Encode output for its context, and add a strict CSP as defence in depth.",
            "- [OWASP XSS prevention](\(owasp)Cross_Site_Scripting_Prevention_Cheat_Sheet.html)"),
        def(
            "passive.open-redirect", "Redirect to a user-supplied URL", "Input handling", .low, .tentative,
            "A parameter's URL is used as the redirect target, which can send users to an attacker's site under the trusted domain.",
            "Redirect only to relative paths or an allowlist of destinations.",
            "- [OWASP unvalidated redirects](\(owasp)Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)"),
        def(
            "passive.form.no-csrf-token", "Form without an anti-CSRF token", "Input handling", .low,
            .tentative,
            "A state-changing (POST) form carries no token, so another site may be able to submit it on the user's behalf.",
            "Add a per-session (or per-request) token checked on submission, and use SameSite cookies.",
            "- [OWASP CSRF](\(owasp)Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)"),
        def(
            "passive.form.cross-domain-action", "Form submits to another domain", "Input handling", .info,
            .certain,
            "The form sends its fields to a different host, which then receives everything the user types.",
            "Check that the destination is intended and trusted."),
        def(
            "passive.form.password-cleartext", "Password submitted in cleartext", "Input handling", .medium,
            .certain,
            "A password field is submitted over plain HTTP, readable by anyone on the network path.",
            "Serve the form and its target over HTTPS only."),
    ]

    /// Findings written by a person (a Notebook item promoted to an issue, F14 NB-005).
    static let manual: [IssueDefinition] = [
        def(
            "manual.finding", "Manual finding", "Manual", .medium, .firm,
            "Found by hand during testing; see the detail and the evidence.", "See the detail.")
    ]

    static let other: [IssueDefinition] = [
        def(
            "passive.cors.credentials-reflected", "CORS reflects any origin with credentials", "CORS", .high,
            .firm,
            "`Access-Control-Allow-Origin` echoes the request's `Origin` (or allows `null`) with `Access-Control-Allow-Credentials: true`, so any website can read this response with the user's cookies.",
            "Allow only a fixed list of trusted origins, and never `null`.",
            "- [CORS](\(mdn)Access-Control-Allow-Origin)"),
        def(
            "passive.cors.wildcard", "CORS allows any origin", "CORS", .info, .certain,
            "`Access-Control-Allow-Origin: *` lets any website read this response (without cookies). Fine for public data, a leak otherwise.",
            "Restrict the allowed origins if the response isn't public."),
        def(
            "passive.cache.sensitive", "Sensitive response may be cached", "Caching", .info, .tentative,
            "A response to an authenticated request (or one setting a session cookie) can be stored by browsers or shared caches.",
            "Send `Cache-Control: no-store` on responses with personal or session data."),
        def(
            "passive.content-type.missing", "Content-Type missing", "Content type", .info, .certain,
            "Without a declared type the browser sniffs the content, which can make data render as HTML or script.",
            "Send an accurate `Content-Type` on every response with a body."),
        def(
            "passive.charset.missing", "HTML without a character set", "Content type", .info, .certain,
            "Without a declared charset the browser guesses, and some encodings let attacker-supplied bytes become markup.",
            "Send `Content-Type: text/html; charset=utf-8`."),
        def(
            "passive.mixed-content", "Mixed content", "TLS", .low, .certain,
            "An HTTPS page loads scripts, styles or frames over HTTP, which a network attacker can replace.",
            "Load every sub-resource over HTTPS."),
        def(
            "passive.tls.weak-protocol", "Weak TLS protocol", "TLS", .medium, .certain,
            "The server negotiated TLS 1.0 or 1.1, which are deprecated and have known weaknesses.",
            "Allow only TLS 1.2 and 1.3."),
    ]
}
