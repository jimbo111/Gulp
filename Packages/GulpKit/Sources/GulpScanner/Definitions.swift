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
    public static let all: [IssueDefinition] =
        headers + cookies + disclosure + input + other + manual + active

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
            "Found by hand during testing; see the detail and the evidence.", "See the detail."),
        def(
            "authz.broken-access-control", "Broken access control", "Access control", .high, .firm,
            "A request succeeded for an identity that should not be allowed to make it: a lower-privilege or unauthenticated user received the same response as the authorized user. The server is not checking who is asking (IDOR / missing authorization).",
            "Enforce an ownership/role check on the server for every request, not just in the UI; deny by default and verify the caller owns or may access the object.",
            "- [OWASP broken access control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)"),
        def(
            "graphql.introspection-enabled", "GraphQL introspection enabled", "GraphQL", .low, .certain,
            "The GraphQL endpoint answers introspection queries, so anyone can read the full schema (types, queries, mutations and arguments) and map the API's attack surface.",
            "Disable introspection in production, or restrict it to trusted clients.",
            "- [OWASP GraphQL cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)"
        ),
        def(
            "graphql.broken-object-authz", "GraphQL broken object/field authorization", "GraphQL", .high,
            .firm,
            "A GraphQL field returned another object's or user's data to a caller who should not see it (object- or field-level authorization is missing). GraphQL hides many objects behind one endpoint, so a missing check exposes them all.",
            "Enforce authorization in the resolver for every field that returns user- or tenant-scoped data, not just at the query root.",
            "- [OWASP GraphQL cheat sheet: authorization](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#authorization)"
        ),
        def(
            "recon.secret", "Secret or credential in a response", "Recon", .high, .firm,
            "A response (or a JavaScript file it serves) contains what looks like a real secret — an API key, token, private key or high-entropy credential. Anything a client can fetch is not a secret.",
            "Remove the secret from client-delivered content, rotate it, and move it server-side; scan build output for secrets in CI.",
            "- [OWASP secrets management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)"
        ),
        def(
            "recon.endpoint", "Endpoints discovered in JavaScript", "Recon", .info, .certain,
            "URLs and API paths were found hard-coded in JavaScript. They widen the known attack surface (hidden or admin endpoints) even when nothing links to them.",
            "Informational — review the endpoints for ones that should not be reachable or that lack authorization.",
            "- [OWASP testing guide](https://owasp.org/www-project-web-security-testing-guide/)"),
        def(
            "passive.vuln-js-library", "Vulnerable JavaScript library", "Vulnerable library", .medium, .firm,
            "The page loads a JavaScript library whose version has a known, publicly-documented vulnerability. Even if nothing on this page triggers it, shipping a vulnerable library is a finding and often an easy win.",
            "Upgrade the library to a fixed version; remove unused libraries; track dependencies with an SCA tool.",
            "- [OWASP: using components with known vulnerabilities](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)"
        ),
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

    /// Active-check definitions (F08 §3.2, M11b).
    static let active: [IssueDefinition] = [
        def(
            "active.xss.reflected", "Cross-site scripting (reflected)", "XSS", .high, .firm,
            "Input is copied into the page without encoding for its context, so a crafted link runs the attacker's script in the victim's session — stealing data, acting as the user or rewriting the page.",
            "Encode output for the exact context (HTML text, attribute, JavaScript string, URL) with a templating engine that escapes by default; validate URLs to allow only http(s); add a strict CSP as defense in depth.",
            "- [OWASP XSS prevention](\(owasp)Cross_Site_Scripting_Prevention_Cheat_Sheet.html)"),
        def(
            "active.xss.stored", "Cross-site scripting (stored)", "XSS", .high, .firm,
            "Submitted data is stored and later rendered without encoding, so every visitor of the page runs the attacker's script.",
            "Encode stored data when rendering it, for its context; sanitize rich text with an allowlist sanitizer; add a strict CSP.",
            "- [OWASP XSS prevention](\(owasp)Cross_Site_Scripting_Prevention_Cheat_Sheet.html)"),
        def(
            "active.sqli.error", "SQL injection (error-based)", "SQL injection", .high, .firm,
            "Input changes the structure of a database query: a quote broke the query and the database error came back, so an attacker can read or change data.",
            "Use parameterized queries (prepared statements) everywhere; never build SQL by concatenating input. Don't show database errors to users.",
            "- [OWASP SQL injection prevention](\(owasp)SQL_Injection_Prevention_Cheat_Sheet.html)"),
        def(
            "active.sqli.boolean", "SQL injection (boolean-based)", "SQL injection", .high, .firm,
            "True and false conditions injected into the input change the page consistently, so the input reaches a SQL query unsanitized and data can be extracted bit by bit.",
            "Use parameterized queries; never build SQL from input.",
            "- [OWASP SQL injection prevention](\(owasp)SQL_Injection_Prevention_Cheat_Sheet.html)"),
        def(
            "active.sqli.time", "SQL injection (time-based)", "SQL injection", .high, .firm,
            "Database sleep functions injected into the input delayed the response in proportion to the requested time, so the input is executed as SQL even though nothing visible changes.",
            "Use parameterized queries; never build SQL from input.",
            "- [OWASP SQL injection prevention](\(owasp)SQL_Injection_Prevention_Cheat_Sheet.html)"),
        def(
            "active.cmd.time", "OS command injection (time-based)", "Command injection", .high, .firm,
            "Shell metacharacters in the input start extra commands on the server (a `sleep` measurably delayed the response), giving an attacker code execution.",
            "Don't pass input to a shell. Call programs directly with an argument array, or use a library API; validate input against an allowlist.",
            "- [OWASP OS command injection defense](\(owasp)OS_Command_Injection_Defense_Cheat_Sheet.html)"),
        def(
            "active.cmd.oast", "OS command injection (out-of-band)", "Command injection", .high, .certain,
            "A command injected into the input made the server contact an attacker-controlled host, proving commands run on the server.",
            "Don't pass input to a shell; call programs with an argument array and validate input.",
            "- [OWASP OS command injection defense](\(owasp)OS_Command_Injection_Defense_Cheat_Sheet.html)"),
        def(
            "active.ssti", "Server-side template injection", "Template injection", .high, .certain,
            "Input is evaluated as a template expression on the server (arithmetic came back computed). Template engines usually allow reaching code execution from there.",
            "Never build templates from input; pass input as data to fixed templates. Use a sandboxed engine if users must author templates.",
            "- [OWASP testing guide: SSTI](https://owasp.org/www-project-web-security-testing-guide/)"),
        def(
            "active.path-traversal", "Path traversal", "File access", .high, .certain,
            "Input used as a file name can climb out of the intended directory with `../`, letting an attacker read arbitrary files such as configuration and secrets.",
            "Map user input to an allowlist of files or IDs; otherwise canonicalize the path and verify it stays inside the base directory before opening it.",
            "- [OWASP path traversal](https://owasp.org/www-community/attacks/Path_Traversal)"),
        def(
            "active.xxe.inband", "XML external entity injection", "XXE", .high, .certain,
            "The XML parser resolves external entities, so a document can pull local files into the response.",
            "Disable DTDs and external entity resolution in the XML parser (or use a parser that does so by default).",
            "- [OWASP XXE prevention](\(owasp)XML_External_Entity_Prevention_Cheat_Sheet.html)"),
        def(
            "active.xxe.oast", "XML external entity injection (out-of-band)", "XXE", .high, .certain,
            "The XML parser fetched an external entity from an attacker-controlled host, so it resolves external entities (file reads and SSRF follow).",
            "Disable DTDs and external entity resolution in the XML parser.",
            "- [OWASP XXE prevention](\(owasp)XML_External_Entity_Prevention_Cheat_Sheet.html)"),
        def(
            "active.ssrf.oast", "Server-side request forgery", "SSRF", .high, .certain,
            "The server fetches URLs taken from the request, so an attacker can make it reach internal services and cloud metadata endpoints.",
            "Fetch only from an allowlist of hosts; resolve and block private, loopback and link-local addresses (re-check after redirects); don't return fetched content verbatim.",
            "- [OWASP SSRF prevention](\(owasp)Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)"),
        def(
            "active.open-redirect", "Open redirect", "Redirects", .low, .certain,
            "The application redirects to any host named in the request, which lends the site's trust to phishing links and can leak tokens in OAuth-style flows.",
            "Redirect only to relative paths or an allowlist of hosts; reject protocol-relative (`//`) and backslash forms.",
            "- [OWASP unvalidated redirects](\(owasp)Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)"),
        def(
            "active.crlf", "HTTP response header injection (CRLF)", "Header injection", .medium, .certain,
            "Line breaks in the input end up in a response header, so an attacker can add headers (cookies, redirects) or split the response.",
            "Reject or strip CR and LF from anything placed in headers; use framework APIs that refuse them.",
            "- [OWASP CRLF injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)"),
        def(
            "active.cors", "CORS allows an untrusted origin with credentials", "CORS", .high, .certain,
            "The server reflects an arbitrary `Origin` (or `null`) into `Access-Control-Allow-Origin` and allows credentials, so any website can read this response with the user's cookies.",
            "Compare `Origin` against an exact allowlist; never reflect it, and never allow `null` with credentials.",
            "- [OWASP HTML5 security: CORS](\(owasp)HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing)"
        ),
        def(
            "active.host-header", "Host header injection", "Host header", .medium, .firm,
            "The application builds absolute URLs from a client-supplied host (`X-Forwarded-Host`). Password-reset links, cache keys and redirects can then point at an attacker's host.",
            "Build absolute URLs from a configured canonical host; trust forwarding headers only from your own proxies.",
            "- [OWASP: testing for host header injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)"
        ),
        def(
            "active.jwt", "JWT signature not verified", "JWT", .high, .firm,
            "The server accepted a JSON Web Token whose signature was removed or weakened (for example `alg: none`, or an HMAC signed with a guessable secret), so an attacker can mint tokens for any user.",
            "Verify the signature with a fixed algorithm and key; reject `alg: none`; use a strong, random HMAC secret or asymmetric keys.",
            "- [OWASP JWT cheat sheet](\(owasp)JSON_Web_Token_for_Java_Cheat_Sheet.html)"),
        def(
            "active.mass-assignment", "Mass assignment / overposting", "Mass assignment", .high, .firm,
            "A create/update endpoint accepted a privileged property (such as `role` or `isAdmin`) that was not part of the intended input, so a user can set fields the UI does not expose.",
            "Bind only an explicit allowlist of properties on the server; never bind request bodies straight onto domain objects.",
            "- [OWASP mass assignment cheat sheet](\(owasp)Mass_Assignment_Cheat_Sheet.html)"),
        def(
            "active.prototype-pollution", "Server-side prototype pollution", "Prototype pollution", .high,
            .firm,
            "A JSON merge on the server followed `__proto__`, so a property injected under `__proto__` appeared on an object that never set it. This can change later behaviour app-wide and sometimes lead to remote code execution.",
            "Reject `__proto__`/`constructor`/`prototype` keys in input; use a safe merge (null-prototype objects, `Map`), and freeze prototypes.",
            "- [OWASP prototype pollution prevention](\(owasp)Prototype_Pollution_Prevention_Cheat_Sheet.html)"
        ),
        def(
            "active.nosqli", "NoSQL / JavaScript expression injection", "NoSQL injection", .high, .firm,
            "Input reaches a server-side JavaScript or NoSQL expression (such as a MongoDB `$where` clause): a quote broke the expression and JavaScript-boolean conditions flipped the response, so an attacker can bypass authentication or extract data.",
            "Never build queries or `$where`/`$expr` expressions from input; use the driver's typed query API, and reject query operators (`$ne`, `$gt`, `$where`) in user-supplied values.",
            "- [OWASP testing for NoSQL injection](https://owasp.org/www-project-web-security-testing-guide/)"
        ),
        def(
            "active.ldapi", "LDAP injection", "LDAP injection", .high, .firm,
            "Input is interpolated into an LDAP search filter: an unbalanced parenthesis broke the filter, or a wildcard matched where a literal did not, so an attacker can alter the filter to bypass authentication or enumerate the directory.",
            "Escape input for LDAP filters (RFC 4515) or use a parameterized directory API; validate against an allowlist and never build filters by string concatenation.",
            "- [OWASP LDAP injection prevention](\(owasp)LDAP_Injection_Prevention_Cheat_Sheet.html)"),
        def(
            "active.upload", "Unrestricted file upload", "File upload", .high, .firm,
            "A file upload accepted a dangerous type (such as `.php` or `.svg`) that a hardened endpoint would reject, so an attacker could upload a web shell or a stored-XSS SVG.",
            "Enforce a server-side allowlist of extensions and content types, verify the file's magic bytes, store uploads outside the web root (or on a separate domain), and never execute uploaded files.",
            "- [OWASP file upload cheat sheet](\(owasp)File_Upload_Cheat_Sheet.html)"),
        def(
            "active.xpathi", "XPath injection", "XPath injection", .high, .firm,
            "Input is built into an XPath expression over XML data: a quote broke the expression and `or`-boolean conditions flipped the response, so an attacker can bypass checks or read other nodes of the document.",
            "Use parameterized XPath (variable binding) instead of string concatenation, and escape or allowlist input.",
            "- [OWASP XPath injection](https://owasp.org/www-community/attacks/XPATH_Injection)"),
    ]
}
