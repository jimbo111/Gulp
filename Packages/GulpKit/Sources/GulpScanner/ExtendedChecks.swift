// GulpScanner — the active checks beyond the [P0] set (F08 §3.2, M11c). These are standard web
// security checks for an authorised scanner: each sends a benign probe and confirms a weakness from
// the response, raising an issue. They follow the same `ActiveCheck` pattern as the P0 set.

import Foundation
import GulpCodec
import GulpCore
import GulpHTTP

/// The non-P0 active checks.
enum ExtendedChecks {
    static let all: [any ActiveCheck] = [
        CORSCheck(), HostHeaderCheck(), JWTScanCheck(), MassAssignmentCheck(), PrototypePollutionCheck(),
        NoSQLInjectionCheck(), LDAPInjectionCheck(), XPathInjectionCheck(),
    ]
}

/// CORS misconfiguration: the server reflects an arbitrary `Origin` (or `null`) and allows
/// credentials, so any site can read authenticated responses. Request-level (runs once per request).
struct CORSCheck: ActiveCheck {
    let id = "active.cors"
    let family = "cors"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = []  // request-level

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        let canary = "https://\(context.token(8)).gulp-canary.test"
        for (candidate, variant) in [(canary, "arbitrary origin"), ("null", "null origin")] {
            let probe = await context.send(context.base.settingHeader("Origin", to: candidate))
            guard probe.header("access-control-allow-origin") == candidate,
                probe.header("access-control-allow-credentials")?.lowercased() == "true"
            else { continue }
            return [
                context.finding(
                    "active.cors", point: nil, variant: variant,
                    detail:
                        "The server reflected `Origin: \(candidate)` into `Access-Control-Allow-Origin` and set `Access-Control-Allow-Credentials: true`, so that origin can read this response with the user's credentials.",
                    evidence: probe, marker: "Access-Control-Allow-Origin: \(candidate)", confidence: .certain
                )
            ]
        }
        return []
    }
}

/// Host-header injection: a forwarded host (`X-Forwarded-Host`) is reflected into a redirect or an
/// absolute link, so password-reset mails / cache keys can be pointed at an attacker's host.
struct HostHeaderCheck: ActiveCheck {
    let id = "active.host-header"
    let family = "host-header"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = []  // request-level

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        let canary = "\(context.token(8)).gulp-canary.test"
        let probe = await context.send(context.base.settingHeader("X-Forwarded-Host", to: canary))
        let inLocation = probe.header("location")?.lowercased().contains(canary) == true
        let inBody = ["//\(canary)", "http://\(canary)", "https://\(canary)"].contains {
            probe.body.contains($0)
        }
        guard inLocation || inBody else { return [] }
        return [
            context.finding(
                "active.host-header", point: nil, variant: inLocation ? "redirect" : "link",
                detail:
                    "`X-Forwarded-Host: \(canary)` was reflected into \(inLocation ? "a redirect (`Location`)" : "an absolute URL in the body"). Absolute URLs built from a client-supplied host (reset links, cache keys) can be redirected to an attacker.",
                evidence: probe, marker: canary, confidence: .firm)
        ]
    }
}

/// JWT verification: when a request carries a Bearer JWT that authenticates it, re-send it with the
/// signature removed (`alg: none`) or re-signed with a guessable HMAC secret; if the server still
/// treats the request as authenticated, it isn't verifying the signature. Reuses the JWT workbench.
struct JWTScanCheck: ActiveCheck {
    let id = "active.jwt"
    let family = "jwt"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = []  // request-level

    /// A tiny built-in list of weak HMAC secrets.
    static let weakSecrets = ["secret", "password", "123456", "changeme", "secret123", "admin", "key", "jwt"]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let token = Self.bearer(context.base), let jwt = try? JWT(token) else { return [] }
        // The original request must currently succeed, so a forged one "still works" means something.
        let original = await context.send(context.base)
        guard let status = original.status, (200..<400).contains(status) else { return [] }

        // alg:none — the signature is removed entirely.
        for forgery in (try? JWTAttacks.algNone(jwt)) ?? [] {
            let probe = await context.send(Self.replacingBearer(context.base, with: forgery.token))
            if accepted(probe, like: original) {
                return [
                    context.finding(
                        id, point: nil, variant: "alg:none",
                        detail:
                            "The server accepted a token with its signature removed (\(forgery.label)) and still treated the request as authenticated, so JWT signatures are not verified.",
                        evidence: probe, confidence: .certain)
                ]
            }
        }
        // Weak HMAC secret — if a guessable secret verifies the token, it is forgeable.
        if jwt.algorithm.uppercased().hasPrefix("HS"),
            JWTAttacks.crack(jwt, wordlist: Self.weakSecrets) != nil
        {
            return [
                context.finding(
                    id, point: nil, variant: "weak secret",
                    detail:
                        "The token is HMAC-signed with a guessable secret, so anyone can mint valid tokens for any user.",
                    evidence: original, confidence: .firm)
            ]
        }
        return []
    }

    /// Whether `probe` looks as authenticated as the original (same success, similar body).
    func accepted(_ probe: Probe, like original: Probe) -> Bool {
        guard let status = probe.status, (200..<400).contains(status) else { return false }
        return SQLInjectionCheck.similar(probe, original, removing: [])
    }

    static func bearer(_ request: RawRequest) -> String? {
        guard let value = request.headerValue("authorization")?.string(),
            value.lowercased().hasPrefix("bearer ")
        else { return nil }
        return String(value.dropFirst("bearer ".count)).trimmingCharacters(in: .whitespaces)
    }

    static func replacingBearer(_ request: RawRequest, with token: String) -> RawRequest {
        request.settingHeader("Authorization", to: "Bearer \(token)")
    }
}

/// Mass assignment: for a JSON create/update request, add a privileged property the input shouldn't
/// carry and see whether it is echoed back as accepted. Unsafe-gated (it modifies data).
struct MassAssignmentCheck: ActiveCheck {
    let id = "active.mass-assignment"
    let family = "mass-assignment"
    let intensity = CheckIntensity.balanced
    let kinds: Set<InsertionPointKind> = []  // request-level (edits the whole JSON body)

    static let privileged: [(String, String)] = [
        ("role", "admin"), ("isAdmin", "true"), ("is_admin", "true"), ("admin", "true"), ("verified", "true"),
    ]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard context.unsafe else { return [] }  // adds a property; only with the unsafe gate
        let method = context.base.bytes[context.base.parsed.method].string().uppercased()
        guard ["POST", "PUT", "PATCH"].contains(method) else { return [] }
        guard context.base.headerValue("content-type")?.string().lowercased().contains("json") == true else {
            return []
        }
        let bodyBytes = Array(context.base.bytes.rawBytes[context.base.parsed.body])
        guard var object = (try? JSONSerialization.jsonObject(with: Data(bodyBytes))) as? [String: Any] else {
            return []
        }

        for (name, value) in Self.privileged where object[name] == nil {
            object[name] = value == "true" ? true : value
            guard let newBody = try? JSONSerialization.data(withJSONObject: object) else { continue }
            let request = context.base.replacing(context.base.parsed.body, with: Bytes(Array(newBody)))
                .updatingContentLength()
            let probe = await context.send(request)
            // Accepted if the response echoes the privileged field set to our value.
            let marker = "\"\(name)\""
            if probe.body.contains(marker), probe.body.contains(value) {
                return [
                    context.finding(
                        id, point: nil, variant: name,
                        detail:
                            "Adding `\(name)` to the JSON body was accepted: the response shows `\(name)` set to the injected value, so the endpoint binds properties the client should not control.",
                        evidence: probe, marker: value, confidence: .firm)
                ]
            }
            object[name] = nil
        }
        return []
    }
}

/// Server-side prototype pollution: inject a benign marker under `__proto__` into a JSON body, then
/// send a clean request; if the marker appears on an object that never set it, a merge followed
/// `__proto__`. Non-destructive (a random marker property) and unsafe-gated (it writes server state).
struct PrototypePollutionCheck: ActiveCheck {
    let id = "active.prototype-pollution"
    let family = "prototype-pollution"
    let intensity = CheckIntensity.balanced
    let kinds: Set<InsertionPointKind> = []  // request-level

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard context.unsafe else { return [] }  // writes to the server's object graph
        let method = context.base.bytes[context.base.parsed.method].string().uppercased()
        guard ["POST", "PUT", "PATCH"].contains(method) else { return [] }
        guard context.base.headerValue("content-type")?.string().lowercased().contains("json") == true else {
            return []
        }
        let bodyBytes = Array(context.base.bytes.rawBytes[context.base.parsed.body])
        guard var object = (try? JSONSerialization.jsonObject(with: Data(bodyBytes))) as? [String: Any] else {
            return []
        }

        let marker = context.token(10)
        // A clean baseline must not already contain the marker.
        let clean = await context.send(context.base)
        guard !clean.body.contains(marker) else { return [] }
        // Pollute `__proto__` with the marker, then re-send the clean request and look for leakage.
        object["__proto__"] = ["gulpPoll": marker]
        guard let polluted = try? JSONSerialization.data(withJSONObject: object) else { return [] }
        _ = await context.send(
            context.base.replacing(context.base.parsed.body, with: Bytes(Array(polluted)))
                .updatingContentLength())
        let confirm = await context.send(context.base)
        guard confirm.body.contains(marker) else { return [] }
        return [
            context.finding(
                id, point: nil, variant: "__proto__",
                detail:
                    "A marker injected under `__proto__` appeared in a later clean response (`\(marker)`), so a server-side merge follows `__proto__` — prototype pollution.",
                evidence: confirm, marker: marker, confidence: .firm)
        ]
    }
}

/// NoSQL injection in a JavaScript string context (for example MongoDB `$where`, or any server that
/// concatenates input into an evaluated expression). A quote provokes a JavaScript parse error, and
/// two independent JS-boolean pairs (`|| '1'=='1'` true, `|| '1'=='2'` false) flip the response the
/// way a boolean-based SQL injection would — but with JavaScript operators, so it is a distinct
/// family. Reuses `SQLInjectionCheck.similar` for the differential and the same two-pair rigour.
struct NoSQLInjectionCheck: ActiveCheck {
    let id = "active.nosqli"
    let family = "nosqli"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = ActiveChecks.parameterKinds

    /// JavaScript / MongoDB driver parse errors — none of which a SQL engine emits.
    static let errorPatterns = [
        "SyntaxError", "MongoError", "MongoServerError", "CastError", "BSONError", "BSONTypeError",
        "unterminated string literal", "missing ) after argument list", "$where",
    ]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point, let baseline else { return [] }
        let v = point.baseValue
        // Error based: a lone quote breaks the JavaScript string literal.
        for payload in ["\(v)'", "\(v)\""] {
            let probe = await context.send(point.build(context.base, payload: payload))
            if let error = Self.errorPatterns.first(where: {
                probe.text.contains($0) && !baseline.original.text.contains($0)
            }) {
                return [
                    context.finding(
                        "active.nosqli", point: point, variant: "error",
                        detail:
                            "A quote in **\(point.label)** produced a JavaScript/NoSQL engine error (`\(error)`), so the value is evaluated as part of a server-side expression.",
                        evidence: probe, marker: error, confidence: .firm)
                ]
            }
        }
        // Boolean based: two independent JS-boolean true/false pairs, as for SQL injection. `&&`
        // (true keeps the match, false removes it) so the oracle holds for a valid baseline value.
        guard !baseline.volatile else { return [] }
        let pairs = [
            ("\(v)' && '1'=='1", "\(v)' && '1'=='2"), ("\(v)' && 'a'=='a", "\(v)' && 'a'=='b"),
        ]
        var evidence: Probe?
        for (truePayload, falsePayload) in pairs {
            let yes = await context.send(point.build(context.base, payload: truePayload))
            let no = await context.send(point.build(context.base, payload: falsePayload))
            let same = SQLInjectionCheck.similar(yes, baseline.original, removing: [truePayload, v])
            let different = !SQLInjectionCheck.similar(no, baseline.original, removing: [falsePayload, v])
            guard same && different else { return [] }
            evidence = no
        }
        guard let evidence else { return [] }
        return [
            context.finding(
                "active.nosqli", point: point, variant: "boolean",
                detail:
                    "Two independent JavaScript-boolean conditions (`&& '1'=='1'` and `&& 'a'=='a'`) appended to **\(point.label)** kept the original page while their false twins (`'1'=='2`) removed it — a NoSQL/JavaScript expression injection.",
                evidence: evidence, confidence: .firm)
        ]
    }
}

/// LDAP injection in a search filter. An unbalanced parenthesis provokes a filter/parse error, and a
/// wildcard (`*`) that matches where a random literal does not shows the value lands inside an LDAP
/// filter (`(uid=INPUT)`) rather than being compared literally.
struct LDAPInjectionCheck: ActiveCheck {
    let id = "active.ldapi"
    let family = "ldapi"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = ActiveChecks.parameterKinds

    /// LDAP filter / directory errors — distinct from SQL and XML.
    static let errorPatterns = [
        "javax.naming", "LDAPException", "ldap_search", "Bad search filter", "invalid filter",
        "Protocol error", "com.sun.jndi", "INVALID_SYNTAX", "FILTER_ERROR",
    ]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point, let baseline else { return [] }
        let v = point.baseValue
        // Error based: an unbalanced parenthesis or filter operator breaks the filter.
        for payload in ["\(v))", "\(v)(", "\(v)*)("] {
            let probe = await context.send(point.build(context.base, payload: payload))
            if let error = Self.errorPatterns.first(where: {
                probe.text.contains($0) && !baseline.original.text.contains($0)
            }) {
                return [
                    context.finding(
                        "active.ldapi", point: point, variant: "error",
                        detail:
                            "An unbalanced parenthesis in **\(point.label)** produced an LDAP filter error (`\(error)`), so the value is built into a search filter.",
                        evidence: probe, marker: error, confidence: .firm)
                ]
            }
        }
        // Boolean based: `*` is an LDAP wildcard that matches like the real value; a random literal
        // does not. A plain exact-match parameter treats `*` literally, so neither matches and the
        // check stays quiet.
        guard !baseline.volatile else { return [] }
        let invalidLiteral = "\(context.token(8))zz"
        let wildcard = await context.send(point.build(context.base, payload: "*"))
        let invalid = await context.send(point.build(context.base, payload: invalidLiteral))
        // Strip both payloads from both comparisons so an endpoint that merely echoes the value (not
        // an LDAP filter) matches the baseline either way and does not look like a wildcard match.
        let wildcardMatches = SQLInjectionCheck.similar(wildcard, baseline.original, removing: ["*", v])
        let invalidDiffers = !SQLInjectionCheck.similar(
            invalid, baseline.original, removing: [invalidLiteral, v])
        guard wildcardMatches && invalidDiffers else { return [] }
        return [
            context.finding(
                "active.ldapi", point: point, variant: "wildcard",
                detail:
                    "An LDAP wildcard (`*`) in **\(point.label)** matched like the original value while a random literal did not, so the value is interpolated into an LDAP filter.",
                evidence: wildcard, confidence: .firm)
        ]
    }
}

/// XPath injection in an XML query. A quote breaks the XPath string literal, and two independent
/// `and`-boolean pairs flip the response (`' and '1'='1` keeps the match, `' and '1'='2` removes it).
/// It uses lowercase `and`/`=` and single quotes — the XPath idiom — so it is distinct from the SQL
/// `AND`-based check (uppercase, different family and lab route).
struct XPathInjectionCheck: ActiveCheck {
    let id = "active.xpathi"
    let family = "xpathi"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = ActiveChecks.parameterKinds

    /// XPath / XML evaluation errors — none of which a SQL engine emits.
    static let errorPatterns = [
        "XPathException", "xmlXPathEval", "Invalid expression", "Invalid predicate", "XPath",
        "javax.xml.xpath", "SyntaxError: unexpected", "unclosed", "XPST0003",
    ]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point, let baseline else { return [] }
        let v = point.baseValue
        // Error based: a lone quote breaks the XPath string literal.
        for payload in ["\(v)'", "\(v)\""] {
            let probe = await context.send(point.build(context.base, payload: payload))
            if let error = Self.errorPatterns.first(where: {
                probe.text.contains($0) && !baseline.original.text.contains($0)
            }) {
                return [
                    context.finding(
                        "active.xpathi", point: point, variant: "error",
                        detail:
                            "A quote in **\(point.label)** produced an XPath error (`\(error)`), so the value is built into an XPath expression.",
                        evidence: probe, marker: error, confidence: .firm)
                ]
            }
        }
        // Boolean based: two independent `and`-boolean pairs that use the XPath-only `string-length()`
        // function, so a SQL engine rejects the payload (no `string-length`) and only a true XPath
        // context flips — this distinguishes XPath injection from SQL injection on real targets.
        guard !baseline.volatile else { return [] }
        let pairs = [
            ("\(v)' and string-length('ab')='2", "\(v)' and string-length('ab')='9"),
            ("\(v)' and string-length('abcd')='4", "\(v)' and string-length('abcd')='9"),
        ]
        var evidence: Probe?
        for (truePayload, falsePayload) in pairs {
            let yes = await context.send(point.build(context.base, payload: truePayload))
            let no = await context.send(point.build(context.base, payload: falsePayload))
            let same = SQLInjectionCheck.similar(yes, baseline.original, removing: [truePayload, v])
            let different = !SQLInjectionCheck.similar(no, baseline.original, removing: [falsePayload, v])
            guard same && different else { return [] }
            evidence = no
        }
        guard let evidence else { return [] }
        return [
            context.finding(
                "active.xpathi", point: point, variant: "boolean",
                detail:
                    "Two XPath conditions using `string-length()` appended to **\(point.label)** kept the original page when the length matched and removed it when it did not — XPath injection (the `string-length()` function a SQL engine would reject).",
                evidence: evidence, confidence: .firm)
        ]
    }
}
