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
        NoSQLInjectionCheck(), LDAPInjectionCheck(), XPathInjectionCheck(), UploadBypassCheck(),
        CachePoisoningCheck(), CacheDeceptionCheck(),
    ]
}

/// Web cache poisoning (F28 WCP-001/002/004): a candidate **unkeyed input** (a forwarded-host/scheme/
/// port header) is reflected into a response a shared cache would store. WCP-001 detects the reflection
/// into a cacheable response; WCP-002 *confirms* the vector by issuing a clean follow-up (without the
/// header) and checking the canary is still served — i.e. the poison was cached. A unique canary alone
/// would not protect anyone: the poisoned entry is served to every user of that URL for its TTL. So
/// both requests carry a per-probe cache-buster (F08 §3.5), an extra query parameter only Gulp's own
/// follow-up repeats, and the family is opt-in (`ActiveChecks.optInFamilies`). WCP-004: the finding
/// carries the poisoning request, the confirming cached response, and the vector header.
struct CachePoisoningCheck: ActiveCheck {
    let id = "active.cache-poisoning"
    let family = "cache-poisoning"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = []  // request-level

    /// Candidate unkeyed inputs (header → how it is typically reflected). Kept small and high-signal.
    static let unkeyedHeaders = [
        "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Server", "X-Host",
        "X-Forwarded-Port", "Forwarded",
    ]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        for header in Self.unkeyedHeaders {
            let canary = "\(context.token(8)).gulp-cache.test"
            let keyed = Self.cacheBusted(context.base, context)
            let probe = await context.send(keyed.settingHeader(header, to: canary))
            guard Self.cacheable(probe), Self.reflects(probe, canary) else { continue }

            // WCP-002: confirm it was cached — a clean follow-up (no injected header, same cache key)
            // still carries the canary, so users of a URL keyed like that one would get the poison.
            let cleanFollowUp = await context.send(keyed)
            let confirmedCached = Self.reflects(cleanFollowUp, canary)
            let confidence: IssueConfidence = confirmedCached ? .certain : .firm
            let confirmation =
                confirmedCached
                ? " A clean follow-up request (without the header) was still served the canary, confirming the poison was **cached** and would reach other users."
                : " (Reflected into a cacheable response; a clean follow-up did not reproduce it, so caching is probable but unconfirmed.)"
            return [
                context.finding(
                    id, point: nil, variant: confirmedCached ? "confirmed-cached" : "reflected",
                    detail:
                        "`\(header): \(canary)` was reflected into a **cacheable** response (`\(probe.header("cache-control") ?? "Age present")`) — web cache poisoning via an unkeyed header.\(confirmation)",
                    evidence: confirmedCached ? cleanFollowUp : probe, marker: canary,
                    confidence: confidence)
            ]
        }
        return []
    }

    /// `request` with a fresh cache-buster query parameter (F08 §3.5), so a cache keyed on the URL
    /// files whatever the probe provokes under a key no real user requests.
    static func cacheBusted(_ request: RawRequest, _ context: AuditContext) -> RawRequest {
        ParamMiner.appendingQuery(request, [("gulpcb", context.token(8))])
    }

    /// Whether `canary` appears in the response's redirect Location or body.
    static func reflects(_ probe: Probe, _ canary: String) -> Bool {
        if probe.header("location")?.contains(canary) == true { return true }
        return ["//\(canary)", "http://\(canary)", "https://\(canary)", canary].contains {
            probe.body.contains($0)
        }
    }

    /// Whether the response looks like something a shared cache would store.
    static func cacheable(_ probe: Probe) -> Bool {
        if probe.header("age") != nil || probe.header("x-cache")?.lowercased().contains("hit") == true {
            return true
        }
        guard let control = probe.header("cache-control")?.lowercased() else { return false }
        if control.contains("no-store") || control.contains("private") || control.contains("no-cache") {
            return false
        }
        return control.contains("public") || control.contains("max-age")
    }
}

/// Web cache deception (F28 WCP-003): a private/authenticated page is requested with a static-looking
/// suffix (`/account.css`, `/account/x.js`, an encoded `/account%2fx.css`). If the app still returns
/// the private content but the path makes a CDN treat it as a cacheable static asset, that private
/// content lands in a shared cache — anyone can then fetch it. Confirmed by a private marker appearing
/// in a now-cacheable response at the deceptive path that was not cacheable at the real path.
struct CacheDeceptionCheck: ActiveCheck {
    let id = "active.cache-deception"
    let family = "cache-poisoning"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = []  // request-level

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        let base = context.base
        let target = base.bytes[base.parsed.target].string()
        let path = String(target.split(separator: "?", maxSplits: 1).first ?? "")
        // Only meaningful on a path that returns content and has no static extension already.
        guard !path.isEmpty, path != "/", !path.contains(".") else { return [] }
        // Determine the private marker from the real page (baseline is per-point and absent here).
        let original: Probe
        if let b = baseline?.original {
            original = b
        } else {
            original = await context.send(base)
        }
        guard let privateMarker = Self.privateMarker(original.body) else { return [] }

        for suffix in ["/x.css", ".css", "/x.js", "%2fx.css"] {
            let deceptive = CachePoisoningCheck.cacheBusted(Self.retarget(base, path: path + suffix), context)
            let probe = await context.send(deceptive)
            guard CachePoisoningCheck.cacheable(probe), probe.body.contains(privateMarker) else { continue }
            return [
                context.finding(
                    id, point: nil, variant: suffix,
                    detail:
                        "Requesting `\(path)\(suffix)` returned the private content (marker `\(privateMarker)`) in a **cacheable** response (`\(probe.header("cache-control") ?? "Age present")`). A CDN keyed on the extension would cache this private page and serve it to anyone — web cache deception.",
                    evidence: probe, marker: privateMarker, confidence: .firm)
            ]
        }
        return []
    }

    /// A short, stable substring of the baseline body that marks it as private (a session/user cue).
    static func privateMarker(_ body: String?) -> String? {
        guard let body else { return nil }
        for cue in ["Balance:", "account_number", "\"email\"", "Welcome back", "session_token", "SSN"] {
            if body.contains(cue) { return cue }
        }
        return nil
    }

    /// `base` with the path of its request-target replaced (the query and every other byte — method,
    /// version, cookies, authorization — kept), so the deceptive request is made as the same user.
    static func retarget(_ base: RawRequest, path: String) -> RawRequest {
        let target = base.bytes[base.parsed.target].string()
        let query = target.firstIndex(of: "?").map { String(target[$0...]) } ?? ""
        return base.replacing(base.parsed.target, with: Bytes(path + query))
    }
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
        // Cache-busted like the cache family: a cache that doesn't key the header must not keep the
        // canary page for the URL real users request.
        let probe = await context.send(
            CachePoisoningCheck.cacheBusted(context.base, context).settingHeader(
                "X-Forwarded-Host", to: canary))
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

/// JWT verification: when a request carries a Bearer JWT that authenticates it, and the endpoint
/// rejects the request without a token, re-send it with the signature corrupted and then removed
/// (`alg: none`); if the server still treats the request as authenticated, it isn't verifying the
/// signature. An HMAC token is also cracked offline against a few guessable secrets. Reuses the JWT
/// workbench.
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
        if let forged = await forgedTokenFinding(jwt, token, original: original, context: context) {
            return [forged]
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

    /// A forged token the server accepts, after two negative controls: the request without a token
    /// must be rejected (else the endpoint ignores the token and no forgery proves anything), and so
    /// must the token with its signature corrupted (else the signature isn't checked at all, reported
    /// as such rather than as alg:none). Only then is an accepted `alg: none` token a finding.
    func forgedTokenFinding(_ jwt: JWT, _ token: String, original: Probe, context: AuditContext) async
        -> IssueFinding?
    {
        let missing = await context.send(Self.replacingBearer(context.base, with: ""))
        guard !accepted(missing, like: original) else { return nil }
        if let corruptedToken = Self.corruptingSignature(token) {
            let corrupted = await context.send(Self.replacingBearer(context.base, with: corruptedToken))
            if accepted(corrupted, like: original) {
                return context.finding(
                    id, point: nil, variant: "unverified signature",
                    detail:
                        "The server rejected the request without a token but accepted the token with its signature corrupted, so JWT signatures are not verified.",
                    evidence: corrupted, confidence: .certain)
            }
        }
        // alg:none — the signature is removed entirely.
        for forgery in (try? JWTAttacks.algNone(jwt)) ?? [] {
            let probe = await context.send(Self.replacingBearer(context.base, with: forgery.token))
            if accepted(probe, like: original) {
                return context.finding(
                    id, point: nil, variant: "alg:none",
                    detail:
                        "The server rejected the request without a token and with a corrupted signature, but accepted a token with its signature removed (\(forgery.label)), so it honours `alg: none`.",
                    evidence: probe, confidence: .certain)
            }
        }
        return nil
    }

    /// `token` with the first character of its signature changed; nil for an unsigned token.
    static func corruptingSignature(_ token: String) -> String? {
        guard let dot = token.lastIndex(of: "."), let first = token[token.index(after: dot)...].first else {
            return nil
        }
        return String(token[...dot]) + (first == "A" ? "B" : "A") + token[token.index(dot, offsetBy: 2)...]
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

/// Unrestricted file upload: for a multipart upload, re-send the same file with a dangerous
/// extension and content-type (`.php`, `.svg`, …). A server that still accepts it the way it accepted
/// the benign file is not enforcing an allowlist, so a web shell or stored-XSS SVG could be uploaded.
/// Unsafe-gated (it submits a file) and non-destructive (the file content stays benign).
struct UploadBypassCheck: ActiveCheck {
    let id = "active.upload"
    let family = "upload"
    let intensity = CheckIntensity.balanced
    let kinds: Set<InsertionPointKind> = []  // request-level (rewrites the file part)

    /// Dangerous (extension, content-type) pairs a hardened upload endpoint should reject.
    static let dangerous: [(label: String, ext: String, type: String)] = [
        ("PHP web shell", ".php", "application/x-httpd-php"),
        ("SVG (stored XSS)", ".svg", "image/svg+xml"),
        ("HTML", ".html", "text/html"),
        ("JSP", ".jsp", "application/x-jsp"),
    ]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard context.unsafe else { return [] }  // submits a file
        let method = context.base.bytes[context.base.parsed.method].string().uppercased()
        guard ["POST", "PUT"].contains(method) else { return [] }
        guard
            context.base.headerValue("content-type")?.string().lowercased().contains("multipart/form-data")
                == true
        else { return [] }
        // Latin-1 round-trip: every byte maps to one scalar, so binary file content survives untouched.
        let bodyBytes = Array(context.base.bytes.rawBytes[context.base.parsed.body])
        let body = String(bodyBytes.map { Character(UnicodeScalar($0)) })
        guard let nameStart = body.range(of: "filename=\""),
            let nameEnd = body.range(of: "\"", range: nameStart.upperBound..<body.endIndex)
        else { return [] }  // a real file upload
        let originalName = String(body[nameStart.upperBound..<nameEnd.lowerBound])
        let base =
            originalName.contains(".")
            ? String(originalName[..<originalName.lastIndex(of: ".")!]) : originalName

        // The benign upload must currently be accepted, or "still accepted" means nothing.
        let benign = await context.send(context.base)
        guard let status = benign.status, (200..<300).contains(status) else { return [] }

        for variant in Self.dangerous {
            let newName = base + variant.ext
            guard let rewritten = Self.rewrite(body, ext: variant.ext, type: variant.type) else { continue }
            let newBody = [UInt8](rewritten.unicodeScalars.map { UInt8($0.value & 0xff) })
            let request = context.base.replacing(context.base.parsed.body, with: Bytes(newBody))
                .updatingContentLength()
            let probe = await context.send(request)
            // "Accepted like the benign file": same 2xx and the same response once the (reflected)
            // filename is removed — so a rejection page (different status/body) does not match.
            guard let code = probe.status, (200..<300).contains(code),
                SQLInjectionCheck.similar(probe, benign, removing: [originalName, newName])
            else { continue }
            return [
                context.finding(
                    id, point: nil, variant: variant.label,
                    detail:
                        "The upload endpoint accepted a file renamed to `\(variant.ext)` with `Content-Type: \(variant.type)` exactly as it accepted the benign file, so it does not enforce a type allowlist (\(variant.label)).",
                    evidence: probe, confidence: .firm)
            ]
        }
        return []
    }

    /// Replace the first file part's extension and `Content-Type`. Returns nil if there is no filename.
    static func rewrite(_ body: String, ext: String, type: String) -> String? {
        guard let nameStart = body.range(of: "filename=\"") else { return nil }
        guard let nameEnd = body.range(of: "\"", range: nameStart.upperBound..<body.endIndex) else {
            return nil
        }
        let filename = String(body[nameStart.upperBound..<nameEnd.lowerBound])
        let base = filename.contains(".") ? String(filename[..<filename.lastIndex(of: ".")!]) : filename
        var out = body.replacingOccurrences(
            of: "filename=\"\(filename)\"", with: "filename=\"\(base)\(ext)\"")
        // Replace the file part's Content-Type (the first one after the filename), if present.
        if let ctStart = out.range(
            of: "Content-Type:",
            range: (out.range(of: "filename=\"")?.upperBound
                ?? out.startIndex)..<out.endIndex),
            let ctEnd = out.range(of: "\r\n", range: ctStart.upperBound..<out.endIndex)
        {
            out.replaceSubrange(ctStart.lowerBound..<ctEnd.lowerBound, with: "Content-Type: \(type)")
        }
        return out
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
