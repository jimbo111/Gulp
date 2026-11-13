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
        CORSCheck(), HostHeaderCheck(), JWTScanCheck(), MassAssignmentCheck(),
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
