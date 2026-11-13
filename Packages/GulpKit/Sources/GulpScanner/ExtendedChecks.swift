// GulpScanner — the active checks beyond the [P0] set (F08 §3.2, M11c). These are standard web
// security checks for an authorised scanner: each sends a benign probe and confirms a weakness from
// the response, raising an issue. They follow the same `ActiveCheck` pattern as the P0 set.

import Foundation
import GulpCore
import GulpHTTP

/// The non-P0 active checks.
enum ExtendedChecks {
    static let all: [any ActiveCheck] = [
        CORSCheck(), HostHeaderCheck(),
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
