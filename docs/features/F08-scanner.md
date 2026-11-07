# F08 — Scanner (passive, active, check recipes)

> Milestones: M10 (passive + issue model), M11 (active) · Modules: `GulpScanner`,
> `GulpFeatures/{Scanner,Issues}` · Depends on: F03, F04, F09, F10, F15

## 1. Purpose

The Scanner finds vulnerabilities automatically. **Passive** checks analyze traffic already seen
(no extra requests). **Active** checks send crafted requests to probe for flaws. Findings become
**Issues** with evidence, severity, confidence and remediation guidance.

> **Concept: passive vs. active.** Passive scanning is safe to run always — it only inspects
> responses the tester already caused (e.g. "this cookie lacks HttpOnly", "the response reflects
> input"). Active scanning sends attack payloads (e.g. a quote to test SQLi) and can change state, so
> it's scope-gated and configurable.

## 2. Issue model and requirements

### 2.1 Issues

| ID | Pri | Requirement |
|---|---|---|
| SCN-001 | P0 | `Issue`: type id, name, severity (High/Medium/Low/Info), confidence (Certain/Firm/Tentative), host, path, insertion point, detail (markdown), background, remediation, references, status (open/false-positive/accepted/fixed), and one or more **evidence** items. |
| SCN-002 | P0 | **Evidence** links to an exchange (or OAST interaction) with **marker ranges** into the request and response bytes, so the UI highlights exactly what proved the issue. |
| SCN-003 | P0 | **Deduplication**: a stable `dedup_key` (type + host + normalized path + insertion-point identity + a payload-class hash). The same issue found again updates evidence/confidence instead of creating a duplicate. |
| SCN-004 | P0 | Severity/confidence are check-defined but user-overridable per issue; status changes and notes are stored. |
| SCN-005 | P0 | Issues UI: the Dashboard issue tree (severity → type → host/path), a detail pane (rendered markdown + evidence with highlighted request/response + "send to Repeater"), filtering by severity/confidence/status/host, and bulk status changes. |
| SCN-006 | P1 | Issue definitions catalog (built-in) with stable ids and texts; each check references a definition. A "known issues" browser to read about any check. |
| SCN-007 | P1 | Collaboration-friendly export of issues (JSON/SARIF/HTML, see F19). |

### 2.2 Insertion points (active)

| ID | Pri | Requirement |
|---|---|---|
| SCN-020 | P0 | Derive insertion points from a request: URL query params, body params (form-urlencoded), JSON values (by path), XML values/attributes, multipart fields, cookies, headers (selected), the URL path segments, and whole-body. Each knows its **encoding context** so payloads are encoded correctly. |
| SCN-021 | P0 | Insertion-point policy per scan config: which locations to test, name/value, skip patterns, and a cap. Users can also mark custom insertion points manually (like Fuzzer positions) for a targeted audit. |
| SCN-022 | P1 | Nested decoding: detect and descend into base64/url/JSON-in-param values to place insertion points inside them (configurable depth). |

### 2.3 Active check engine

| ID | Pri | Requirement |
|---|---|---|
| SCN-030 | P0 | An `ActiveCheck` protocol: given a base request + an insertion point + an `AuditContext` (send function, baseline, OAST client, scope), it issues probes and yields issues. Checks declare which insertion points they want and an intensity tier. |
| SCN-031 | P0 | Baseline handling: capture a baseline response per insertion point; many checks compare against it (length, status, timing, reflected markers). Include a random "canary" to detect dynamic pages. |
| SCN-032 | P0 | Time-based detection with statistical rigor: multiple samples, compare against baseline latency distribution, require a consistent delay to reduce false positives. |
| SCN-033 | P0 | OAST integration (F10): checks can request a correlation token, inject it, and later ask whether an interaction arrived (supports asynchronous/blind detection; a scan isn't "done" until a grace period for OAST has elapsed). |
| SCN-034 | P0 | Scan configurations: **Passive only**, **Light active**, **Balanced**, **Thorough**, and **Custom** (choose check families, intensity, insertion-point policy, concurrency, throttle). Configs are savable/shareable. |
| SCN-035 | P0 | Scan tasks: created from "Actively scan" on a request/branch, or from a Crawl-and-audit (F09). Progress, pause/resume/cancel, per-check counts, and a log. Respect ScopeGuard and the shared resource pool. |
| SCN-036 | P1 | Consolidation across insertion points (don't report the same reflected-XSS once per param if it's clearly the same sink); configurable. |
| SCN-037 | P1 | Re-scan an issue to verify (re-run just that check) and mark fixed/still-present. |
| SCN-038 | P1 | Scan speed/safety guards: max requests per insertion point, global budget, and "safe checks only" (no payloads that could modify data). |

## 3. Built-in checks catalog

Each entry = one or more issue definitions. Mark the P0 set that the VulnLab accuracy test (doc 06
§3) depends on; implement the rest as P1 within M10/M11.

### 3.1 Passive checks (M10)

- Security headers missing/weak: CSP (absent/weak), HSTS, X-Content-Type-Options,
  X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy. **[P0 for the ones VulnLab
  plants]**
- Cookie flags: missing Secure, HttpOnly, SameSite; overly broad Domain/Path; session-looking
  cookies without protection. **[P0]**
- Information disclosure: stack traces/error messages, server/version banners, internal IPs,
  `X-Powered-By`, directory listings, source/backup files, exposed `.git`, `.env`,
  comments with secrets, autocomplete on password fields. **[P0 for `.git`/`.env`/stack traces]**
- Input reflection (potential XSS/injection signposting), unencoded reflection by context. **[P0]**
- TLS/cert observations (from F02 data): weak protocol, cert about to expire, mixed content.
- Caching of sensitive responses; CORS misconfig observed (wildcard with credentials). **[P0 CORS]**
- Forms: password field over HTTP, CSRF token absent on state-changing forms (heuristic),
  cross-domain form actions.
- Unencrypted / cleartext submission; open redirect parameters observed.
- Content-type sniffing risks; charset issues.

### 3.2 Active checks (M11)

- **Reflected XSS** (context-aware: HTML body, attribute, JS string, URL, CSS) with a benign
  marker-probe methodology and a proof payload per context. **[P0]**
- **Stored XSS** (inject, then detect in a later fetched page; coordinate with the Crawler). **[P0]**
- **SQL injection**: error-based, boolean-based (compare true/false response divergence), and
  time-based (statistical). **[P0]**
- **OS command injection**: time-based and OAST-based. **[P0 OAST]**
- **Server-side template injection**: polyglot probes and arithmetic-evaluation confirmation. **[P0]**
- **Path traversal / local file inclusion**: context-aware traversal sequences, confirm by known
  file markers. **[P0]**
- **XXE**: in-band and OAST (external entity to Beacon). **[P0 OAST]**
- **SSRF**: OAST-based (make the server call Beacon), plus response-based for internal endpoints.
  **[P0]**
- **Open redirect**. **[P0]**
- **CRLF/header injection / response splitting**. **[P0]**
- **CORS** active confirmation (reflected arbitrary Origin + credentials).
- **Host-header attacks** (password-reset poisoning signposting, cache tricks — overlaps F23).
- **Server-side request parameter pollution / HPP**.
- **Open/insecure deserialization** signposting (OAST where possible).
- **LDAP / NoSQL / XPath injection** (error- and boolean-based).
- **Clickjacking** (missing framing protection — confirmed with Frame Kit, F16).
- **Vulnerable JS libraries**: fingerprint versions of common libraries and flag known-vulnerable
  ones from a bundled, updatable dataset (no network calls required at scan time).
- **Secrets in responses**: API keys/tokens via a regex ruleset (overlaps F23 secret scanner).

### 3.3 Check Recipes (custom checks, M11)

| ID | Pri | Requirement |
|---|---|---|
| SCN-060 | P0 | **Check Recipes**: user-authored checks in YAML (inspired by BChecks/Nuclei) for passive and active detection without writing code. |
| SCN-061 | P0 | Schema: `metadata` (id, name, severity, confidence), `when` (GulpQL condition / insertion-point selector), `requests` (templated probes with Transform Tags and payload placeholders), `matchers` (status/word/regex/binary/time/OAST, with `and`/`or`), `extractors`, and `issue` (templated detail/remediation referencing captured groups). |
| SCN-062 | P0 | A recipe editor with validation, a dry-run against a selected request, and a library folder (`~/.../recipes/`). |
| SCN-063 | P1 | Import/convert common Nuclei/BCheck templates where feasible (document unsupported features). |
| SCN-064 | P1 | Recipes participate in scan configs like built-in checks (enable/disable, intensity). |
| SCN-065 | P2 | Share/export recipes; a signed-recipe notion for trust. |
| SCN-066 | P2 | A GraphQL/JSON-aware matcher helper set. |

## 4. Live passive scanning (M10)

- A background consumer of `exchangeRecorded` runs passive checks on in-scope traffic (configurable
  to all), emitting issues. It must keep up with proxy throughput (batch, run off-main, drop to a
  queue with backpressure; if it lags, it re-reads from the store).
- A toggle to passively scan specific tools' traffic (proxy always; repeater optional).

## 5. Implementation notes

- Checks are registered in a `CheckRegistry`; each has an id, family, default intensity, and the
  insertion points it wants. The engine groups probes per insertion point to reuse baselines.
- Keep probe payloads **benign by default** (markers, arithmetic, timing, OAST) and clearly separate
  any payload that could modify data behind the "unsafe checks" gate.
- The scan scheduler uses a bounded task group with the shared throttle; it interleaves insertion
  points to spread load across endpoints.
- Determinism for tests: seed any randomness (canaries) from an injectable RNG; VulnLab timing is
  stable enough for the time-based checks in CI (use generous thresholds).

## 6. Edge cases

- **Dynamic / non-deterministic pages**: responses that change every request (timestamps, CSRF
  tokens, ads) break length/diff comparisons. Use the per-insertion-point canary (SCN-031) to detect
  volatility and fall back to content-independent signals (reflection, OAST, timing) or widen
  thresholds; never report solely on a length delta for a page flagged volatile.
- **Rate limiting / WAF**: on 429/503 or a block page, back off (shared throttle), mark the host
  throttled, and surface it in the task log rather than emitting false "fixed/absent" verdicts.
- **Auth expiry mid-scan**: a session that drops mid-audit yields login redirects that look like
  "not vulnerable". Detect via the session-validity check (F15) and re-auth before continuing;
  single-flight the re-auth under concurrency.
- **Stored-XSS timing**: the inject and the detect can be on different endpoints/requests, and the
  render may be delayed — coordinate with the Crawler and allow a re-check pass before concluding.
- **OAST asynchrony**: blind checks (OS command, SSRF, XXE) may see interactions arrive after the
  request completes; the scan must honor the OAST grace period (SCN-033) before declaring "done".
- **Insertion-point explosion**: deeply nested/decoded values (SCN-022) can multiply points without
  bound; cap depth and per-request point count, and respect the per-insertion-point request budget.
- **Destructive payloads**: anything that could modify or delete data stays behind the "unsafe
  checks" gate (SCN-038); default configs never send it.

## 7. Acceptance tests

- Passive: browsing VulnLab yields exactly the planted passive issues (doc 06 §3), deduped, and none
  on `/safe/*`.
- Active per family: each P0 active check finds its VulnLab endpoint and reports correct markers;
  `/safe/*` twins produce no ≥Low issues (the scanner-accuracy test asserts recall and precision).
- OAST: the command-injection and SSRF checks register tokens and correlate interactions from the
  dev Beacon; the scan waits for the OAST grace period before finishing.
- A YAML Check Recipe for a custom header-leak detects it on a crafted VulnLab route and renders the
  templated issue with the captured value.
