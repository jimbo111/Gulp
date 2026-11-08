# F08 — Scanner (passive, active, check recipes)

> Milestones: M10a (passive, issues), M11b (active, P0 checks), M11c (catalog), M15 (recipes), M22, M24, M25 ·
> Modules: `GulpScanner`, `GulpFeatures/{Scanner,Issues}` · Depends on: F03, F04, F09, F10, F12 (JWT
> checks), F15, F16 (CSPT confirmation)

## 1. Purpose

The Scanner finds vulnerabilities automatically. **Passive** checks analyze traffic already seen
(no extra requests). **Active** checks send crafted requests to probe for flaws. Findings become
**Issues** with evidence, severity, confidence and remediation guidance.

> **Concept: passive vs. active.** Passive scanning is safe to run always — it only inspects
> responses the tester already caused (e.g. "this cookie lacks HttpOnly", "the response reflects
> input"). Active scanning sends attack payloads (e.g. a quote to test SQLi) and can change state, so
> it's scope-gated and configurable.

Milestones: the issue model and passive checks are M10a; the active engine and the [P0] checks
M11b; the rest of the catalog M11c; Check Recipes M15. M22, M24 and M25 in the header are the
**post-1.0** parts — WebSocket checks (§3.6), the cache poisoning family (§3.5) and issue retest
(§2.4), merged here from F26, F28 and F30 on 2026-11-08.

## 2. Issue model and requirements

### 2.1 Issues

| ID | Pri | Requirement |
|---|---|---|
| SCN-001 | P0 | `Issue`: type id, name, severity (High/Medium/Low/Info), confidence (Certain/Firm/Tentative), host, path, insertion point, detail (markdown), background, remediation, references (all markdown, backed by the `issues` columns incl. `references_md`), status using the exact tokens `open` / `false_positive` / `accepted_risk` / `fixed` (matching doc 04), and one or more **evidence** items. |
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
| SCN-035 | P0 | Scan tasks: created from "Actively scan" on a request/branch, or from a Crawl-and-audit (F09). Progress, pause/resume/cancel, per-check counts, and a log. Respect ScopeGuard and the shared resource pool. *(The F15 dependency in the header is for **authenticated** scanning, which lands in M12a; the M11b/M11c scanner runs unauthenticated, matching their DoDs — same deferral as CRL-006.)* |
| SCN-036 | P1 | Consolidation across insertion points (don't report the same reflected-XSS once per param if it's clearly the same sink); configurable. |
| SCN-037 | P1 | Re-scan an issue to verify (re-run just that check) and mark fixed/still-present. |
| SCN-038 | P1 | Scan speed/safety guards: max requests per insertion point, global budget, and "safe checks only" (no payloads that could modify data). |

### 2.4 Retest and remediation tracking (moved from F30, 2026-11-08; post-1.0)

Extends SCN-037 (re-scan one issue) into a stored, replayable proof per issue with a verdict history.
F30's endpoint **baselines** (drift detection) were cut; only the per-issue retest remains.
*(later: M25 — post-1.0, see the roadmap's Phase F.)*

| ID | Pri | Requirement |
|---|---|---|
| DRF-003 | P0 | **Retest proof per issue**: store, per issue, a replayable proof (originating request(s)/insertion point + the matcher/extractor that confirmed it, auto-captured from Scanner/Repeater/Recipes or user-attached). *(Moved from F30; later: M25.)* |
| DRF-004 | P0 | **Verdicts**: re-running an issue's proof computes Fixed / Still-Vulnerable / Changed / Needs-Review with the new evidence attached and a per-field breakdown in `DiffView` (UI-030). *(Moved from F30, minus the cut endpoint-baseline verdicts; later: M25.)* |
| DRF-005 | P0 | **History** per issue (round, date, verdict, evidence); surface the latest verdict in the issue list and in reports (F19) as a "remediation status" column. *(Moved from F30, minus the cut baseline history; later: M25.)* |

Retest notes: proofs and verdicts persist in the post-1.0 `issue_proofs`/`retest_runs` tables (doc 04
§4); the verdict axis is orthogonal to `issues.status` (a verdict may update it, never replaces it).
Replays reuse the Repeater/engine send path, so session rules (F15) apply. An endpoint that 404s on
re-run is Needs-Review ("gone" is not "patched"); a proof that can't be re-run (a one-time token) is
Needs-Review with the reason.

## 3. Built-in checks catalog

Each entry = one or more issue definitions. Mark the P0 set that the VulnLab accuracy test (doc 06
§3) depends on; implement the rest as P1 within M10a/M11c.

### 3.1 Passive checks (M10a)

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

### 3.2 Active checks (M11b for the [P0] set, M11c for the rest)

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
- **Clickjacking** (missing framing protection — reported from the response headers; the Frame Kit
  PoC recorder, F16, was cut on 2026-11-08).
- **Vulnerable JS libraries**: fingerprint versions of common libraries and flag known-vulnerable
  ones from a bundled, updatable dataset (no network calls required at scan time). *(Passive
  fingerprint — no probing; runs in the passive engine §4 even though listed here with its family.)*
- **Secrets in responses**: API keys/tokens via a regex ruleset (overlaps F23 secret scanner).
  *(Passive regex/entropy — no probing; runs passively like the F23 secret scanner.)*

Added by the 2026-11-08 feature review (A6) — P1, in **M11c**, each with a VulnLab fixture and safe
twin (doc 06 §3):

| ID | Pri | Requirement |
|---|---|---|
| SCN-070 | P1 | **Server-side prototype pollution** (Node.js): inject `__proto__`/`constructor.prototype` properties via JSON bodies and query params and confirm with non-destructive gadgets (e.g. a polluted `json spaces` or status-code property changing later responses), never with properties that could break the app for other users. |
| SCN-071 | P1 | **Client-side path traversal (CSPT)**: find client-side code that builds API paths from user-controlled input (route params, query, hash) and confirm that `../` sequences redirect the browser's authenticated request to another endpoint (passive source-to-fetch detection, confirmed in the browser-backed crawler when available). |
| SCN-072 | P1 | **Mass assignment**: for JSON/form create/update endpoints, add privileged-looking properties (`role`, `isAdmin`, `owner_id`, properties seen in responses but not requests) and confirm they were accepted by re-reading the object. Unsafe-gated (it modifies data). |
| SCN-073 | P1 | **File-upload bypasses**: for multipart upload endpoints, try content-type/extension mismatches, double extensions, case and trailing-dot tricks, polyglot images and SVG with script, and confirm whether the file is stored and served with an executable/HTML content type from the same origin. Unsafe-gated. |
| SCN-074 | P1 | **JWT checks**: for requests carrying a JWT, test `alg:none`, RS→HS key confusion, an empty/weak HMAC secret (small built-in list) and `kid` injection (path traversal / SQL in `kid`), reusing the JWT Workbench operations (F12 §2.3); report acceptance by comparing to the original token's response. |

### 3.3 Check Recipes (custom checks, M15)

Moved out of M11 by the 2026-11-08 feature review (SCN-060…062 P0 → P1); they ship with the
extension work in M15.

| ID | Pri | Requirement |
|---|---|---|
| SCN-060 | P1 | **Check Recipes**: user-authored checks in YAML (inspired by BChecks/Nuclei) for passive and active detection without writing code. *(P0 → P1 by the 2026-11-08 feature review.)* |
| SCN-061 | P1 | Schema: `metadata` (id, name, severity, confidence), `when` (GulpQL condition / insertion-point selector), `requests` (templated probes with Transform Tags and payload placeholders), `matchers` (status/word/regex/binary/time/OAST, with `and`/`or`), `extractors`, and `issue` (templated detail/remediation referencing captured groups). *(P0 → P1 by the 2026-11-08 feature review.)* |
| SCN-062 | P1 | A recipe editor with validation, a dry-run against a selected request, and a library folder (`~/.../recipes/`). *(P0 → P1 by the 2026-11-08 feature review.)* |
| SCN-063 | P1 | Import/convert common Nuclei/BCheck templates where feasible (document unsupported features). |
| SCN-064 | P1 | Recipes participate in scan configs like built-in checks (enable/disable, intensity). |
| SCN-065 | P2 | Share/export recipes; a signed-recipe notion for trust. |
| SCN-066 | P2 | A GraphQL/JSON-aware matcher helper set. |

### 3.4 Detection methodology (precision rules for the P0 active checks)

The catalog above names the checks; these are the techniques that keep them low-false-positive. All
compare against the per-insertion-point baseline + random canary (SCN-031) and skip pages flagged
volatile.

- **Boolean SQLi**: use a control triplet — a true-condition payload must make the response ≈ the
  baseline *and* a false-condition payload must differ from it; confirm with a second, independent
  inverted pair. Never fire on a single coincidental length delta, and never on a volatile page.
- **Time-based (SQLi/cmd)**: inject a *varying* delay (e.g. 0/5/10 s) and require the measured delay
  to **scale with** the injected value across repeats (dose-response), not merely exceed a flat
  threshold — this rejects uniformly slow/jittery endpoints. (Extends SCN-032.)
- **SSTI**: use **randomized** operands per probe (e.g. `{{a*b}}` with fresh a,b) and require the
  exact product to appear only in the injected response, so a literal already on the page can't
  masquerade as evaluation.
- **Reflected XSS**: beyond reflection, verify which context-breakout characters (`< > " '` per
  HTML/attr/JS/URL/CSS context) survive **unencoded** in the response; only an unencoded breakout is
  reported. The `/safe/xss/*` twins (encoded per context) must stay clean.
- **Stored XSS**: inject a **unique canary token** per injection so the later-rendered reflection can
  be located and attributed to the exact insertion point, across a different render endpoint
  (coordinated with the Crawler).
- **Open redirect**: inject a canary external host and its obfuscations (`//canary`, `/\canary`,
  whitespace/`@`-confusion, protocol-relative) and confirm an actual redirect to the canary via a 3xx
  `Location` or a client-side (meta/JS) redirect — not mere reflection in the body.
- **CRLF / header injection**: confirm a **real new response header or status-line split** was
  created (observe it in the parsed response), not merely that the payload is reflected in the body.

### 3.5 Cache poisoning & deception family (moved from F28, 2026-11-08; post-1.0)

An opt-in active check family (and Check-Recipe primitives) for web cache poisoning and web cache
deception. **Victim-safe by default**: every probe uses a per-run unique cache key (a cache-buster
the confirming request repeats) so a poisoned entry can only be observed by Gulp's own confirming
request, never by a real user. *(later: M24 — post-1.0, see the roadmap's Phase F.)*

| ID | Pri | Requirement |
|---|---|---|
| WCP-001 | P0 | Detect cacheability and infer cache status/age from `Age`, `X-Cache`, `CF-Cache-Status`, `Cache-Control`, `Vary`, ETag and response-time deltas, per URL. *(Moved from F28; later: M24.)* |
| WCP-002 | P0 | Probe candidate **unkeyed inputs** (a maintained header/param list) by injecting a unique canary, then issue a clean follow-up request to confirm the canary was cached and served *without* the input — proving a poisoning vector — using per-run unique keys so no real user is served a poisoned page. *(Moved from F28; later: M24.)* |
| WCP-003 | P0 | Test **cache deception** via path/extension confusion (`/profile`, `/profile.css`, `/profile/..%2f`, encoded suffixes) and report when authenticated/private content becomes publicly cacheable. *(Moved from F28; later: M24.)* |
| WCP-004 | P0 | Raise issues with the exact poisoning request, the confirming cached response, the inferred cache key, and blast-radius notes; all sends scope-gated and drawing from the shared limiter (F03 §3.4). *(Moved from F28; later: M24.)* |
| WCP-005 | P1 | Integrate with OAST (F10) for header-based SSRF/interaction that is cache-amplified; reuse the header wordlist from Param Discovery (F23). *(Moved from F28; later: M24.)* |
| WCP-006 | P1 | Detect cache-key normalization quirks (case, port, trailing dot, duplicate headers) that enable keyed-but-equivalent poisoning. *(Moved from F28; later: M24.)* |
| WCP-007 | P1 | Ship as an opt-in active check family in scan configurations and as Check-Recipe primitives (cacheability matchers). *(Moved from F28; later: M24.)* |
| WCP-008 | P2 | A guided multi-request confirmation workbench (poison → observe → auto-expire) with strong warnings; never auto-run on shared production caches without explicit confirmation. *(Moved from F28; later: M24.)* |

Notes for this family: a cached hit is typically much faster and carries `Age`/cache-status headers;
factor `Vary` (cookies, encodings) into the cache-key model; short TTLs mean the confirming request
must race the TTL (retry with timing awareness); reuse the F13 diff machinery to detect reflected
effects; and don't confuse mere reflection with a *cached* reflection — the clean follow-up is what
proves it.

### 3.6 WebSocket checks (moved from F26, 2026-11-08; post-1.0)

*(later: M22 — post-1.0, see the roadmap's Phase F.)*

| ID | Pri | Requirement |
|---|---|---|
| WSX-003 | P0 | **CSWSH** (cross-site WebSocket hijacking): replay the upgrade handshake with a forged/absent/cross-origin `Origin` header (cookies kept) and report whether the server still upgrades and returns authenticated data in the first frames; raise a CSWSH issue. *(Moved from F26; later: M22.)* |

## 4. Live passive scanning (M10a)

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
- *(M15)* A YAML Check Recipe for a custom header-leak detects it on a crafted VulnLab route and
  renders the templated issue with the captured value.
- *(M11c)* The A6 checks (SCN-070…074) each find their VulnLab endpoint (`/pp/merge`, `/cspt/`,
  `/api/users/me`, `/upload`, `/api/me` with weak JWT handling) and stay silent on the `/safe/*`
  twins.
- *(post-1.0, M25)* Retest: a VulnLab issue's proof re-run after the endpoint is patched returns
  "Fixed" with the new (now-safe) evidence; before patching it returns "Still-Vulnerable" (moved
  from F30).
- *(post-1.0, M24)* Cache family: VulnLab reflects `X-Forwarded-Host` into a cached response; the
  family confirms poisoning via a clean follow-up and reports the key, and the non-caching twin is
  clean. An `/account` endpoint cached as `/account.css` is flagged as cache deception; the hardened
  twin (`Cache-Control: private`) is clean. A header-based SSRF reflected into cache produces an
  OAST interaction correlated to the probe. Run as the opt-in family, there are no false positives
  on the safe twins (moved from F28).
- *(post-1.0, M22)* CSWSH: a socket that upgrades with a cross-origin `Origin` and returns user data
  is reported; the Origin-checking twin is clean (moved from F26).
