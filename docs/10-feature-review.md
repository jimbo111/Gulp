# 10 — Per-feature review, with the tests that prove each feature (2026-11-13)

This is the feature-level counterpart to `08-architecture-review.md` (structure and invariants) and
`09-burpsuite-comparison.md` (competitive position). For every shipped feature area it states: what is
built, which module holds it, the **tests and the executable Definition-of-Done (DoD) that prove it**,
the Burp parity verdict, and the honest gaps. The point is that every "done" claim here is backed by a
test you can run, not an assertion.

## 1. Method and how to reproduce

- **Unit/property/integration tests** live in `Packages/GulpKit/Tests/*` and run with
  `swift test --package-path Packages/GulpKit` (Linux-friendly for the platform-independent modules).
  As of this review the suite is **451 `@Test` cases across 25 targets**.
- **Executable DoDs** live in `Scripts/m*-dod.sh` (plus `recon`, `report`, `recipe`, and
  `m11c-checks`). Each spins up the real `gulp-vulnlab` server and drives the real `gulp-cli`, then
  asserts exact outcomes (for the scanner: the precise issue types per route, and **nothing** on the
  `/safe/` twins). They run in CI (`.github/workflows/ci.yml`) and in the local gate
  (`Scripts/localci.sh`). This is the project's core quality claim: the scanner's precision/recall is
  a number you can reproduce, not a black box.
- **Architecture conformance** is itself a test: `Scripts/arch-check.sh` fails the build if a module
  imports across the layering boundaries defined in `01-architecture.md`.

Legend for the verdict column: ✅ parity · ⭐ Gulp advantage over Burp · 🟡 partial · ⬜ not built.

## 2. Coverage at a glance

| # | Feature area | Module(s) | Tests | DoD | vs Burp |
|---|---|---|---|---|---|
| 1 | Byte-exact HTTP engine (h1/h2, upstream proxies, decompression) | GulpHTTP, GulpCore | `GulpHTTPTests` (57), `GulpCoreTests` (59) | `m1`, `m3b` | ⭐ |
| 2 | TLS interception + per-host CA | GulpTLS | `GulpTLSTests` (15) | `m3a` | ✅ |
| 3 | Intercepting proxy (h1/h2/WS, intercept queue, M&R) | GulpProxy | `GulpProxyTests` (39) | `m2`, `m4a`, `m4b` | ✅ |
| 4 | Storage, history, write coalescing, paging | GulpStore | `GulpStoreTests` (30) | `m2` | ✅ |
| 5 | Repeater (tabs, single-packet, pipelining, throttle) | GulpRepeater | `GulpRepeaterTests` (7), HTTP engine tests | `m5` | ✅ |
| 6 | Codec: paste-to-request, transforms, JWT, GraphQL, protobuf | GulpCodec | `GulpCodecTests` (56) | `m5`, `m6b`, `m7`, `m10b`, `m13b-graphql` | ⭐ |
| 7 | Comparer (Myers word/byte diff) | GulpDiff | `GulpDiffTests` (6) | `m7` | ✅ |
| 8 | Fuzzer (4 attack types, payloads, discovery) | GulpFuzzer | `GulpFuzzerTests` (19) | `m8` | ⭐ |
| 9 | GulpQL + logger + notebook + coverage | GulpQuery, GulpStore | `GulpQueryTests` (9), store tests | `m9` | ⭐ |
| 10 | Passive scanner + issue model | GulpScanner | `GulpScannerTests` (43) | `m10a` | ✅ |
| 11 | Active scanner + full check catalog | GulpScanner | `GulpScannerTests` (43) | `m11b`, `m11c`, `m11c-checks` | 🟡→⭐ |
| 12 | gRPC / protobuf | GulpCodec, GulpWorkspace | codec + workspace tests | `m10b` | ⭐ |
| 13 | Crawler (static) | GulpCrawler | `GulpCrawlerTests` (7) | `m11a` | ✅ |
| 14 | OAST (interactsh client + Beacon) | GulpOAST | `GulpOASTTests` (4) | `m11a` | ⭐ |
| 15 | Sessions, macros, request signing | GulpSession | `GulpSessionTests` (17) | `m12a` | ⭐ |
| 16 | Authorization matrix | GulpWorkspace | `GulpWorkspaceTests` (60, incl. authz) | `m12b` | ⭐ |
| 17 | Recon (secrets + JS endpoints + vuln JS libs) | GulpScanner | `GulpScannerTests` | `recon` | ⭐ |
| 18 | Reporting (HTML + Markdown) + Check Recipes | GulpReport, GulpScanner | `GulpReportTests` (4) | `report`, `recipe` | ✅ |
| 19 | Automation: CLI, MCP server | gulp-cli, GulpWorkspace | `GulpAutomationTests` (5) | `m6b` | ⭐ |
| 20 | Sequencer (token randomness) | GulpSequencer | `GulpSequencerTests` (11) | `sequencer` | ✅⭐ |
| 21 | Workspace orchestration (the glue) | GulpWorkspace | `GulpWorkspaceTests` (60) | all live DoDs | — |

Not built / platform-gated (honest status, §5): browser automation & DOM probe (M13a), extensions/JS
API (M15), AI assistant (M18), Sequencer (post-1.0), the macOS SwiftUI UI (`GulpFeatures`, 7.2k LOC,
unverified without macOS CI), HTTP/3, request-smuggling tooling.

## 3. Feature-by-feature

Each subsection: **what it does · module · proof (tests + DoD) · Burp verdict · gaps**. Specific
`@Test` display names are quoted from the suite.

### 3.1 HTTP engine — byte-exact, h1 + h2 ⭐
- **Does:** sends exactly the bytes the user wrote (the enforced "raw bytes are the truth"
  invariant), HTTP/1.1 and HTTP/2 both ways with ALPN mirroring and h2c, upstream HTTP/SOCKS proxies,
  transparent decompression, h1↔h2 text conversions, trailers.
- **Module:** `GulpHTTP` (+ `GulpCore` for the conversions and model types).
- **Proof:** `GulpHTTPTests` (57) and `GulpCoreTests` (59), with round-trip/property tests mandated
  since M1 — e.g. "HTTP-001: parse(bytes).serialize() == bytes for every fixture", "editing a header
  changes only that header's bytes", "a 1 MB header and 10k headers parse and round-trip", and
  "fuzz: random HTTP-shaped inputs never crash and keep every invariant". Framing hostility is proven
  in the proxy: "F01 §4.1: hostile framing is refused instead of guessed (no overflow, no desync)".
  The `m1` DoD sends raw requests through the real engine and `gulp-cli send --raw`; the `m3b` DoD
  exercises upstream h2/h2c/multiplexing and single-packet group sends against VulnLab. Byte-fidelity
  is also guarded structurally: there are **zero `URLSession`/`URLRequest` uses in any engine**.
- **Burp:** ⭐ — Burp's send path re-normalizes some requests; Gulp never round-trips through a parser,
  which is the correct foundation for smuggling/desync/header-injection work.
- **Gaps:** HTTP/3 (QUIC) is post-1.0.

### 3.2 TLS interception + CA ✅
- **Does:** generates a per-user CA (RSA-2048 default) on first use, mints leaf certs with SNI, stores
  the CA key in the macOS Keychain or a 0600 file elsewhere (the "no secrets in the repo" rule).
- **Module:** `GulpTLS`.
- **Proof:** `GulpTLSTests` (15) — leaf minting, SNI, trust chain; the `m3a` DoD drives TLS
  interception end-to-end.
- **Burp:** ✅ parity.

### 3.3 Intercepting proxy — h1/h2/WebSockets, intercept queue, Match & Replace ✅
- **Does:** forward proxy for HTTP/1 and HTTP/2 with client-side ALPN mirroring; an intercept queue
  with rules; Match & Replace with GulpQL-powered conditions; WebSocket intercept/repeat; streaming
  responses and pending rows; scope-aware recording.
- **Module:** `GulpProxy`.
- **Proof:** `GulpProxyTests` (39); DoDs `m2` (forward proxy), `m4a` (intercept queue + M&R), `m4b`
  (streaming, WebSockets, browser launch).
- **Burp:** ✅ parity; Match & Replace conditions use GulpQL (see 3.9), which is more expressive than
  Burp's literal rules.

### 3.4 Storage & history ✅
- **Does:** SQLite project store (schema-versioned, migrations), a write coalescer so the main thread
  never waits on the DB, paged async queries, FTS, issues/evidence tables, WebSocket messages.
- **Module:** `GulpStore` (GRDB).
- **Proof:** `GulpStoreTests` (30) — migrations, coalescing, paging, FTS, issue upsert/dedup; the `m2`
  DoD records real proxy traffic into a project and reads it back. **Per-project isolation** was
  re-verified this session while debugging the prototype-pollution DoD (the store is the `.gulp` file;
  `GULP_SUPPORT_DIR` only relocates the support dir, not the project DB).
- **Burp:** ✅ parity.

### 3.5 Repeater ✅
- **Does:** persisted Repeater tabs, paste-to-request (cURL/fetch/raw), single-packet group send
  (HTTP/2 race), raw h2, pipelining, throttle, streamed responses, WS Repeater.
- **Module:** `GulpRepeater` (+ engine features in `GulpHTTP`).
- **Proof:** `GulpRepeaterTests` (7) + the HTTP engine's single-packet/pipelining tests; `m5` DoD.
- **Burp:** ✅ parity (single-packet attack included).

### 3.6 Codec — transforms, JWT, GraphQL, protobuf ⭐
- **Does:** Smart Decode, a transform registry with reversible inline Transform Tags and preview; a
  JWT workbench (alg:none, RS→HS confusion, weak secret, kid/jku/x5u); GraphQL (introspection, schema
  model, variable insertion points); schema-less protobuf + `.proto` import + gRPC/gRPC-Web/Connect
  framing; many import/export formats (HAR, Postman, Caido, OpenAPI, CSV, …).
- **Module:** `GulpCodec`.
- **Proof:** `GulpCodecTests` (56) — the largest unit target; DoDs `m7` (transforms, JWT), `m6b`
  (formats, OpenAPI), `m10b` (protobuf/gRPC), `m13b-graphql` (introspection + field-authz).
- **Burp:** ⭐ — JWT, GraphQL and protobuf are all third-party extensions in Burp; here they are
  first-party and tested.

### 3.7 Comparer ✅
- **Does:** Myers diff, word and byte granularity, pre-diff transforms.
- **Module:** `GulpDiff`. **Proof:** `GulpDiffTests` (6); `m7` DoD. **Burp:** ✅.

### 3.8 Fuzzer ⭐
- **Does:** the four Intruder-class attack types (sniper/battering-ram/pitchfork/cluster-bomb),
  payload sources and processing, grep-match/extract/reflection/anomaly analysis, a concurrent runner
  with rps cap, retries, stop-on, pause/resume/cancel, recursive grep, ScopeGuard, content discovery,
  and **native protobuf-field positions**.
- **Module:** `GulpFuzzer`. **Proof:** `GulpFuzzerTests` (19); `m8` DoD (incl. content discovery).
- **Burp:** ⭐ — no Community-tier throttle (the limiter is a user-controlled safety cap, not a
  paywall), and protobuf-field fuzzing is native (Burp needs an extension).

### 3.9 GulpQL + logger + notebook ⭐
- **Does:** a real query language over history (lexer/parser/AST/evaluator with push-down to SQL),
  FTS search, saved filters, the Logger, a Notebook, and a coverage index — and GulpQL is **reused**
  in intercept rules and Match & Replace.
- **Module:** `GulpQuery` (+ store integration). **Proof:** `GulpQueryTests` (9) + store query tests;
  `m9` DoD. **Burp:** ⭐ — Burp's Bambdas are Java snippets; GulpQL is a language usable by
  non-programmers and shared across the product.

### 3.10 Passive scanner + issue model ✅
- **Does:** ~33 passive checks (security headers, cookies, disclosure, CORS/caching/TLS/mixed-content,
  reflection signposts), an issue model with dedup, evidence with byte-range markers, overrides,
  status, and a notebook link; JSON + SARIF export.
- **Module:** `GulpScanner` (+ `GulpCore` issue types). **Proof:** `GulpScannerTests` (43, shared with
  active); `m10a` DoD against planted passive routes with safe twins. **Burp:** ✅; SARIF out of the
  box is ⭐.

### 3.11 Active scanner + check catalog 🟡→⭐
- **Does (P0):** reflected/stored XSS by context, SQLi (error/boolean/time with dose-response), OS
  command injection (time + OAST), SSTI, path traversal, XXE, SSRF, open redirect, CRLF.
- **Does (P1, landed this session):** CORS, host-header injection, JWT-in-scan (alg:none/weak-secret),
  mass assignment (SCN-072), **server-side prototype pollution (SCN-070)**, and **NoSQL `$where`,
  XPath (via `string-length()`), and LDAP (wildcard) injection** — each engineered to fire only for
  its own family (verified by the live DoD reporting 0 cross-matches).
- **Module:** `GulpScanner`. **Proof:** `GulpScannerTests` (43) incl. the `@Test` cases
  "SCN-030…033: every planted vulnerability is found, with OAST and dose-response timing",
  "SCN-030: the safe twins produce nothing", "SCN-032: a constant delay is not a time-based injection
  (dose-response required)", "SCN-038: the per-point budget caps probes", and the M11c family tests
  for CORS/host-header, JWT, mass assignment, prototype pollution, and NoSQL/XPath/LDAP. DoDs: `m11b`
  (39 routes, 25 expected issues, **0 missing / 0 unexpected**), `m11c` (crawl-and-audit, OpenAPI
  scan, gRPC points, re-test), and `m11c-checks` (prototype pollution, mass assignment, NoSQL, XPath,
  LDAP — each fires on the vulnerable route, nothing on the safe twin).
- **Burp:** 🟡→⭐ — the methodology is open and reproducible against a vulnerable lab with safe twins
  (Burp's checks are closed); breadth is now most of Burp's catalog.
- **Gaps:** client-side path traversal (CSPT, browser-gated) and file-upload bypass remain.

### 3.12 gRPC / protobuf ⭐
- **Does:** schema-less protobuf wire decode, descriptor models, `.proto` parser, named decode to
  JSON, gRPC/gRPC-Web/Connect framing + reflection fetch, Repeater calls, Fuzzer protobuf positions.
- **Module:** `GulpCodec` (+ `GulpWorkspace` RPC service). **Proof:** codec tests + workspace RPC
  tests; `m10b` DoD (Echo/Say, streaming, Orders/Get + safe twin, reflection). **Burp:** ⭐ (extension
  territory in Burp).

### 3.13 Crawler ✅ · 3.14 OAST ⭐
- **Crawler:** static crawl (links/forms), scope-bound, re-auth hook. `GulpCrawlerTests` (7); `m11a`.
- **OAST:** interactsh-compatible client + a self-hostable dev Beacon server, store tables, the
  `beacon()` transform tag. `GulpOASTTests` (4); `m11a`. **Burp:** ⭐ — self-hostable and not tied to
  a vendor Collaborator.

### 3.15 Sessions, macros, request signing ⭐
- **Does:** cookie jar, identities, variables, login macros, session handling rules, and **request
  signing: DPoP (RFC 9449), HTTP Message Signatures (RFC 9421), AWS SigV4** — running last and signing
  the actual sent bytes.
- **Module:** `GulpSession`. **Proof:** `GulpSessionTests` (17) — "SES-016: a DPoP proof carries
  htm/htu/jti/ath and verifies against its own JWK", "SES-017: an HMAC message signature builds a
  verifiable RFC 9421 base and Content-Digest", "SES-018: SigV4 signs host, date and the payload hash;
  the signature re-derives exactly", plus "SES-020/021: a login macro chains a CSRF token and carries
  cookies forward" and (in the workspace) "SES-012: concurrent stale requests trigger exactly one login
  macro (single-flight)". The `m12a` DoD signs against VulnLab `/signed/*` and verifies independently.
  **Burp:** ⭐ — all three signing schemes are separate extensions in Burp (SigV4 is Pro+add-on).

### 3.16 Authorization matrix ⭐
- **Does:** replay each request as every configured identity, compute an access-control verdict,
  auto-raise issues for broken access control; a safe twin stays "Enforced".
- **Module:** `GulpWorkspace` (AuthzMatrix service). **Proof:** the `@Suite("Authz Matrix analysis
  (ADV-003)")` cases — "an authenticated non-owner matching the authorized response is a bypass", "a
  denied response is enforced", "the unauthenticated column matching is public, not a bypass", "the
  authorized identity's own cell is the baseline", "a same-status but different body needs review;
  similarity honours the threshold" — plus the `m12b` DoD (flags the IDOR as a bypass, `/safe` twin
  Enforced). **Burp:** ⭐ — Autorize is a third-party extension; here it is built in and its verdict
  logic is unit-tested.

### 3.17 Recon ⭐
- **Does:** always-on passive secret detection (curated ruleset + entropy: AWS/Google/GitHub/GitLab/
  Slack/Stripe keys, JWTs, private keys, generic high-entropy assignments), JS endpoint/path
  extraction, and vulnerable-JS-library fingerprinting (jQuery, lodash, Bootstrap, Moment, Handlebars,
  AngularJS, DOMPurify) with a bundled advisory dataset — no network at scan time.
- **Module:** `GulpScanner` (`Recon*`, `VulnLibraryCheck`). **Proof:** the `@Suite("Recon checks
  (F27)")` cases — "a hard-coded AWS key and a Stripe key are flagged as secrets", "a generic
  high-entropy secret is caught; a low-entropy placeholder is not", "endpoints are extracted from
  JavaScript, not from HTML", "a clean JS file produces nothing" — and `@Suite("Vulnerable JS
  libraries")` ("A vulnerable jQuery by filename is flagged; a fixed one is not", "AngularJS is always
  flagged (end of life)"); the `recon` DoD flags planted secrets and stays clean on safe twins.
  **Burp:** ⭐ (extension territory, with weaker entropy handling).

### 3.18 Reporting + Check Recipes ✅
- **Does:** HTML and bug-bounty Markdown reports from issues (`gulp-cli report`); declarative
  JSON/YAML passive Check Recipes that join the scan with no code.
- **Module:** `GulpReport`, `GulpScanner`. **Proof:** `GulpReportTests` (4); `report` and `recipe`
  DoDs. **Burp:** ✅ (SARIF is ⭐); PDF export and active recipes remain.

### 3.19 Automation — CLI + MCP ⭐
- **Does:** `gulp-cli` makes every feature headless/scriptable; an MCP stdio server exposes
  history/send/scan to an AI agent with an audit log.
- **Module:** `gulp-cli`, `GulpWorkspace`. **Proof:** `GulpAutomationTests` (5); `m6b` DoD (MCP).
  **Burp:** ⭐ — first-party agent interface and a complete CLI (Burp's headless is a limited REST API).

### 3.20 Sequencer — token randomness ✅⭐
- **Does:** collects many security-sensitive tokens (by cookie name or a regex capture) and estimates
  their effective entropy with a statistical battery — NIST SP 800-22-style bit tests (monobit, block
  frequency, runs, longest run, approximate entropy, cumulative sums), a FIPS poker χ², and a
  per-position character χ² — returning a verdict (Excellent…Extremely poor) and the estimated bits.
  Constant framing is stripped (SEQ-007); non-power-of-two alphabets fall back to the character test.
- **Module:** `GulpSequencer` (pure Swift, Linux-testable). **Proof:** `GulpSequencerTests` (11),
  including reference-vector checks of the incomplete-gamma p-value ("regularizedGammaQ matches closed
  forms: Q(1,x)=e^-x and Q(½,x)=erfc(√x)"), "a high-quality pseudo-random stream passes every bit
  test", "a biased (70% ones) stream fails the frequency tests", and the verdicts "CSPRNG hex tokens
  are rated Excellent…" / "a counter-derived token is rated Poor…". The `sequencer` DoD captures live
  from VulnLab: `/token/weak` (a counter) rates Extremely poor (~0 of 12 bits), `/token/strong`
  (CSPRNG) rates Excellent (~63.9 of 64 bits).
- **Burp:** ✅ parity with Burp's Sequencer, and ⭐ the method is open and reference-tested rather than
  a black box. **Gaps:** the Swift-Charts UI and project-saved runs are macOS/post-1.0 carry-overs.

### 3.21 Browser automation + DOM Probe 🟡→⭐
- **Does:** a Chrome DevTools Protocol client (connect, command id-correlation, event routing,
  remote-error handling) and a launch helper (automation flags, `DevToolsActivePort` → `ws://`); a DOM
  Probe that injects a taint-tracking instrumentation to report client-side source→sink flows
  (DOM-based XSS).
- **Module:** `GulpBrowser`. **Proof:** `GulpBrowserTests` — "a command is answered by id; concurrent
  commands correlate to their own results", "a remote error becomes a thrown CDPError.remote", "events
  are delivered on the events stream, not confused with responses", "the automation flags carry the
  debug port, isolated profile, proxy and SPKI pin", "the DevToolsActivePort file is parsed into a
  ws:// endpoint". The instrumentation is **validated against real headless Chromium** by
  `Scripts/dom-probe-check.mjs` (`m13a-dom-probe-dod.sh`): it reports the planted DOM XSS on `/spa`
  (location.hash → innerHTML) and nothing on `/safe/spa`. The embedded `dom-probe.js` is the exact
  bytes shipped, so what the browser tests is what runs.
- **Burp:** 🟡→⭐ — DOM Invader is a Burp feature; here the probe is built and its detection is proven
  against a real browser with an open, inspectable instrumentation.
- **Gaps:** the swift↔real-browser integration (crawl/login/passkeys) and the macOS UI need a
  Chromium+Swift host; the verification sandbox has Chromium and Swift in separate places.

### 3.22 Extensions (out-of-process) 🟡→⭐
- **Does:** loads an extension described by a `gulp-extension.json` manifest with declared, user-approved
  permissions, and runs it as a child process speaking JSON-RPC 2.0 over stdio: `initialize` reads the
  checks it registers, `passiveCheck` runs them over traffic, and the extension can call back into Gulp
  (`host/log`, and `http/send` only if granted).
- **Module:** `GulpExtensions`. **Proof:** `GulpExtensionsTests` — "frames round-trip, even split
  across arbitrary byte chunks", "a gulp-extension.json parses with its runtime, permissions and
  hooks", "initialize reads the extension's declared checks", "a passive check returns findings only
  when create-issues is granted", "an inbound http/send is denied without the http-send permission",
  and "**a bash extension over real stdio registers a check and reports a finding**" — a dependency-free
  sample extension (`SDK/examples/header-leak`) driven as a real subprocess.
- **Burp:** 🟡→⭐ — the out-of-process host (any language, permission-scoped) is built and tested;
  Burp's BApp ecosystem is far larger, and the in-process JS host + manager UI remain.
- **Gaps:** in-process JS (JavaScriptCore, macOS), the Python/TS SDKs, and the extension-manager UI.

### 3.23 AI assistant (provider abstraction + bounded agent) 🟡
- **Does:** a provider-agnostic LLM layer (Claude via the Messages API) with a redaction pipeline that
  masks secrets before egress, and a bounded agentic loop ("Investigate this endpoint") with hard
  step/request budgets, a cancel/panic stop, and per-run grounding on Gulp's own tool surface.
- **Module:** `GulpAI`. **Proof:** `GulpAITests` — "secrets are masked; header names are kept;
  disabling is a no-op", "the loop runs a tool, feeds back a redacted result, and returns the final
  answer", "the step budget stops a model that keeps calling tools", "the request budget blocks active
  sends past the cap", "the kill switch / panic stop ends the run immediately", and the Anthropic
  wire-format tests ("the request body carries system, messages, tool results and tools" / "a text +
  tool_use response parses into an LLMResponse with usage"). All run against a scripted mock provider —
  no key or network.
- **Burp:** 🟡 — Burp AI exists; Gulp's assistant is grounded on its open MCP/CLI tool surface with
  explicit budgets and secret redaction, but the consent/chat UI and live key wiring remain.
- **Gaps:** the egress-consent + chat UI, Keychain key storage, and wiring the loop's executor to the
  live F21 services are provider-/macOS-gated.

## 4. Cross-cutting quality evidence

- **Scope safety (CLAUDE.md hard rule):** `GulpScannerTests` includes "SCN-012 / CLAUDE.md scope
  safety: out-of-scope requests are never sent"; every active tool checks `ScopeGuard` before sending.
- **Precision discipline:** the active scanner's DoD asserts **nothing** on every `/safe/` twin — a
  false-positive is a build failure. The LDAP wildcard check was tightened this session precisely
  because it first false-positived on reflecting endpoints.
- **Concurrency:** Swift 6 strict concurrency across the package; `@unchecked Sendable` only with a
  justifying comment (e.g. the lock-guarded lab stores).
- **Architecture conformance:** `arch-check.sh` is in CI; engines never import UI; `GulpCore` imports
  nothing from the app.

## 5. Honest "not built / gated" list

| Area | Status | Why |
|---|---|---|
| Browser automation, recorded login, DOM/DOM-XSS probe (M13a) | ⬜ | Needs CDP + a real browser; macOS-gated. `GulpBrowser` is launch-only (211 LOC). |
| Extensions / JS API + active Check Recipes (M15) | ⬜ | `GulpExtensions`, `GulpScript` are 13-LOC stubs. |
| AI assistant (M18) | ⬜ | `GulpAI` is a 13-LOC stub; provider-gated. |
| Sequencer (randomness analysis) | ⬜ | `GulpSequencer` is a 13-LOC stub; moved to post-1.0. |
| macOS SwiftUI views (`GulpFeatures`, 7.2k LOC) | 🟡 | Implemented but **unverified** without macOS CI (`xcodebuild` unavailable on Linux). The message-editor/inspector *logic* in `GulpUI` is tested on Linux: "UI-010/UI-020" — UTF-8/Latin-1 round-trip and request/response section parsing (3 real tests). |
| HTTP/3 (QUIC) client, request-smuggling tooling | ⬜ | Post-1.0 backlog. |
| PDF report export, per-identity client-cert selection | 🟡 | Carry-overs. |

### 5.1 Test-coverage gaps worth closing (found during this review)

These are places where the feature exists but the **test suite** is thinner than it should be —
tracked here so the coverage claim stays honest:

- **Integration tests** (addressed 2026-11-13): `IntegrationTests` now carries a real end-to-end test
  — "a vulnerable page is captured, scanned into issues, and rendered into HTML + Markdown reports" —
  that drives the `capture → store → passive scan → report` pipeline across GulpStore, GulpScanner
  (via the workspace) and GulpReport in one flow. Further end-to-end paths (an active scan through the
  engine, a full proxy round-trip) could still be added, but the core pipeline is now covered.
- **DB migrations:** `GulpStoreTests` proves schema v1 creation but not a v1→later migration path
  (there is only one schema version today, but the migrator is untested for upgrades).
- **Suite-advertised but unnamed requirement IDs:** a few suites name a range wider than their tests —
  GOV-003 (limiter), BCN-005 (OAST), CRL-009/010 (crawler), HIS-023 (GulpQL), several REP-0xx. The
  behaviour may be covered transitively, but there is no dedicated assertion.
- **Protocol breadth:** no named tests for SOCKS auth / proxy-chaining, HTTP/2 flow-control
  (GOAWAY/RST_STREAM), frame-level HPACK decode (text-form only), NTLM/Negotiate auth, or GraphQL
  mutations/variable substitution. These are real-world cases a top-tier tool should pin down.

## 6. Verdict

Across the **built** feature set, Gulp is at parity with Burp Suite on the core workflow (proxy, TLS,
repeater, scanner, target, decoder, comparer, fuzzer) and **ahead** on a meaningful list that Burp
leaves to third-party extensions or paywalls: byte-exact HTTP, the Authz Matrix, JWT/GraphQL/protobuf,
request signing (DPoP/RFC 9421/SigV4), GulpQL, self-hostable OAST, always-on secret/JS recon, SARIF,
and an agent-native CLI + MCP surface. Every one of those claims is backed by a unit test and, for the
server-facing features, an executable DoD that runs in CI against a vulnerable lab with safe twins.

The remaining distance to "decisively beat Burp everywhere" is concentrated in the platform-gated and
not-yet-built areas in §5 — browser-driven testing, the extension ecosystem, and AI triage — not in
the core that is already tested and shipping.
