# 06 — Testing strategy

## 1. Test pyramid

| Level | Where | Tooling | What |
|---|---|---|---|
| Unit | `Packages/GulpKit/Tests/<Module>Tests` | Swift Testing (`import Testing`, `@Test`, `#expect`) — XCTest is acceptable where Swift Testing lacks something | Parsers, codecs, GulpQL, diff, payload generators, statistics, cert minting, scope matching |
| Integration | `Tests/IntegrationTests` | Swift Testing + an in-process VulnLab + an in-process proxy | Proxy ↔ engine ↔ store end-to-end; scanner against VulnLab; Beacon client ↔ dev Beacon server |
| UI | `GulpAppUITests` (XCUITest) | Xcode | Smoke flows: create a project, see proxied traffic, send to Repeater, run an attack |
| Performance | `Tests/PerformanceTests` (run with `make perf`, not in the default `make test`) | `ContinuousClock` measurements with budgets from doc 01 §9 | Throughput, latency, table paging, project open |
| Fuzz | `Tests/FuzzTests` (Linux, libFuzzer via `-sanitize=fuzzer`) plus a deterministic random-input test in the unit suite | | HTTP/1 parser, HTTP/2 frame handling, GulpQL parser, decoders |

Rules:

- Name tests after requirement IDs: `@Test("PRX-010 intercept queue forwards edited request")`.
- No test may hit the public internet. Everything runs against VulnLab, a dev Beacon or in-memory
  fixtures. Use `127.0.0.1` with ephemeral ports (bind to port 0 and read the assigned port).
- Tests must be deterministic. Inject a clock and a random source (`RandomNumberGenerator`) where
  timing or randomness matters.

## 2. Property and round-trip tests (must exist from M1)

- `parse(bytes).serialize() == bytes` for every fixture in
  `Packages/GulpKit/Tests/GulpCoreTests/Fixtures/http/` (`request-*.http` / `response-*.http`, exact
  wire bytes protected by `.gitattributes`), including malformed ones: bare LF, duplicate headers,
  obs-fold, missing final CRLF, NUL bytes; the 1 MB-header and 10k-header cases and a seeded fuzz
  corpus are generated in `ParserPropertyTests`.
- Editing a header via `ParsedRequest` changes only that header's bytes.
- Codecs: `decode(encode(x)) == x` over random bytes, for every reversible codec.
- GulpQL: `parse(print(ast)) == ast`.

## 3. VulnLab — the reference vulnerable target (`gulp-vulnlab`)

VulnLab is a deliberately vulnerable web app that ships in the repo (`gulp-vulnlab` executable
target). Its protocol-level **Basics** fixtures (`/echo`, `/echo-raw`, `/chunked`, `/continue`, …) run
on a small raw SwiftNIO server so every byte on the wire is exact — a framework would normalize the
very things they exist to exercise (1xx responses, chunk bytes, verbatim echo). The app-level
endpoints below (auth, XSS, SQLi, …) may use Hummingbird. The M1 DoD is executable:
`Scripts/m1-dod.sh` (run by the Linux CI job).
It's the fixture for manual checks, integration tests and scanner accuracy tests. **It must bind
only to 127.0.0.1** and prints a warning banner at startup.

Each vulnerable endpoint has a **safe twin** (the same shape, but correctly implemented) so that
tests can measure false positives.

| Area | Vulnerable endpoint(s) | Safe twin | Used by |
|---|---|---|---|
| Basics | `/echo` (reflects the request as a readable response), **`/echo-raw`** (a raw TCP listener on :8089 that writes back the exact bytes it received, verbatim — used for byte-fidelity tests with malformed/duplicate headers and bare LF), `/redirect?to=`, `/chunked`, `/gzip`, `/slow?ms=`, `/large?mb=`, `/status/{code}`, `/continue` (emits `100 Continue` then the final response), `/h2` (HTTPS listener on :8443 with ALPN h2), **`/sse`** (a `text/event-stream` that emits one numbered event every 200 ms, with heartbeat comments, until the client disconnects or `?n=` events were sent — M4b streaming) | — | F01, F03, F05, F06 |
| Auth | `/login` (form + CSRF token), `/account` (session cookie), `/api/me` (Bearer JWT that accepts `alg:none`, RS→HS key confusion, a weak HMAC secret from the bundled wordlist, and `kid` path traversal), session expires after N requests (configurable) | `/safe/api/me` (pinned algorithm, strong key, `kid` allowlist) | F15, F07, F12 (JWT Workbench), SCN (SCN-074) |
| Request signing (M12a) | `/signed/dpop` (requires a valid DPoP proof bound to the access token, issues `DPoP-Nonce`), `/signed/http-sig` (verifies an RFC 9421 signature over `@method @target-uri content-digest`), `/signed/sigv4` (verifies AWS SigV4 with a fixture key, region and service) | — (each rejects unsigned/badly signed requests with 401) | F15 SES-016…018 |
| Passkeys (M13a) | `/webauthn/register` + `/webauthn/login` (a WebAuthn relying party for `localhost`; the session cookie is issued only after a valid assertion) | — | F16 BRW-016, F15 SES-032 |
| Reflected XSS | `/xss/html?q=`, `/xss/attr?q=`, `/xss/js?q=`, `/xss/url?q=` (into href) | `/safe/xss/...` (encoded per context) | SCN |
| Stored XSS | `/guestbook` (POST, then rendered on GET) | `/safe/guestbook` | SCN |
| DOM XSS | `/spa` (JS reads `location.hash` into `innerHTML`) | `/safe/spa` | BRW (DOM Probe) |
| SQL injection | `/sqli/error?id=` (SQLite, error-based), `/sqli/bool?id=`, `/sqli/time?id=` (simulated delay), `/sqli/json` (JSON body) | `/safe/sqli/...` (parameterized) | SCN |
| OS command injection | `/cmd/ping?host=` (simulated; never executes a real shell; pattern-matched to emulate behavior, including the time delay and an OAST lookup to the configured Beacon host) | `/safe/cmd/ping` | SCN, BCN |
| SSTI | `/ssti?name=` (a tiny template engine that evaluates `{{ a*b }}`) | `/safe/ssti` | SCN |
| Path traversal | `/file?name=` (serves from a sandboxed fixture tree that contains a fake `etc/passwd`) | `/safe/file` | SCN |
| XXE | `/xml` (simulated entity expansion against a fixture file) | `/safe/xml` | SCN |
| SSRF | `/fetch?url=` (performs the HTTP fetch only to the Beacon/dev host; anything else is simulated) | `/safe/fetch` | SCN, BCN |
| Open redirect | `/go?next=` | `/safe/go` | SCN |
| CORS | `/api/cors` (reflects Origin with credentials) | `/safe/api/cors` | SCN |
| Header issues | Pages with missing CSP/HSTS, cookies without Secure/HttpOnly, verbose errors with stack traces, an exposed `.git/HEAD`, `/.env` | `/safe/*` with correct headers | SCN passive |
| CRLF / header injection | `/crlf?lang=` (sets a header from input) | `/safe/crlf` | SCN |
| Request smuggling | A raw NIO listener on :8090 that emulates a CL.TE front-end/back-end pair | — | ADV |
| Race condition | `/race/redeem` (a check-then-act with a 50 ms window; a coupon can be redeemed only once) | — | REP, F03 |
| IDOR / access control | `/api/orders/{id}` (no owner check), `/admin` (role check by cookie `role=`) | `/safe/api/orders/{id}` | ADV (Authz Matrix) |
| Tokens | `/token/weak` (sequential/time-based), `/token/strong` (CSPRNG) — kept for the post-1.0 Sequencer (F11 is out of v1 since 2026-11-08); no v1 test uses them | — | SEQ (post-1.0) |
| GraphQL | `/graphql` (introspection on, a field-level authz bug) | — | ADV |
| OpenAPI | `/openapi.json` describing the `/api/*` routes | — | ADV, SCN |
| WebSockets | `/ws/chat` (echo + broadcast; an XSS sink in messages) | — | PRX |
| gRPC (M10b) | On the h2 listener :8443: a `vulnlab.Echo` service (`Say`, unary; `Stream`, server-streaming) with **server reflection** enabled and its `.proto` in `Fixtures/grpc/`; `vulnlab.Orders/Get` with a planted SQL injection in the `id` string field. On :8088: the same `Echo` service as **gRPC-Web** (binary and `-text`) and as a **Connect** unary endpoint | `vulnlab.SafeOrders/Get` (parameterized) | F33, SCN |
| Clickjacking | `/frameable` (no X-Frame-Options / frame-ancestors) | `/safe/frameable` | SCN passive (Frame Kit was cut 2026-11-08) |
| Prototype pollution (M11c) | `/pp/merge` (deep-merges a JSON body into a server-side object; a polluted `json spaces`-style property changes later response formatting) | `/safe/pp/merge` (rejects `__proto__`/`constructor`) | SCN-070 |
| Client-side path traversal (M11c) | `/cspt/` (a page whose JS builds `fetch('/api/items/' + location.hash.slice(1))` with credentials) | `/safe/cspt/` (encodes the segment) | SCN-071 |
| Mass assignment (M11c) | `/api/users/me` (`PATCH` JSON; accepts and persists an unexpected `role` property) | `/safe/api/users/me` (allowlists fields) | SCN-072 |
| File upload (M11c) | `/upload` (checks only the `Content-Type` header; serves stored files from `/uploads/` with an extension-derived type, so `x.svg`/`x.html` render same-origin) | `/safe/upload` (content sniffing + `Content-Disposition: attachment` + sandbox CSP) | SCN-073 |
| SPA | `/app/` (client-side routing, links rendered by JS) | — | CRL |

**Import fixtures (M6b).** `Tests/Fixtures/import/` holds files captured against VulnLab for the
import/export service (F20 PRJ-012/013, F23 ADV-050/051): a HAR, a Postman v2.1 collection, an XML
proxy-history export from the reference suite, a Caido export and a mitmproxy HAR. They are test data,
not VulnLab routes.

**M1 endpoint behaviors (so the M1 build isn't guessing).** `/echo` returns `200` with the request's
method, target, headers and body reflected as `text/plain` (and `Content-Length` set). `/echo-raw`
(raw TCP, :8089) writes the exact received bytes straight back and then **closes the connection**
(close-delimited), so a client reading to EOF gets a byte-identical copy — this is the byte-fidelity
oracle for HTTP-001 and the M1 DoD. `/redirect?to=` returns `302` with a `Location` of the `to`
value. `/chunked` responds `Transfer-Encoding: chunked` in several small chunks (e.g. 3 chunks) plus
a terminating zero-chunk (optionally a trailer, to exercise trailer parsing). `/gzip` sets
`Content-Encoding: gzip`; `/slow?ms=` delays before the body; `/large?mb=` streams N MB;
`/status/{code}` returns that status (used for the Governor-backoff test). A `/continue` endpoint
emits a `100 Continue` interim response before the final one, to exercise 1xx handling (recorded in
`ParsedResponse.interimResponses`, doc 04 §2). Fixture files for the parser round-trip/edit tests
live in `Tests/Fixtures/http/` and are authored as part of M1 (doc §2 lists the malformed cases).

**Determinism prerequisites.** For the accuracy test to be stable, VulnLab must make its planted
issues explicit rather than incidental:

- **Security-header/cookie baseline**: VulnLab sends a *correct* baseline (CSP, X-Content-Type-
  Options, cookie `HttpOnly`/`SameSite`, etc.) on **every** route by default, so a passive
  missing-header/weak-cookie issue fires **only** on the specific routes that deliberately omit it.
  Each such planted route is enumerated in a machine-readable fixture manifest
  (`Fixtures/vulnlab-issues.json`: route → expected issue type ids) that the test asserts against,
  instead of a vague "exactly the planted issues".
- **Plaintext-localhost checks**: HSTS-absent, `Secure`-cookie-absent, cleartext-password-submission
  and mixed-content can't be meaningfully tested on the HTTP `:8088` listener (they'd fire on every
  route including `/safe/*`). Exercise these only on the HTTPS `:8443` listener, which serves a
  vulnerable/`/safe/` pair for them; on the plaintext listener they are suppressed (or emitted at
  Info and excluded from the precision assertion).
- **OAST wiring**: the OAST-based P0 checks (SSRF, OS-command, XXE) only fire when a Beacon is
  configured (BCN-004 is off by default). The test run **must** start the dev Beacon (`make beacon
  --dev` equivalent, F10 BCN-024) and point the scan config at it; otherwise those three have no
  recall path.

**Scanner accuracy test** (`IntegrationTests/ScannerAccuracyTests`): with the dev Beacon running,
crawl and audit VulnLab with the "Thorough" configuration, then assert:

- recall: every P0 check finds its vulnerable endpoint (per the fixture manifest), including the
  three OAST checks via the dev Beacon;
- precision: no issue of severity ≥ Low is reported on `/safe/*` (plaintext-only passive checks are
  excluded per above);
- the results are written to `.build/scanner-accuracy.json` so changes are tracked over time.

### 3.1 Phase F fixtures (added with F25–F32, M21+)

The table above is the **v1** VulnLab (M0–M20). Each Phase F feature **extends VulnLab with its own
fixtures** — building that target is part of the feature's milestone, and the feature's own
Acceptance tests section is the authoritative list. VulnLab stays 127.0.0.1-only. The targets each
post-1.0 feature adds (every vulnerable route gets a `/safe/*` twin unless noted):

| Feature (milestone) | VulnLab fixtures to add |
|---|---|
| F25 SSO (M21) | An **OIDC** authorization server: `/oidc/authorize`, `/oidc/token`, `/oidc/userinfo`, `/.well-known/openid-configuration`, JWKS — a vulnerable instance (over-accepts `redirect_uri`, missing/static `state`, PKCE downgradable to `plain`, implicit-flow token leak via `Referer`) and a hardened twin. A **SAML** SP `/saml/acs` that accepts a signature-stripped/XSW assertion, with a signature-validating twin. |
| WebSocket checks, ex-F26 (M22: F07 §2.6, F08 §3.6, F23 WSX-004) | Reuses `/ws/chat`; adds a socket that authorizes **only at handshake** (+ per-message-authz twin), a socket that **upgrades on a cross-origin `Origin`** returning authenticated data (+ Origin-checking twin, for CSWSH), and a socket whose messages reach a **blind sink** (command/SSRF) that calls the dev Beacon, for OAST-correlated WS injection. |
| F27 JS Recon (M23) | A **minified JS bundle with an exposed `.map`**, `/api/internal/*` routes referenced only from JS (not linked), a bundled **known-vulnerable JS library** version, and a second **versioned capture** of the bundle (adds an endpoint) for the asset-diff test. |
| Cache family, ex-F28 (M24: F08 §3.5) | `/cache/reflect` that reflects **`X-Forwarded-Host`** into a cacheable response (+ non-caching twin) — and when that reflected header value is fetched server-side it reaches the dev Beacon, giving the cache-amplified **SSRF-into-cache** path (OAST-correlated); and an `/account` endpoint cacheable as **`/account.css`** (cache deception) with a `Cache-Control: private` twin. |
| Retest, ex-F30 (M25: F08 §2.4, F21 DRF-009) | No new routes required — reuses existing endpoints, plus a **config toggle** on one planted vuln so a fixture can flip vulnerable→patched between runs (for the Fixed/Still-Vulnerable verdict test). |
| F32 LLM (M26) | `/ai/chat` (SSE) vulnerable to **direct prompt injection** (+ guarded twin); a stored-note path the assistant later ingests for **indirect injection + OAST exfil**; an endpoint that renders model **Markdown into HTML** (XSS sink) with a sanitizing twin; and a remote **MCP server** at `/mcp` (HTTP transport) with an unauthenticated privileged tool and a **poisoned tool description** (+ an authenticated, clean twin) for LLM-009. |

(The merged Governor and Journal requirements — now F03 §3.4, F20 §2.4, F04 §2.3 and F14 — need no
new VulnLab fixtures; their acceptance tests drive Gulp's own tooling against existing endpoints.
F26, F28, F29, F30 and F31 were merged into other specs on 2026-11-08; the rows above name the new
homes.)

## 4. Third-party targets for manual testing (optional, Docker)

`Scripts/targets/docker-compose.yml` with OWASP Juice Shop and DVWA, bound to localhost only. These
are not part of automated tests.

## 5. Performance tests

| Test | Budget (doc 01 §9) |
|---|---|
| `ProxyThroughputTests` | ≥ 2,000 req/s, p50 added latency < 5 ms |
| `StoreInsertTests` | 1M exchange inserts (small bodies) in < 60 s; paged fetch of 200 rows < 10 ms |
| `GulpQLPerfTests` | Filter 1M rows < 2 s |
| `FuzzerThroughputTests` | ≥ 1,000 req/s (normal), ≥ 5,000 req/s (Turbo) |
| `ProjectOpenTests` | 1M-exchange project opens to first page < 3 s |

Fixture generator: `swift run gulp-cli dev generate-project --exchanges 1000000 --out big.gulp`.

## 6. UI smoke tests (XCUITest)

1. Launch → New Temporary Project → the sidebar shows every tool.
2. Start VulnLab, then drive traffic with `gulp-cli dev replay` through the proxy → history rows appear.
3. Select a row → ⌘R → the Repeater tab opens → ⌘↩ → a response appears.
4. Send to Fuzzer → mark a position → simple list → start → the results table fills.
5. Settings → Proxy → add a listener on port 8081 → the status shows it running.

Use accessibility identifiers (`gulp.history.table`, `gulp.repeater.send`, …) defined in a shared
`AccessibilityID` enum.
