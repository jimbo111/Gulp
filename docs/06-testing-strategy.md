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

- `parse(bytes).serialize() == bytes` for every fixture in `Tests/Fixtures/http/` (including
  malformed ones: bare LF, duplicate headers, obs-fold, missing final CRLF, NUL bytes, 1 MB headers).
- Editing a header via `ParsedRequest` changes only that header's bytes.
- Codecs: `decode(encode(x)) == x` over random bytes, for every reversible codec.
- GulpQL: `parse(print(ast)) == ast`.

## 3. VulnLab — the reference vulnerable target (`gulp-vulnlab`)

VulnLab is a deliberately vulnerable web app that ships in the repo (Hummingbird executable target).
It's the fixture for manual checks, integration tests and scanner accuracy tests. **It must bind
only to 127.0.0.1** and prints a warning banner at startup.

Each vulnerable endpoint has a **safe twin** (the same shape, but correctly implemented) so that
tests can measure false positives.

| Area | Vulnerable endpoint(s) | Safe twin | Used by |
|---|---|---|---|
| Basics | `/echo` (reflects the request as a readable response), **`/echo-raw`** (a raw TCP listener on :8089 that writes back the exact bytes it received, verbatim — used for byte-fidelity tests with malformed/duplicate headers and bare LF), `/redirect?to=`, `/chunked`, `/gzip`, `/slow?ms=`, `/large?mb=`, `/status/{code}`, `/h2` (HTTPS listener on :8443 with ALPN h2) | — | F01, F03 |
| Auth | `/login` (form + CSRF token), `/account` (session cookie), `/api/me` (Bearer JWT), session expires after N requests (configurable) | — | F15, F07 |
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
| Tokens | `/token/weak` (sequential/time-based), `/token/strong` (CSPRNG) | — | SEQ |
| GraphQL | `/graphql` (introspection on, a field-level authz bug) | — | ADV |
| OpenAPI | `/openapi.json` describing the `/api/*` routes | — | ADV, SCN |
| WebSockets | `/ws/chat` (echo + broadcast; an XSS sink in messages) | — | PRX |
| Clickjacking | `/frameable` (no X-Frame-Options / frame-ancestors) | `/safe/frameable` | BRW (Frame Kit) |
| SPA | `/app/` (client-side routing, links rendered by JS) | — | CRL |

**Scanner accuracy test** (`IntegrationTests/ScannerAccuracyTests`): crawl and audit VulnLab with the
"Thorough" configuration, then assert:

- recall: every P0 check finds its vulnerable endpoint;
- precision: no issue of severity ≥ Low is reported on `/safe/*`;
- the results are written to `.build/scanner-accuracy.json` so changes are tracked over time.

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
