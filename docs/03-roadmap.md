# 03 — Roadmap

Build the milestones **in order**. Each one ends with a usable, tested app. Requirement ID prefixes:

| Prefix | Spec | Prefix | Spec |
|---|---|---|---|
| PRX | F01 Proxy | SES | F15 Sessions |
| TLS | F02 TLS & CA | BRW | F16 Browser |
| HTTP | F03 HTTP engine | ETL | F17 (merged — its IDs now live in F06, F07, F19, F21, F27 and doc 05) |
| TGT | F04 Target & scope | EXT | F18 Extensions |
| HIS | F05 History/Logger/GulpQL | RPT | F19 Reporting |
| REP | F06 Repeater | PRJ | F20 Projects & settings |
| FUZ | F07 Fuzzer | AUT | F21 Automation |
| SCN | F08 Scanner | AI | F22 AI assistant |
| CRL | F09 Crawler | ADV | F23 Advanced tools |
| BCN | F10 Beacon | MAC | F24 macOS integration |
| SEQ | F11 Sequencer (post-1.0) | UI | doc 05 |
| DEC | F12 Decoder (incl. JWT Workbench) | CMP | F13 Comparer |
| NB | F14 Notebook | GRP | F33 gRPC & protobuf |

Post-1.0 expansion prefixes (Phase F): `SSO` (F25), `JSR` (F27 — its core is v1, M19a), `LLM`
(F32). The prefixes of the specs merged on 2026-11-08 keep working where the requirements now live:
`GOV` (F03 §3.4, F20 §2.4) and `JRN` (F04 §2.3, F14) are v1; `WSX` (F01, F07, F08, F15, F23), `WCP`
(F08 §3.5) and `DRF` (F08 §2.4, F21) are post-1.0. See `docs/07-decisions.md` product decision #7.

"All P0 of Fxx" means every requirement in that spec marked P0. P1 items are part of the milestone
unless the spec marks them "(later: Mxx)", "post-1.0" or "Cut". **Post-1.0** items are scheduled in
Phase F or listed in the Post-1.0 backlog at the end of this file; **cut** items are not built.

**Re-sequenced on 2026-11-08** (the feature review, `docs/FEATURE-REVIEW.md` §3, adopted by the owner):
milestone numbers were **not** renumbered, because hundreds of cross-references use them. Oversized
milestones were split with letter suffixes (as M3 was split into M3a/M3b): M4 → M4a/M4b, M6 →
M6a/M6b, M10 → M10a/M10b, M11 → M11a/M11b/M11c, M12 → M12a/M12b, M13 → M13a/M13b, M16 → M16a/M16b,
M19 → M19a/M19b. A bare "Mxx" in older text means the whole group (e.g. "M11" = M11a–M11c). M14
(Sequencer) is retired — F11 moved to the Post-1.0 backlog — and its number is not reused. A
**Daily-driver beta** release gate sits between M9 and M10a.

### Cross-milestone dependencies (why some requirements are deferred, not reordered)

A few requirements need a cross-cutting capability — **OAST/Beacon** (F10, M11a) or **Sessions**
(F15, M12a) — that a tool is built before. The build strategy is **layer the capability in when it
lands**, not reorder the milestones, because reordering only moves the conflict: Sessions (F15)
itself forward-depends on the Browser's CDP automation (F16, M13a) for login recording, so pulling
Sessions earlier would create a new forward dependency. So the tool is built first with a clean
**hook point**, and the dependent requirement is finished in the later milestone and marked
"(later: Mxx)" in its spec. The known cases are: FUZ-025 (M8 tool → OAST column in M11a), CRL-006
(M11a crawler → session re-auth in M12a), REP-006 (M5 Repeater's "in-scope" redirect option +
ScopeGuard gating → M6a when F04/scope lands; until then Repeater sends unconditionally), REP-008
(M5 Repeater → Transform Tags in M7), ADV-013 (M7 JWT Transform Tag → the Fuzzer payload processor
in M8), DEC-021 `beacon()` tag (M7 Decoder → wired in M11a when F10/Beacon lands), NB-005 (M9
Notebook↔issue link → M10a when F08 lands), NB-007 (M9 Notebook→report → M16a when F19 lands),
GRP-005 (M10b protobuf insertion points → Scanner in M11c), SES-030 (M12a Sessions → recorded login
in M13a). Each milestone's Definition of Done only checks what can work with the capabilities built
so far (e.g. M11b/M11c validate an **unauthenticated** audit; M12a validates the authenticated one),
and any acceptance test that exercises a deferred part (e.g. F07 test 4's OAST column) runs only in
the later milestone.

> **On spec "Depends on" headers.** Those headers list the features a spec is *conceptually* related
> to, not a strict acyclic module graph, so they can appear mutually (e.g. F01↔F05, F04↔F05). The
> authoritative, acyclic import graph is the module layering in doc 01 §3; resolve any apparent cycle
> at module granularity there (e.g. F05's history UI is M2 but its scope-aware filters are M9), not
> from the feature-header lists.

---

## Phase A — Foundation (M0–M3): "a proxy you can browse through"

### M0 — Scaffolding
- [ ] Create the repository layout from doc 01 §2 (empty modules with a placeholder type and test each).
- [ ] `Package.swift` with every target and the dependency graph from doc 01 §3. The manifest has **no** platform `#if`: the macOS-capability modules are ordinary targets whose AppKit/JavaScriptCore code is behind `#if canImport(...)` (empty shells on Linux), so the whole graph builds on both OSes (doc 01 §3 rule 4, ADR-010).
- [ ] `project.yml`, `App/GulpApp.swift` showing an empty `NavigationSplitView` window with the sidebar from doc 05 §2.
- [ ] Makefile, Brewfile, `.swift-format`, `.gitignore` (`.build/`, `*.xcodeproj`, `DerivedData`, `.DS_Store`).
- [ ] CI workflow (doc 02 §7).
- **DoD:** `make bootstrap generate build test lint` pass on macOS; `swift test` for GulpKit passes on Linux; the app launches and shows the empty sidebar.

### M1 — Core model and raw HTTP engine (HTTP/1.x)
- [x] GulpCore: `Bytes`, `RawRequest`/`RawResponse`, the raw-preserving HTTP/1 parser (doc 04 §2), `HTTPTarget`, `Exchange`, `ToolSource`, `EventBus`, `GulpError`.
- [x] GulpHTTP: HTTP/1.1 client that sends raw bytes over TCP/TLS, plus response framing (Content-Length, chunked, close-delimited, 1xx, HEAD/204/304), connection pool and timeouts (F03 HTTP-001…HTTP-010).
- [x] gulp-vulnlab: first endpoints (echo, redirect, chunked, gzip, slow, large; doc 06 §3).
- [x] Parser fuzz tests and round-trip property tests (doc 06 §2).
- *Done (CI run 42398666124, both platforms; DoD enforced by `Scripts/m1-dod.sh`). TLS is M3 per the DoD note; carry-overs: HTTP-007 brotli/zstd decoders, SOCKS5 credentials (see PROGRESS).*
- **DoD:** `gulp-cli send --raw request.txt --target http://127.0.0.1:8088/echo` prints the exact response bytes, and `--target http://127.0.0.1:8089/echo-raw` round-trips a malformed request byte-for-byte; all HTTP-0xx P0 tests pass. (HTTPS/`:8443` and TLS trust are **not** exercised until M3 — M1 is plaintext HTTP/1 only.)

### M2 — Plain-HTTP proxy, storage, history UI
- [x] GulpStore: schema v1 (doc 04 §4), migrations, write coalescer, paged queries.
- [x] Projects: new temporary project, new/open/save-as `*.gulp`, recent projects (F20 PRJ-001…PRJ-006).
- [x] GulpProxy: HTTP/1 forward proxy listener (non-CONNECT), absolute-form requests, keep-alive, recording (F01 PRX-001…PRX-004).
- [x] UI: Proxy → HTTP History table (NSTableView, paged), the message viewer (read-only Raw/Hex), a basic filter bar (F05 HIS-001…HIS-006), Settings → Proxy listeners.
- **DoD:** Browse `http://localhost:8088` through Gulp; 10k requests are recorded and scroll smoothly; quitting and reopening the project shows the same history.

### M3a — TLS interception and the certificate authority (HTTP/1.1) — DONE
Split from the original M3 after the 2026-11-07 feature review (docs/FEATURE-REVIEW.md): CA + CONNECT
+ MITM is one milestone, HTTP/2 the next, so each lands with a working DoD.
- [x] GulpTLS: CA generation and storage (Keychain on macOS, 0600 file elsewhere), leaf minting with SNI/SAN, an LRU cache, CA export in PEM/DER (F02 TLS-001…TLS-010, TLS-012).
- [x] GulpHTTP: upstream TLS (HTTPS targets) with chain capture and the would-be validation result (TLS-008), protocol settings (TLS-009).
- [x] GulpProxy: CONNECT handling, ClientHello sniff (SNI + ALPN), MITM with HTTP/1.1 offered to the client, TLS pass-through list, non-TLS tunnels as plain HTTP (F01 PRX-005…PRX-007). (ECH, TLS-017, is P1 and not done.)
- [x] macOS integration: "Install CA in login keychain" helper, uninstall, trust status, CA export (F24 MAC-001, MAC-002); Settings → TLS pane; MAC-004 instructions. (MAC-003 simulator install is P1 and not done.)
- **DoD:** Browse `https://example.com` and VulnLab's `https://localhost:8443` through Gulp with the CA trusted; the history shows the decrypted traffic.

### M3b — HTTP/2 (client side and upstream) — DONE
- [x] ALPN mirroring (PRX-008), HTTP/2 between client and proxy with one exchange per stream (PRX-009).
- [x] Upstream HTTP/2 in the engine: conversion, multiplexing, GOAWAY/RST/flow control, trailers (F03 HTTP-020…HTTP-024, HTTP-027).
- **DoD:** `curl --http2` through Gulp to an h2 site and to VulnLab's h2 endpoint; the history shows the decrypted traffic with HTTP/2 flagged, and gRPC-style trailers are kept.

## Phase B — Manual testing core (M4a–M9) → Daily-driver beta

### M4a — Message editor, Intercept, Match & Replace, Send to / Copy as — DONE
- [x] Shared `MessageEditor` component: Pretty/Raw/Hex tabs, header highlighting, search, invisibles, Inspector sidebar (doc 05 §4, UI-010…UI-014, UI-020). (Render tab, editable hex, UI-015/021/030 follow with the tools that need them — see PROGRESS carry-overs.)
- [x] Intercept: queue, forward/drop, edit, intercept rules, intercept responses (PRX-010…PRX-014, PRX-018). (P1 PRX-015/016/017-UI, P2 PRX-019 later.)
- [x] Match & Replace rules (PRX-020…PRX-022). (P1 PRX-023…025 later.)
- [x] The "Send to…" context-menu entry point with **Copy as** cURL/PowerShell/fetch/Python/Go (ETL-008); Send-to destinations arrive with their tools (M5+).
- **DoD:** Intercept a login POST, change a parameter, and forward it; a match-replace rule adds a header to every request; "Copy as cURL" on a history row reproduces the request against `/echo` (F01 test 7).

### M4b — Streaming responses, WebSockets, Gulp Browser launch — DONE
- [x] **Streaming responses** through the proxy with in-progress recording (PRX-050, F01 §4.3) and in-progress history rows with an SSE event view (HIS-007). (FEATURE-REVIEW A1; fixes the M2 "responses are buffered whole" carry-over.)
- [x] WebSockets: proxying, history, intercept and edit (PRX-030…PRX-034). (RFC 8441 WS-over-h2 not offered; PRX-035 with the Repeater in M5; PRX-036 P2 not scheduled — see PROGRESS carry-overs.)
- [x] **Gulp Browser launch** — the zero-setup capture path: discover/download Chromium, launch with the CA SPKI pin and proxy flags, one-click ⌘⇧O, cleanup on quit (BRW-001…BRW-004). CDP automation is M13a.
- **DoD:** `curl -N` through Gulp to VulnLab `/sse` receives every event as it is sent and the history row goes from "streaming" to complete (F01 test 8); WebSocket messages show up in WS history; one click launches Chromium proxied through Gulp with no certificate warning on `https://localhost:8443`, its traffic is recorded, and quitting Gulp closes it (F16 test 1).

### M5 — Repeater (and the advanced HTTP engine) — implemented; awaiting macOS CI (see PROGRESS)
- [ ] All P0/P1 of F06 (tabs, groups, history, follow redirects, connection options), including streamed responses in Repeater (REP-016) and **paste to request** from cURL/fetch/raw (REP-017).
- [ ] F03 HTTP/2 raw mode, the "update Content-Length" option, group send modes including single-packet attack (HTTP-030…HTTP-036).
- [ ] F03 remaining P1 engine features: HTTP/1 pipelining for Turbo mode, platform auth, and the shared global/per-host throttle (HTTP-011, HTTP-012, HTTP-013). The HTTP-013 limiter is extended with concurrency budgets and backoff in M11a (F03 §3.4, GOV-002/003/007).
- **DoD:** The VulnLab race-condition endpoint (doc 06 §3) can be exploited with a group send in single-packet mode; a pasted cURL command reproduces its request (F06 test 8); `/sse` streams in a Repeater tab (F06 test 7).

### M6a — Target: site map and scope — implemented; awaiting macOS CI (see PROGRESS)
- [ ] All P0/P1 of F04 §2.1–§2.2 (site map, scope, ScopeGuard).
- **DoD:** The site map tree fills from proxy traffic; scope rules hide out-of-scope items; ScopeGuard blocks out-of-scope Repeater sends (with a confirmation dialog).

### M6b — Import/export and the MCP read surface — implemented; awaiting macOS CI (see PROGRESS)
Pulled forward from M16/M17/M19 by the 2026-11-08 feature review: importing existing traffic and API
definitions, and letting an AI agent read the project and send a request, are daily-driver needs.
- [ ] The **import/export service** (PRJ-012) and its entry points: History export/import (HIS-044), Project → Import/merge (PRJ-008), site-map import (TGT-009), Postman/HAR import (ADV-051); **other-proxy history import** (PRJ-013).
- [ ] **API import**: OpenAPI/Swagger request building into the site map and schema-aware values (ADV-050, ADV-052). ("Scan the whole API" activates with the active scanner in M11c.)
- [ ] **MCP server, read surface + `send_request`**: the stdio transport (AUT-020), the tools `list_exchanges`, `get_exchange`, `send_request` and `get_scope` (AUT-021, first part), the site map and exchanges as resources (AUT-022, first part), and agent safety — ScopeGuard, approval mode, audit log (AUT-023). The remaining MCP tools arrive with their features and are completed in M17.
- **DoD:** Importing VulnLab's `/openapi.json` creates requests for every `/api/*` operation in the site map; a HAR export → import round-trips byte-for-byte (F20 test 6) and the other-proxy fixtures import (F20 test 7); Claude Code connected over MCP (stdio) lists history and sends a request, and an out-of-scope `send_request` is refused with a structured error and audit-logged.

### M7 — Decoder, Comparer and JWT Workbench — implemented; awaiting macOS CI (see PROGRESS)
- [ ] All P0/P1 of F12 (including Transform Tags in Repeater and the **JWT Workbench**, ADV-010…ADV-013, moved from F23) and F13.
- **DoD:** A Base64 → URL → Gzip chain decodes correctly; Smart Decode solves the fixture set; Comparer word-diffs two 1 MB responses in < 1 s; forged `alg:none` and RS→HS tokens are accepted by VulnLab `/api/me` and rejected by `/safe/api/me`, and a weak HMAC secret is brute-forced (F12 test 5).

### M8 — Fuzzer (with content discovery) — implemented; awaiting macOS CI (see PROGRESS)
- [ ] All P0/P1 of F07 §2.1–§2.5, including **content discovery** (ETL-003, moved from F17), except Turbo mode (optional, finish it last within this milestone) and except FUZ-025 (the OAST result column), which needs Beacon and is finished in M11a. (§2.6 WebSocket fuzzing is post-1.0, M22.)
- **DoD:** A Cartesian attack with 2 positions × 100 payloads runs at ≥ 1,000 req/s against VulnLab; grep-extract pulls the CSRF token from every response; "Discover content" finds VulnLab's hidden `/admin` and backup files (F07 test 6).

### M9 — Logger, GulpQL, search, Notebook, coverage index — implemented; awaiting macOS CI (see PROGRESS)
- [ ] GulpQL parser and evaluator, applied to History, Logger, site map and Fuzzer results (HIS-020…HIS-028).
- [ ] Logger tool showing every tool's traffic (HIS-040…HIS-045).
- [ ] Global search with FTS5 (HIS-050…HIS-054).
- [ ] Notebook (all P0/P1 of F14 except the timeline group JRN-003/005/008/009, which is M16b).
- [ ] **Coverage index (JRN-001, F04 §2.3, moved from F31)**: record per-endpoint tool coverage from `ToolSource` (Repeater/Fuzzer/Notebook sources exist now; Scanner columns populate at M10a/M11b). The coverage view (JRN-002) is M16b.
- **DoD:** `resp.status >= 500 and req.host ~ "api"` filters 1M rows in < 2 s (index-assisted where possible); the coverage index reflects which tools touched each endpoint.

### Release gate — Daily-driver beta (after M9)

Not a milestone with new features: a gate that M3b–M9 must pass before Phase C starts, so real users
get the manual-testing core months before the scanner. Scope of the beta: proxy (HTTP/1.1, HTTP/2,
TLS interception, streaming, WebSockets), Gulp Browser launch, intercept and Match & Replace,
Repeater (incl. race sends and paste-to-request), site map and scope, import (HAR/OpenAPI/Postman/
other proxies) and the MCP read surface, Decoder + JWT Workbench, Comparer, Fuzzer with content
discovery, Logger, GulpQL, search and Notebook.
- [ ] Every P0 of M3b–M9 is implemented and tested; `make test` and `make lint` pass; the core builds on Linux.
- [ ] A scripted end-to-end beta check (`Scripts/beta-dod.sh`, run in CI on macOS) against VulnLab passes: browse via the Gulp Browser, intercept and edit, Repeater single-packet race, Fuzzer content discovery, JWT forgery, import of `/openapi.json`, global search, and a Notebook entry — then quit and reopen the project with everything intact.
- [ ] The performance budgets of doc 01 §9 that apply to the shipped tools hold (history scrolling at 1M rows, proxy overhead, GulpQL, Comparer).
- [ ] No known data-loss bug: the PROGRESS carry-overs that can lose data (the app-terminate flush hook, exchange-id reuse after delete) are fixed; every other open carry-over is listed in the beta release notes.
- [ ] A Developer-ID-signed, notarized build (doc 02 §8 signing and notarization; Sparkle auto-update stays M20) installs on a clean macOS 14 machine. This needs the final bundle id and team (doc 07 product decision #1).
- **DoD:** The beta build is in the hands of a small group of real testers with a feedback channel, and the release notes list what is not there yet (scanner, crawler, sessions, extensions, reports, AI).

## Phase C — Automation (M10a–M13b)

### M10a — Passive scanner and the issue model — implemented; awaiting macOS CI (see PROGRESS)
- [ ] Issue model, issue UI (dashboard issue list, the issue detail with highlighted evidence), dedup (SCN-001…SCN-007).
- [ ] Passive checks catalog (F08 §3.1).
- [ ] Live passive scanning of proxy traffic as a background task.
- **DoD:** Browsing VulnLab produces the expected passive issues (fixture list in doc 06 §3) and no duplicates.

### M10b — gRPC and protobuf
- [x] All P0/P1 of F33 except the Scanner half of GRP-005 (later: M11c): RPC recognition and framing with trailers (GRP-001), schema-less decode (GRP-002), `.proto`/descriptor/reflection schemas (GRP-003), edit and re-send in Repeater (GRP-004), Fuzzer positions inside protobuf fields (GRP-005). (FEATURE-REVIEW A2; supersedes ADV-053.)
- **DoD:** A gRPC unary call to VulnLab's `vulnlab.Echo/Say` through the proxy decodes without a schema and shows `grpc-status` from the HTTP/2 trailers; reflection names the fields; an edited message re-sent from Repeater returns the edited echo; gRPC-Web text and Connect calls decode (F33 tests 1–3).
- *Implemented 2026-11-10 (local Linux gate; `Scripts/m10b-dod.sh` PASS, which also covers F33 test 4's Fuzzer half); the macOS views await CI. Carry-overs in PROGRESS.*

### M11a — Crawler (static), Beacon client, shared limiter and panic stop
- [x] Crawler, **static mode only**: the static-mode P0s CRL-001…CRL-010. The browser-backed P0s (CRL-030/031) are M13a. Build CRL-006's re-authentication **hook point** now; its session-rule/macro wiring is completed in M12a — until then the crawler runs unauthenticated.
- [x] Beacon **client** + interactsh client (all P0/P1 of F10 §2.1) and the local **dev Beacon** (BCN-024) for tests; wire the Fuzzer's OAST column (FUZ-025) and the `beacon()` Transform Tag (DEC-021). The deployable Beacon server (BCN-020…023, 025) is post-1.0.
- [x] **Shared limiter** (F03 §3.4: GOV-002, GOV-003, GOV-007 — HTTP-013 extended with concurrency budgets and adaptive backoff) and the **panic stop** (F20 GOV-001), built now because M11 ships the first active tools.
- **DoD:** A static crawl of VulnLab discovers every linked route within scope and none outside it; the dev-Beacon and interactsh loops correlate an interaction to its request (F10 tests 1, 3, 4); global/per-host caps bound aggregate throughput (F03 test 6) and backoff reacts to 503 bursts (F03 test 7); the panic stop halts a running crawl + fuzz with zero in-flight requests (F20 test 5).
- *Implemented 2026-11-11 (local Linux gate; `Scripts/m11a-dod.sh` PASS); the macOS views await CI. Carry-overs in PROGRESS (BCN-007's promote-to-issue, the status-bar health/throttled badges, crawl persistence across restarts).*

### M11b — Active scan engine and the P0 checks
- [x] Insertion points, active check engine, scan configurations, the scan task UI (SCN-020…SCN-038).
- [x] Every active check marked **[P0]** in F08 §3.2, with the §3.4 detection methodology.
- **DoD:** An active audit of VulnLab's vulnerable endpoints finds every P0 vulnerability planted there (including the three OAST checks via the dev Beacon), with zero false positives on the "safe twin" endpoints (doc 06 §3).
- *Implemented 2026-11-12 (local Linux gate; `Scripts/m11b-dod.sh` PASS: 32 routes, 20 expected issues, 0 missing, 0 unexpected); the macOS Scanner → Audit pane awaits CI.*

### M11c — Full check catalog and crawl-and-audit
- [ ] The remaining (P1) active checks of F08 §3.2 and the checks added by the 2026-11-08 review: server-side prototype pollution, client-side path traversal, mass assignment, upload bypasses and JWT checks (SCN-070…SCN-074).
- [x] "Crawl and audit" end-to-end (F09 + F08), "scan the whole API" for imported OpenAPI operations (ADV-050), and protobuf-field insertion points in the Scanner (GRP-005).
- *2026-11-12: the second item is implemented (`Scripts/m11c-dod.sh` PASS, incl. SCN-036/037/038); the first (the P1 check catalog, SCN-070…074) is deferred.*
- **DoD:** A "Crawl and audit" of VulnLab finds every planted vulnerability (the doc 06 §3 fixture manifest, including the M11c fixtures and the gRPC SQLi) with zero false positives on the safe twins — the scanner-accuracy test (doc 06 §3); a scan of the imported `/openapi.json` covers every operation.

### M12a — Sessions, authentication, macros, request signing
- [x] Cookie jar, identities, macros, session rules (scope + actions), validity check, request signing (DPoP, RFC 9421, AWS SigV4). SES-001/002/010…013/016…018/020…022; SES-003/014/015/040/041 and GulpQL rule scope deferred (see below).
- [x] Request signing runs as the engine's last hook; re-auth is single-flight under concurrency.
- **DoD:** A scan of VulnLab's authenticated area stays logged in by re-running the login macro when the session expires; Repeater sends to the `/signed/*` fixtures succeed with the matching signing action and fail without it (F15 test 5).
- *Implemented 2026-11-12 (`Scripts/m12a-dod.sh` PASS: each signing scheme verified by VulnLab's independent verifier, unsigned → 401; login-macro re-auth keeps /account at 200 across `/session/expire`). Deferred to a follow-up: jar import/export (SES-003), the rule tester (SES-014), per-rule Logger lines beyond the info log (SES-015), client certs per identity (SES-040), platform auth (SES-041), GulpQL rule-scope conditions (host/path/tool scope ships), and the macOS Sessions UI. Keys are passed in config rather than the Keychain yet. Recorded login + passkeys stay M13a.*

### M12b — Authz Matrix
Moved up from M19 by the 2026-11-08 feature review: access-control testing is the most-used
bug-bounty tool and only needs identities (M12a).
- [x] ADV-001…003 (replay as identities, verdict matrix, bypass heuristics raising issues). ADV-004 live mode, ADV-005 CSRF-per-identity (reuses M12a rules) and ADV-006 IDOR id-walking are P1/P2 carry-overs.
- **DoD:** Authz Matrix flags the VulnLab IDOR (`/api/orders/{id}`), with the `/safe/*` twin "Enforced" (F23 test 1).
- *Implemented 2026-11-12 (`Scripts/m12b-dod.sh` PASS: replaying `/api/orders/2` as a non-owner is "bypassed" and raises a broken-access-control issue; the enforcing `/safe/api/orders/2` twin is "Enforced"; the unauthenticated column is labelled public). The `/admin` self-granted-role bypass, ADV-004 live mode, ADV-006 id-walking and the macOS matrix UI are carry-overs.*

### M13a — Browser automation: CDP crawl, recorded logins, passkeys
- [ ] CDP connection and profile management (BRW-005…BRW-007) and the browser-backed crawl mode of F09 (CRL-030…CRL-036).
- [ ] Recorded login (SES-030) and **passkeys**: the CDP virtual authenticator (BRW-016) and passkey recorded logins (SES-032).
- **DoD:** The SPA in VulnLab is crawled through the browser and its client-side routes appear in the site map; a browser-recorded login replays to a valid session (F15 test 4); a passkey login to `/webauthn/login` is recorded and replayed with the virtual authenticator (F15 test 6, F16 test 5).

### M13b — DOM Probe and GraphQL Workbench
- [ ] DOM Probe (BRW-010…BRW-015; now P1) — needs the managed browser/CDP (M13a); deferred with the browser work.
- [x] **GraphQL Workbench** (ADV-040…043): endpoint detection, introspection + schema model + text render, query build/parse, variable insertion points, and the checks (introspection exposed, broken object/field authz). The browser schema view is the macOS half.
- **DoD:** DOM Probe finds the planted DOM XSS on `/spa` and nothing on `/safe/spa` (F16 test 2); the GraphQL Workbench introspects `/graphql`, renders the schema and flags the field-level authz bug (F23 test 5).
- *GraphQL implemented 2026-11-13 (`Scripts/m13b-graphql-dod.sh` PASS: introspect + render, introspection-enabled and broken-object-authz issues on `/graphql`, clean `/safe/graphql`). DOM Probe stays with M13a's browser automation (Chromium/CDP, macOS).*

### M14 — (retired)
Was the Sequencer (F11). The 2026-11-08 feature review moved F11 out of v1 (it rarely finds bugs
against modern frameworks and JWT-based sessions) — see the Post-1.0 backlog below. The number is not
reused, so older references stay unambiguous.

## Phase D — Platform (M15–M17)

### M15 — Extensions, scripting, Check Recipes
- [ ] All P0/P1 of F18 (JS host, JSON-RPC host, Snippets, the Python SDK — now P1). The Extension Gallery (EXT-020/021) is post-1.0; v1 installs from a file or folder.
- [ ] **Check Recipes** (YAML custom checks, SCN-060…SCN-064; moved out of M11 and to P1 by the 2026-11-08 review).
- **DoD:** The sample extensions in `SDK/examples` (header injector, custom passive check, custom tab) work in both runtimes; a YAML Check Recipe for a custom header leak detects it on VulnLab and renders the templated issue (F08 §7).

### M16a — Reporting
- [ ] All P0/P1 of F19, including the **bug-bounty Markdown** export (RPT-012, promoted to P1) and the **CSRF PoC generator** (ETL-007, moved from F17). PDF and branding (RPT-009, RPT-005) are P2.
- [ ] Notebook items in reports (NB-007).
- **DoD:** A self-contained HTML report of the VulnLab scan opens offline; a bug-bounty Markdown export reproduces a finding with its cURL line (F19 test 6); a CSRF PoC is generated for a VulnLab form (F19 test 5).

### M16b — Project polish, throughput panel, coverage view and timeline
- [ ] The remaining items of F20 (Project Info, Compact/Rebuild, auto-save reminder, settings reset/search, first run, diagnostics) and the open M2 carry-overs.
- [ ] Live **throughput panel** (GOV-006, F20 §2.4).
- [ ] **Coverage view** (JRN-002, F04 §2.3) and the **engagement timeline**, resume card, markers and report appendix (JRN-003, JRN-005, JRN-008, JRN-009, F14); the `v2_journal` migration (doc 04 §4).
- **DoD:** Compact reduces project size and Rebuild reconstructs the site map and FTS (F20 test 4); the throughput panel shows live req/s and the binding cap during a fuzz; the coverage view lists the untested in-scope endpoints (F04 test 5); the timeline and resume card reflect the last session (F14 test 4).

### M17 — Automation: CLI, REST API, full MCP server
- [ ] All P0/P1 of F21 — the CLI, the REST API, and the rest of the MCP tools and resources (on top of the M6b read surface) — plus the **task scheduler** (ETL-006, moved from F17). `gulp retest` (DRF-009) is post-1.0 (M25).
- **DoD:** `gulp scan --url http://localhost:8088 --config fast --report out.html` exits non-zero when it finds high-severity issues; Claude Code connected over MCP can start a scan, poll it and list its issues; a scheduled scan starts at its set time and notifies on completion (F21 test 5).

## Phase E — Differentiators and release (M18–M20)

### M18 — Gulp Assistant (AI)
- [ ] All P0/P1 of F22, including the **bounded agentic follow-up** "Investigate this endpoint" (AI-013). Payload crafting and report drafting (AI-007, AI-009) are P2.
- **DoD:** With AI disabled no provider call is possible; enabled (with consent), "Explain this issue" on a VulnLab finding returns a grounded answer citing the real exchange with the auth cookie masked in the redaction preview; an AI-initiated out-of-scope active action is blocked and audit-logged as `.ai`; "Investigate this endpoint" stops at its request budget and every active step waits for approval.

### M19a — Param Discovery, secret scanner, JS Recon core
- [x] *2026-11-13:* **Secret & JS-endpoint recon** (F27 first increment) shipped — passive `recon.secret` (vendor ruleset + high-entropy) and `recon.endpoint` (JS endpoint mining), off by default, `gulp-cli scan passive --recon`; `Scripts/recon-dod.sh` PASS. The rest of M19 (param discovery, full JS recon studio) remains.
- [ ] **Param Discovery** (F23 §3, ADV-020…ADV-022) and the **secret scanner** (F23 §7, ADV-060/061).
- [ ] **JS Recon Studio core** — the review's "trimmed, earlier" F27: asset inventory with the scripts/comments view, beautify, source-map recovery, endpoint extraction and hand-off to the site map/scanner (JSR-001…JSR-005, ETL-004). JSR-006…JSR-009 stay post-1.0 (M23).
- **DoD:** Param Discovery finds the hidden parameter planted in a VulnLab endpoint (F23 test 3); the secret scanner finds the planted key in a VulnLab JS file and reports it redacted (F23 test 7); JS Recon reconstructs the `src/` tree from the exposed `.map` and adds the JS-only `/api/internal/*` routes to the site map (F27 tests 1–2).

### M19b — Smuggling Probe
- [ ] All P0/P1 of F23 §4 (ADV-030…ADV-033).
- **DoD:** The Smuggling Probe classifies VulnLab's CL.TE emulation listener (:8090) as vulnerable via timing differentials and a correctly-behaving endpoint as safe (F23 test 4).

### M20 — macOS polish, packaging, release
- [ ] Remaining items of F24 (system proxy toggle, dock and notifications, Sparkle UI, iOS Simulator CA install; the menu bar extra, Services and App Intents are P2 since 2026-11-08).
- [ ] Sparkle, signing, notarization, DMG, release workflow (doc 02 §8) — signing and notarization already work since the beta gate.
- [ ] Accessibility audit (VoiceOver labels, keyboard navigation), localization-ready strings.
- [ ] Performance budget verification (doc 01 §9).
- **DoD:** A notarized DMG installs and auto-updates from a test appcast.

## Phase F — Post-1.0 expansion (M21+)

Added after the v1 spec review (ADR-013) and reshaped by the 2026-11-08 feature review (product
decision #7): F26, F28 and F30 were merged into the v1 specs they extend, but their requirements stay
post-1.0 and are scheduled here in their new homes. These build on the v1 engines. Schedule and
prioritize with the owner; the suggested order after 1.0 is **M21 (SSO) and M26 (LLM) first**, then
M22–M25.

### M21 — SSO Workbench
- [ ] All P0/P1 of F25. **DoD:** reconstructs a VulnLab OIDC auth-code flow and flags an over-accepted `redirect_uri`; a signature-stripped/XSW SAML assertion is accepted by the vulnerable SP and rejected by the safe twin.

### M22 — WebSocket fuzzing and checks (merged from F26)
- [ ] WS Fuzzer and OAST over WS (F07 §2.6: WSX-002, WSX-005, WSX-007), CSWSH (F08 §3.6: WSX-003), per-message authorization in the Authz Matrix (F23 §1: WSX-004), sub-protocol decoding (F01 §2.4: WSX-006) and scripted WS sequences (F15: WSX-008). **DoD:** a 2-position WS fuzz with an extract rule works against VulnLab `/ws/chat`; a cross-origin handshake is flagged CSWSH; a replayed privileged message under a stripped session is caught.

### M23 — JS Recon Studio (rest)
- [ ] The F27 requirements not built in M19a (JSR-006…JSR-009). **DoD:** library fingerprinting flags the bundled known-vulnerable library version and the asset diff surfaces a new endpoint between two VulnLab captures (F27 tests 3–4).

### M24 — Web cache poisoning & deception check family (merged from F28)
- [ ] All P0/P1 of F08 §3.5 (WCP-001…WCP-008). **DoD:** confirms an `X-Forwarded-Host` poisoning vector victim-safely and a `/account.css` deception; safe twins clean.

### M25 — Issue retest (merged from F30)
- [ ] F08 §2.4 (DRF-003…DRF-005) and `gulp retest` (F21 DRF-009); the `v3_drift` migration with `issue_proofs`/`retest_runs` only. **DoD:** an issue proof re-run flips Still-Vulnerable→Fixed after a patch; `gulp retest --fail-on regression` exits non-zero on a regression.

### M26 — LLM/AI-feature security testing
- [ ] All P0/P1 of F32, including AI-agent/MCP endpoint testing (LLM-009). **DoD:** a VulnLab chat endpoint is flagged for direct prompt injection and for indirect injection with an OAST-correlated exfil; the guarded twins are clean; the poisoned tool description on VulnLab's `/mcp` server is reported.

### Post-1.0 backlog (specified, not scheduled)

Specified requirements that the 2026-11-08 feature review moved out of v1 without a milestone yet.
Schedule them here (as a new Phase F milestone) when the owner decides; nothing below is built
before 1.0.

| Item | Requirements | Why it waits | DoD when scheduled |
|---|---|---|---|
| Sequencer (F11) | SEQ-001…SEQ-010 | Rarely finds bugs against modern frameworks and JWT sessions; a whole milestone | The VulnLab weak-token endpoint is rated "poor" and the strong-token endpoint "excellent" |
| Deployable Beacon server (F10 §2.2) | BCN-020…BCN-023, BCN-025 | interactsh support (BCN-005) covers v1 users | A Gulp client correlates DNS + HTTPS interactions through a self-hosted `gulp-beacon` on a real domain |
| Extension Gallery (F18 §3.3) | EXT-020, EXT-021 | No extension community yet | An extension installs from the signed catalog after its permissions are shown |
| Per-app transparent proxy (F24) | MAC-011 (the post-1.0 P1 part) | Needs a Network Extension and its entitlement | An app that ignores the system proxy is captured |
| HTTP/3 client (F03 §3.5) | HTTP-037 | Interception stays a non-goal; this is a Repeater-only extra | A Repeater send over `h3` to an HTTP/3 server succeeds and `Alt-Svc: h3` is flagged in history |

Further, not-yet-specified candidates (CSP Auditor, Deserialization, Arsenal, Share Packs, Privacy
Guard, Interop Hub, Perspectives, Dojo, Access Pack, target TLS scanner) are listed in
`docs/README.md`; promote each to a full `Fxx` spec and a milestone here when scheduled.
