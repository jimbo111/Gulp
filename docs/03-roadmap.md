# 03 — Roadmap

Build the milestones **in order**. Each one ends with a usable, tested app. Requirement ID prefixes:

| Prefix | Spec | Prefix | Spec |
|---|---|---|---|
| PRX | F01 Proxy | SES | F15 Sessions |
| TLS | F02 TLS & CA | BRW | F16 Browser |
| HTTP | F03 HTTP engine | ETL | F17 Engagement tools |
| TGT | F04 Target & scope | EXT | F18 Extensions |
| HIS | F05 History/Logger/GulpQL | RPT | F19 Reporting |
| REP | F06 Repeater | PRJ | F20 Projects & settings |
| FUZ | F07 Fuzzer | AUT | F21 Automation |
| SCN | F08 Scanner | AI | F22 AI assistant |
| CRL | F09 Crawler | ADV | F23 Advanced tools |
| BCN | F10 Beacon | MAC | F24 macOS integration |
| SEQ | F11 Sequencer | UI | doc 05 |
| DEC | F12 Decoder | CMP | F13 Comparer |
| NB | F14 Notebook | | |

"All P0 of Fxx" means every requirement in that spec marked P0. P1 items are part of the milestone
unless the spec marks them "(later: Mxx)".

### Cross-milestone dependencies (why some requirements are deferred, not reordered)

A few requirements need a cross-cutting capability — **OAST/Beacon** (F10, M11) or **Sessions**
(F15, M12) — that a tool is built before. The build strategy is **layer the capability in when it
lands**, not reorder the milestones, because reordering only moves the conflict: Sessions (F15)
itself forward-depends on the Browser (F16, M13) for login recording, so pulling Sessions earlier
would create a new forward dependency. So the tool is built first with a clean **hook point**, and
the dependent requirement is finished in the later milestone and marked "(later: Mxx)" in its spec.
The known cases are: FUZ-025 (M8 tool → OAST column in M11), CRL-006 (M11 crawler → session re-auth
in M12), REP-008 (M5 Repeater → Transform Tags in M7), SES-030 (M12 Sessions → recorded login in
M13). Each milestone's Definition of Done only checks what can work with the capabilities built so
far (e.g. M11 validates an **unauthenticated** crawl+audit; M12 validates the authenticated one).

---

## Phase A — Foundation (M0–M3): "a proxy you can browse through"

### M0 — Scaffolding
- [ ] Create the repository layout from doc 01 §2 (empty modules with a placeholder type and test each).
- [ ] `Package.swift` with every target and the dependency graph from doc 01 §3, including the macOS-only conditions.
- [ ] `project.yml`, `App/GulpApp.swift` showing an empty `NavigationSplitView` window with the sidebar from doc 05 §2.
- [ ] Makefile, Brewfile, `.swift-format`, `.gitignore` (`.build/`, `*.xcodeproj`, `DerivedData`, `.DS_Store`).
- [ ] CI workflow (doc 02 §7).
- **DoD:** `make bootstrap generate build test lint` pass on macOS; `swift test` for GulpKit passes on Linux; the app launches and shows the empty sidebar.

### M1 — Core model and raw HTTP engine (HTTP/1.x)
- [ ] GulpCore: `Bytes`, `RawRequest`/`RawResponse`, the raw-preserving HTTP/1 parser (doc 04 §2), `HTTPTarget`, `Exchange`, `ToolSource`, `EventBus`, `GulpError`.
- [ ] GulpHTTP: HTTP/1.1 client that sends raw bytes over TCP/TLS, plus response framing (Content-Length, chunked, close-delimited, 1xx, HEAD/204/304), connection pool and timeouts (F03 HTTP-001…HTTP-010).
- [ ] gulp-vulnlab: first endpoints (echo, redirect, chunked, gzip, slow, large; doc 06 §3).
- [ ] Parser fuzz tests and round-trip property tests (doc 06 §2).
- **DoD:** `gulp-cli send --raw request.txt --target https://localhost:8443` prints the exact response bytes; all HTTP-0xx P0 tests pass.

### M2 — Plain-HTTP proxy, storage, history UI
- [ ] GulpStore: schema v1 (doc 04 §4), migrations, write coalescer, paged queries.
- [ ] Projects: new temporary project, new/open/save-as `*.gulp`, recent projects (F20 PRJ-001…PRJ-006).
- [ ] GulpProxy: HTTP/1 forward proxy listener (non-CONNECT), absolute-form requests, keep-alive, recording (F01 PRX-001…PRX-004).
- [ ] UI: Proxy → HTTP History table (NSTableView, paged), the message viewer (read-only Raw/Hex), a basic filter bar (F05 HIS-001…HIS-006), Settings → Proxy listeners.
- **DoD:** Browse `http://localhost:8088` through Gulp; 10k requests are recorded and scroll smoothly; quitting and reopening the project shows the same history.

### M3 — TLS interception and the certificate authority
- [ ] GulpTLS: CA generation and storage in the Keychain, leaf minting with SNI/SAN, an LRU cache, CA export in PEM/DER (F02 TLS-001…TLS-010).
- [ ] GulpProxy: CONNECT handling, SNI sniffing, ALPN mirroring, TLS pass-through list, upstream TLS settings (F01 PRX-005…PRX-009).
- [ ] macOS integration: "Install CA in login keychain" helper, CA export, simulator install (F24 MAC-001…MAC-004).
- [ ] HTTP/2 on the client side of the proxy (browser ↔ Gulp) and upstream (F03 HTTP-020…HTTP-026).
- **DoD:** Browse `https://example.com` and an HTTP/2 site through Gulp with the CA trusted; the history shows the decrypted traffic, with HTTP/2 flagged.

## Phase B — Manual testing core (M4–M9)

### M4 — Intercept, Match & Replace, message editor, WebSockets
- [ ] Shared `MessageEditor` component: Pretty/Raw/Hex/Render tabs, syntax highlighting, search, Inspector sidebar (doc 05 §4, UI-010…UI-030).
- [ ] Intercept: queue, forward/drop, edit, intercept rules, intercept responses (PRX-010…PRX-018).
- [ ] Match & Replace rules (PRX-020…PRX-025).
- [ ] WebSockets: proxying, history, intercept and edit (PRX-030…PRX-036).
- [ ] The global "Send to…" context menu infrastructure (UI-040).
- **DoD:** Intercept a login POST, change a parameter, and forward it; a match-replace rule adds a header to every request; WebSocket messages show up in WS history.

### M5 — Repeater (and the advanced HTTP engine)
- [ ] All P0/P1 of F06 (tabs, groups, history, follow redirects, connection options).
- [ ] F03 HTTP/2 raw mode, the "update Content-Length" option, group send modes including single-packet attack (HTTP-030…HTTP-036).
- **DoD:** The VulnLab race-condition endpoint (doc 06 §3) can be exploited with a group send in single-packet mode.

### M6 — Target: site map and scope
- [ ] All P0/P1 of F04.
- **DoD:** The site map tree fills from proxy traffic; scope rules hide out-of-scope items; ScopeGuard blocks out-of-scope Repeater sends (with a confirmation dialog).

### M7 — Decoder and Comparer
- [ ] All P0/P1 of F12 (including Transform Tags in Repeater) and F13.
- **DoD:** A Base64 → URL → Gzip chain decodes correctly; Smart Decode solves the fixture set; Comparer word-diffs two 1 MB responses in < 1 s.

### M8 — Fuzzer
- [ ] All P0/P1 of F07 except Turbo mode (that is M8b, same milestone, but optional to finish last)
  and except FUZ-025 (the OAST result column), which needs Beacon and is finished in M11.
- **DoD:** A Cartesian attack with 2 positions × 100 payloads runs at ≥ 1,000 req/s against VulnLab; grep-extract pulls the CSRF token from every response.

### M9 — Logger, GulpQL, search, Notebook
- [ ] GulpQL parser and evaluator, applied to History, Logger, site map and Fuzzer results (HIS-020…HIS-028).
- [ ] Logger tool showing every tool's traffic (HIS-040…HIS-045).
- [ ] Global search with FTS5 (HIS-050…HIS-054).
- [ ] Notebook (all P0/P1 of F14).
- **DoD:** `resp.status >= 500 and req.host ~ "api"` filters 1M rows in < 2 s (it is index-assisted where possible).

## Phase C — Automation (M10–M14)

### M10 — Passive scanner and the issue model
- [ ] Issue model, issue UI (dashboard issue list, the issue detail with highlighted evidence), dedup (SCN-001…SCN-007).
- [ ] Passive checks catalog (F08 §3.1).
- [ ] Live passive scanning of proxy traffic as a background task.
- **DoD:** Browsing VulnLab produces the expected passive issues (fixture list in doc 06 §3) and no duplicates.

### M11 — Crawler, active scanner, Beacon
- [ ] Crawler, **static mode only**: the static-mode P0s CRL-001…CRL-010. The browser-backed P0s
  (CRL-030/031, which need the Browser) are M13 — do **not** build them here. Build CRL-006's
  re-authentication **hook point** now, but its session-rule/macro wiring is completed in M12 when
  F15 (Sessions) exists — until then the crawler runs unauthenticated. Unauthenticated crawl+audit
  is what this milestone's DoD checks; authenticated crawling is validated in M12.
- [ ] Insertion points, active check engine, scan configurations, the scan task UI (SCN-020…SCN-038).
- [ ] Active checks catalog (F08 §3.2), at least every check marked P0.
- [ ] Beacon client + interactsh client; Beacon server (Beacon package) (all P0 of F10).
- [ ] Check Recipes (YAML custom checks) (SCN-060…SCN-066).
- **DoD:** A "Crawl and audit" of VulnLab finds every P0 vulnerability planted there, with zero false positives on the "safe twin" endpoints (doc 06 §3).

### M12 — Sessions, authentication, macros
- [ ] All P0/P1 of F15.
- **DoD:** A scan of VulnLab's authenticated area stays logged in by re-running the login macro when the session expires.

### M13 — Gulp Browser, DOM Probe, Frame Kit
- [ ] All P0/P1 of F16, plus the CDP-backed crawl mode of F09 (CRL-030…CRL-036).
- **DoD:** One click launches a proxied Chromium with no certificate warnings; the SPA in VulnLab is crawled; DOM Probe finds the planted DOM XSS.

### M14 — Sequencer
- [ ] All P0/P1 of F11.
- **DoD:** The VulnLab weak-token endpoint is rated "poor" and the strong-token endpoint "excellent".

## Phase D — Platform (M15–M17)

### M15 — Extensions and scripting
- [ ] All P0/P1 of F18 (JS host, JSON-RPC host, Python SDK, Snippets, Extension Gallery stub).
- **DoD:** The sample extensions in `SDK/examples` (header injector, custom passive check, custom tab) work in both runtimes.

### M16 — Reporting, engagement tools, project polish
- [ ] All P0/P1 of F17, F19, and the remaining items of F20.
- **DoD:** A self-contained HTML report of the VulnLab scan opens offline; a CSRF PoC is generated for a VulnLab form.

### M17 — Automation: CLI, REST API, MCP server
- [ ] All P0/P1 of F21.
- **DoD:** `gulp scan --url http://localhost:8088 --config fast --report out.html` exits non-zero when it finds high-severity issues; Claude Code connected over MCP can list history and send a Repeater request.

## Phase E — Differentiators and release (M18–M20)

### M18 — Gulp Assistant (AI)
- [ ] All P0/P1 of F22.

### M19 — Advanced testing tools
- [ ] All P0/P1 of F23 (Authz Matrix, JWT Workbench, Param Discovery, Smuggling Probe, GraphQL Workbench, API import, secret scanner).

### M20 — macOS polish, packaging, release
- [ ] Remaining items of F24 (system proxy toggle, menu bar extra, Shortcuts/App Intents, Quick Look).
- [ ] Sparkle, signing, notarization, DMG, release workflow (doc 02 §8).
- [ ] Accessibility audit (VoiceOver labels, keyboard navigation), localization-ready strings.
- [ ] Performance budget verification (doc 01 §9).
- **DoD:** A notarized DMG installs and auto-updates from a test appcast.
