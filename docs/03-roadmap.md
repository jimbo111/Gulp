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

Post-1.0 expansion prefixes (M21+, see Phase F): `SSO` (F25), `WSX` (F26), `JSR` (F27), `WCP` (F28),
`GOV` (F29), `DRF` (F30), `JRN` (F31), `LLM` (F32).

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
in M12), REP-006 (M5 Repeater's "in-scope" redirect option + ScopeGuard gating → M6 when F04/scope
lands; until then Repeater sends unconditionally), REP-008 (M5 Repeater → Transform Tags in M7),
DEC-021 `beacon()` tag (M7 Decoder → wired in M11 when F10/Beacon lands), NB-005 (M9 Notebook↔issue
link → M10 when F08 lands), NB-007 (M9 Notebook→report → M16 when F19 lands), ETL-004 (M16 →
secret-scanner link in M19), SES-030 (M12 Sessions → recorded login in M13). Each milestone's
Definition of Done only checks what can work with the capabilities built so far (e.g. M11 validates
an **unauthenticated** crawl+audit; M12 validates the authenticated one), and any acceptance test
that exercises a deferred part (e.g. F07 test 4's OAST column) runs only in the later milestone.

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

### M3a — TLS interception and the certificate authority (HTTP/1.1)
Split from the original M3 after the 2026-11-07 feature review (docs/FEATURE-REVIEW.md): CA + CONNECT
+ MITM is one milestone, HTTP/2 the next, so each lands with a working DoD.
- [x] GulpTLS: CA generation and storage (Keychain on macOS, 0600 file elsewhere), leaf minting with SNI/SAN, an LRU cache, CA export in PEM/DER (F02 TLS-001…TLS-010, TLS-012).
- [ ] GulpHTTP: upstream TLS (HTTPS targets) with chain capture and the would-be validation result (TLS-008), protocol settings (TLS-009).
- [ ] GulpProxy: CONNECT handling, ClientHello sniff (SNI + ALPN), MITM with HTTP/1.1 offered to the client, TLS pass-through list, non-TLS tunnels as plain HTTP (F01 PRX-005…PRX-007; ECH per TLS-017).
- [ ] macOS integration: "Install CA in login keychain" helper, uninstall, trust status, CA export (F24 MAC-001, MAC-002); Settings → TLS pane. (MAC-003/004 are P1.)
- **DoD:** Browse `https://example.com` and VulnLab's `https://localhost:8443` through Gulp with the CA trusted; the history shows the decrypted traffic.

### M3b — HTTP/2 (client side and upstream)
- [ ] ALPN mirroring (PRX-008), HTTP/2 between client and proxy with one exchange per stream (PRX-009).
- [ ] Upstream HTTP/2 in the engine: conversion, multiplexing, GOAWAY/RST/flow control, trailers (F03 HTTP-020…HTTP-024, HTTP-027).
- **DoD:** `curl --http2` through Gulp to an h2 site and to VulnLab's h2 endpoint; the history shows the decrypted traffic with HTTP/2 flagged, and gRPC-style trailers are kept.

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
- [ ] F03 remaining P1 engine features: HTTP/1 pipelining for Turbo mode, platform auth, and the shared global/per-host throttle (HTTP-011, HTTP-012, HTTP-013). The HTTP-013 limiter is the one the Governor later consolidates (F29, M11).
- **DoD:** The VulnLab race-condition endpoint (doc 06 §3) can be exploited with a group send in single-packet mode.

### M6 — Target: site map and scope
- [ ] All P0/P1 of F04.
- **DoD:** The site map tree fills from proxy traffic; scope rules hide out-of-scope items; ScopeGuard blocks out-of-scope Repeater sends (with a confirmation dialog).

### M7 — Decoder and Comparer
- [ ] All P0/P1 of F12 (including Transform Tags in Repeater) and F13.
- **DoD:** A Base64 → URL → Gzip chain decodes correctly; Smart Decode solves the fixture set; Comparer word-diffs two 1 MB responses in < 1 s.

### M8 — Fuzzer
- [ ] All P0/P1 of F07 except Turbo mode (optional, finish it last within this milestone) and
  except FUZ-025 (the OAST result column), which needs Beacon and is finished in M11.
- **DoD:** A Cartesian attack with 2 positions × 100 payloads runs at ≥ 1,000 req/s against VulnLab; grep-extract pulls the CSRF token from every response.

### M9 — Logger, GulpQL, search, Notebook
- [ ] GulpQL parser and evaluator, applied to History, Logger, site map and Fuzzer results (HIS-020…HIS-028).
- [ ] Logger tool showing every tool's traffic (HIS-040…HIS-045).
- [ ] Global search with FTS5 (HIS-050…HIS-054).
- [ ] Notebook (all P0/P1 of F14).
- [ ] **F31 Journal — coverage index (JRN-001)**: record per-endpoint tool coverage from `ToolSource`
  (Repeater/Fuzzer/Notebook sources exist now; Scanner columns populate at M10/M11). The full
  coverage/timeline/map tool is M16. (Phase F fold-in.)
- **DoD:** `resp.status >= 500 and req.host ~ "api"` filters 1M rows in < 2 s (index-assisted where possible); the coverage index reflects which tools touched each endpoint.

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
- [ ] **F29 Governor — shared limiter + panic stop (GOV-001/002/003/007)**: the global + per-host
  rate/concurrency limiter (consolidating F03 HTTP-013) and the one-key panic stop that halts all
  active tools, built now because M11 ships the first active tools (Scanner/Crawler/Beacon). The full
  Governor panel/quiet-hours/watchpoints are M16. (Phase F fold-in.)
- **DoD:** A "Crawl and audit" of VulnLab finds every P0 vulnerability planted there, with zero false positives on the "safe twin" endpoints (doc 06 §3); the panic stop halts a running crawl+audit with zero in-flight requests, and global/per-host caps bound aggregate throughput.

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
- [ ] **F29 Governor — full control surface**: the live throughput panel (GOV-006), resource
  watchpoints (GOV-004), quiet hours (GOV-005), dry-run preview (GOV-008) and layered-settings caps
  (GOV-009), on top of the M11 limiter/panic-stop. (Phase F fold-in.)
- [ ] **F31 Journal — full tool**: the coverage view, activity timeline, attack-surface map and
  "resume where I left off" (JRN-002…JRN-009), on top of the M9 coverage index. (Phase F fold-in.)
- **DoD:** A self-contained HTML report of the VulnLab scan opens offline; a CSRF PoC is generated for a VulnLab form; the Governor panel shows live throughput and the Journal shows per-endpoint coverage.

### M17 — Automation: CLI, REST API, MCP server
- [ ] All P0/P1 of F21.
- **DoD:** `gulp scan --url http://localhost:8088 --config fast --report out.html` exits non-zero when it finds high-severity issues; Claude Code connected over MCP can list history and send a Repeater request.

## Phase E — Differentiators and release (M18–M20)

### M18 — Gulp Assistant (AI)
- [ ] All P0/P1 of F22.
- **DoD:** With AI disabled no provider call is possible; enabled (with consent), "Explain this issue" on a VulnLab finding returns a grounded answer citing the real exchange with the auth cookie masked in the redaction preview; an AI-initiated out-of-scope active action is blocked and audit-logged as `.ai`.

### M19 — Advanced testing tools
- [ ] All P0/P1 of F23 (Authz Matrix, JWT Workbench, Param Discovery, Smuggling Probe, GraphQL Workbench, API import, secret scanner).
- **DoD:** Authz Matrix flags the VulnLab IDOR (`/api/orders/{id}`) and `/admin` bypass with `/safe/*` twins "Enforced"; JWT `alg:none` and RS→HS confusion are accepted/rejected correctly; the GraphQL introspection + field-authz bug is found; importing `/openapi.json` creates requests for every `/api/*` operation; the secret scanner finds the planted key.

### M20 — macOS polish, packaging, release
- [ ] Remaining items of F24 (system proxy toggle, menu bar extra, Shortcuts/App Intents, Quick Look).
- [ ] Sparkle, signing, notarization, DMG, release workflow (doc 02 §8).
- [ ] Accessibility audit (VoiceOver labels, keyboard navigation), localization-ready strings.
- [ ] Performance budget verification (doc 01 §9).
- **DoD:** A notarized DMG installs and auto-updates from a test appcast.

## Phase F — Post-1.0 expansion (M21+)

Added after the v1 spec review (ADR-013). These build on the v1 engines; each spec notes where parts
could be pulled earlier. Schedule/prioritize with the owner — the order below is the suggested value
ranking, not a hard sequence. **Two have P0 parts that belong earlier and should be built then:**
F29 Governor's shared limiter + panic stop in **M11** (when the first active tools ship) with the
full panel in M16, and F31 Journal's coverage index in **M9** with the full tool in M16.

### M21 — SSO Workbench
- [ ] All P0/P1 of F25. **DoD:** reconstructs a VulnLab OIDC auth-code flow and flags an over-accepted `redirect_uri`; a signature-stripped/XSW SAML assertion is accepted by the vulnerable SP and rejected by the safe twin.

### M22 — WebSocket Security Workbench
- [ ] All P0/P1 of F26. **DoD:** WS Repeater + Fuzzer work against VulnLab `/ws/chat`; a cross-origin handshake is flagged CSWSH; a replayed privileged message under a stripped session is caught.

### M23 — JS Recon Studio
- [ ] All P0/P1 of F27. **DoD:** reconstructs a source tree from an exposed `.map`, mines `/api/internal/*` endpoints not found by crawling, and feeds them to a scan.

### M24 — Web Cache Poisoning & Deception
- [ ] All P0/P1 of F28. **DoD:** confirms an `X-Forwarded-Host` poisoning vector victim-safely and a `/account.css` deception; safe twins clean.

### M25 — Drift & Retest
- [ ] All P0/P1 of F30. **DoD:** an issue proof re-run flips Still-Vulnerable→Fixed after a patch; `gulp retest --fail-on regression` exits non-zero on a regression.

### M26 — LLM/AI-feature security testing
- [ ] All P0/P1 of F32. **DoD:** a VulnLab chat endpoint is flagged for direct prompt injection and for indirect injection with an OAST-correlated exfil; the guarded twins are clean.

### (Folded into earlier milestones)
- **F29 Governor** — shared limiter + panic stop in **M11**, live panel/quiet-hours in **M16**.
- **F31 Journal** — coverage index in **M9**, full coverage/timeline/map tool in **M16**.

Backlog features (CSP Auditor, Deserialization, gRPC, Arsenal, Share Packs, Privacy Guard, Interop
Hub, Perspectives, Dojo, Access Pack, target TLS scanner) are listed in `docs/README.md`; promote
each to a full `Fxx` spec and a milestone here when scheduled.
