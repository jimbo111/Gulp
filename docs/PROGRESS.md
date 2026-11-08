# Progress tracker

This is the live state of the build. Claude updates it as work lands: tick tasks in the current
milestone (keep the detail in `docs/03-roadmap.md`) and add a dated log line. Work milestones in
order; within a milestone, do P0 first.

## Current status

- **Phase**: **M3b DONE** — CI green on both platforms (run 42498773075, commit `11cd7d5`); the M3b
  DoD (`Scripts/m3b-dod.sh`, Linux CI) PASS: `curl --http2` trusting only the Gulp CA speaks HTTP/2
  to Gulp, Gulp speaks HTTP/2 to VulnLab `:8443` (its echo shows `GET /echo HTTP/2`), the `/chunked`
  trailer arrives as an h2 trailer, https://example.com works over h2, and the reopened project
  flags HTTP/2 and keeps the trailer. M0–M3a DoD scripts still pass in the same run.
- **Active milestone**: **M4a — Message editor, Intercept, Match & Replace, Send to / Copy as**
  (UI-010…030, PRX-010…025, UI-040, ETL-008), per the 2026-11-08 re-sequenced roadmap.
- **Branching**: `main` holds merged milestones (PRs jimbo111/Gulp#1 M0–M2, #2 review fixes,
  #3 M3a, then M3b + the feature-review adoption). Work happens on
  the session branch and is merged by PR once CI is green.
- **Build verification**: the authoring container has no Swift toolchain (`download.swift.org` is
  blocked), so CI (`.github/workflows/ci.yml`) is the gate and runs on **every branch push**:
  `core-linux` (`swift:6.0-noble`: build + all tests + the M1 and M2 DoD scripts) and `macos`
  (`make lint generate test-core build test`, incl. the app UI smoke tests).
- **Carry-overs** (tracked, not silently dropped):
  - M1: HTTP-007 brotli and zstd decoders (gzip/deflate ship; `br`/`zstd` throw `.unsupported`);
    SOCKS5 username/password (NIOSOCKS client is no-auth only). Redirect following is declared but
    `.never`-only until the Repeater (M5).
  - M2: PRJ-001 save/discard prompt on closing a temporary project (the file is kept in Caches
    instead; needs an NSWindow close hook, M16b polish). The proxy answers CONNECT with 501 until M3a
    and origin-form (invisible) requests with 400 until PRX-040.
  - M2, found by the 2026-11-07 code review (partial requirements, now stated honestly):
    - **F01 §4.3 response streaming**: responses are buffered whole (50 MB / 120 s limits), so large
      downloads and SSE/long-polling fail through the proxy. Now specified as PRX-050/HIS-007 (M4b,
      FEATURE-REVIEW A1). Request bodies are buffered too, capped at 256 MB (413 beyond).
    - HIS-004: "add to scope" (needs M6a) and "send to tools" (M5) are not there yet.
    - HIS-005: comments are edited in a dialog, not inline (UI-041 lands with the editor, M4a).
    - HIS-006: in-scope (M6a), MIME and method chips are missing from the UI (the query supports them).
    - PRJ-005: "Use settings from…" has an API but no UI; import from a settings file is missing.
    - PRJ-006 (P1): name/notes API only, no Project Info panel.
    - F20 §4: `settingsChanged` is declared but never published.
    - No app-terminate hook: on Cmd-Q the last ~50 ms of queued writes may be lost (window close is
      fine). Exchange ids can be reused after the newest rows are deleted and the project reopened.
- **M3a carry-overs**: TLS-017 ECH handling (P1); MAC-003 simulator install (P1); TLS-007 PKCS#12
  import (PEM import works); pass-through tunnels are not yet logged (PRX-007 "tunnel entry" needs
  the Logger, M9); `TLSInfo.cipherSuite` is empty (NIOSSL doesn't expose the negotiated suite);
  PRX-046 `http://gulp/cert.pem` landing page (P1) not yet served.
- **M3b carry-overs**: raw HTTP/2 from an `H2RequestSpec` (HTTP-025, P1) arrives with the Repeater
  (M5); HTTP-026 (P1) connection events in the Logger (M9); request trailers from h2 clients are
  ignored; ALPN pre-connect offers upstream `h2, http/1.1` rather than the client's exact list
  (decision log); a failed pre-connect still completes the client handshake (the request then gets
  a 502) instead of aborting it with a TLS alert.
- **Next action**: M4a — the shared MessageEditor (Pretty/Raw/Hex/Render, Inspector), Intercept
  (queue, forward/drop, rules), Match & Replace, the Send-to menu and Copy-as; executable DoD.
  The plan after M3b follows the 2026-11-08 re-sequencing (milestone checklist below).
- **Waiting on the owner**: nothing. The scope proposals in `docs/FEATURE-REVIEW.md` §3 were
  **adopted on 2026-11-08** (product decision #7 in `docs/07-decisions.md`) and applied to the specs:
  merges, cuts, deferrals, new requirements (incl. F33) and the re-sequenced roadmap with letter-
  suffixed splits and a daily-driver beta gate after M9.
- **Product decisions**: resolved by the owner and recorded in `docs/07-decisions.md` §"Product
  decisions" (MIT license; macOS 14 min; Claude-only AI in v1; OAST off until configured;
  `com.gulp.app` placeholder bundle id — to be replaced before the beta's signed build; no team
  server; #7 the feature review adopted). Build to those.

### Documentation Definition of Done (the objective "build-ready" bar)

"Nearly perfect" is subjective, so here is the **concrete, auditable standard** the doc set is held
to, with how each criterion is measured and its status. A criterion is MET only if its stated,
reproducible check passes. (Re-run the checks after any edit; scripts live in the session scratchpad
and are pure Python over the Markdown.)

| # | Criterion (objective) | How measured | Status |
|---|---|---|---|
| D1 | Every feature has a spec file with the standard sections (Purpose, Requirements, UI, Implementation, Edge cases, Acceptance tests) | 33 `docs/features/Fxx-*.md` since 2026-11-08 (27 active specs incl. the new F33, plus 6 merged stubs F17/F26/F28–F31 that keep the section headings); grouped specs (F23) noted in docs/README | MET (32/32) |
| D2 | Every requirement row has a stable ID + priority (P0/P1/P2) | ID-table scan | MET |
| D3 | No duplicate requirement IDs; no referenced-but-undefined IDs (incl. slash-shorthand) | `idcheck` | MET (544 IDs incl. the new `GRP` prefix, 0 dup, 0 dangling — re-run 2026-11-08; was 516) |
| D4 | Every internal Markdown link, `Fxx` ref, and `Mxx` ref resolves | `linkcheck` | MET |
| D5 | Every `## N`/`### N.M` numbering sequence has no gaps/dupes | `secnum` | MET |
| D6 | Every `Fxx §N` / `doc NN §N` cross-ref points to a real section | `secref` | MET |
| D7 | Each feature's milestone agrees across its header, the README index, and the roadmap | `featmap` (a suffix-aware copy since 2026-11-08) + `featmap2` (also checks roadmap sections and every suffixed `Mxx` ref) | MET (re-run 2026-11-08) |
| D8 | Every feature is scheduled in the roadmap with a Definition of Done | roadmap M0–M26 inspection | MET |
| D9 | Every acceptance test maps to a defined or milestone-scoped VulnLab fixture/endpoint | doc 06 §3 + §3.1; independently re-verified | MET |
| D10 | Every persisted requirement has a backing table/column; all FKs resolve | doc 04 §4 incl. Phase F tables; independently verified | MET |
| D11 | Module layering is acyclic; Linux-building modules don't depend on macOS-only ones; `Package.swift` matches doc 01 §3 | architecture + manifest cross-check | MET |
| D12 | Each milestone's tasks need only capabilities built by then; forward deps marked "(later: Mxx)" | roadmap deferral list + per-spec notes | MET |
| D13 | No contradictions across docs on load-bearing points | multi-panel independent review | MET (no Blockers/Majors) |
| D14 | Prose has no misspellings (code/URLs excluded) | aspell with a verified technical-terms dictionary | MET (0 unknown real words) |
| D15 | All Markdown tables are well-formed (any in-cell pipe escaped as backslash-pipe) | table-shape check | MET |
| D16 | Independent fresh-eyes review finds no Blocker/Major | 10 agent reviews incl. a final 2-reviewer panel + targeted re-verifications | MET |
| C1 | The Swift code compiles and tests pass | `swift build`/`swift test`, `xcodebuild` | **OUT OF SCOPE / ENVIRONMENT-IMPOSSIBLE (live-verified 2026-11-07)**: no toolchain installed; the apt `swift` package is OpenStack, not the language; and the toolchain host `download.swift.org` returns `403 CONNECT tunnel failed` through the sandbox proxy (toolchain tarball + swiftly both blocked; only `swift.org` allowlisted). This is a *code* gate enforced by CI (`.github/workflows/ci.yml`), not a Markdown property. |

D1–D16 are MET. C1 is not a documentation criterion and cannot be run here; it is the CI gate for the
code produced *from* these docs. By this objective standard the documentation is build-ready.

**Independently audited (2026-11-07).** A fresh auditor re-derived all 16 criteria from the files
(not trusting this status column) and returned **14/16 cleanly verified, FINAL JUDGMENT: BUILD-READY
(no Blocker, no Major)**. It correctly caught that D8 and D15 had been over-claimed: M18/M19 lacked a
`**DoD:**` line (D8), and the D15 row above itself had an unescaped in-cell pipe (D15). Both were
Minor and both are now fixed (DoD lines added to roadmap M18/M19; this row reworded), so D8 and D15
now genuinely hold. The independent judgment that the objective bar is met therefore stands with the
status column accurate.

### Documentation verification (as of the last review)

The specs were reviewed in several passes, including independent fresh-eyes agent reviews of the core
docs, F01–F12, F13–F24 and F25–F32. Every core doc (00–07) and all **32** feature specs have been
read end to end, and the following consistency checks all pass over the **whole** set (F01–F32) —
re-run them after any doc edit:

- **Requirement IDs**: **516** defined across the spec tables (incl. the Phase F prefixes
  SSO/WSX/JSR/WCP/GOV/DRF/JRN/LLM), no duplicates, and every `Fxx-NNN` reference resolves to a defined
  ID (including slash-shorthand like `MAC-010/011`).
- **Links**: every relative Markdown link resolves; every `Fxx` feature reference has a file; every
  `Mxx` milestone reference is defined in the roadmap.
- **Section numbering**: `## N.`/`### N.M` sequences have no gaps or duplicates in any doc.
- **Section cross-refs**: every `Fxx §N` / `doc NN §N` points to a section that exists.
- **Feature↔milestone**: each spec header, the roadmap body, and the README index agree.
- **Make targets**: every `make <target>` mentioned in the docs exists in the Makefile.
- **Tables**: all Markdown tables are well-formed (literal `|` in cells escaped as `\|`).
- **Spelling**: aspell over the prose (code/URLs stripped) shows only legitimate technical terms.

**Independent build-readiness verdict (2026-11-07).** Multiple fresh-eyes reviewers (no prior context)
checked the set, with "build-ready" defined as *no Blockers and no Majors (Minors acceptable)*. The
Majors they found were fixed and re-verified:
- F29/F31 fold-in P0 work was missing from the M9/M11/M16 task lists/DoDs and this tracker → wired in;
  an independent re-verification then confirmed each milestone carries both a task bullet and a DoD.
- A **final two-reviewer panel** over the whole set converged: the holistic reviewer returned
  BUILD-READY; the adversarial reviewer found v1 (M0–M20) clean and one Phase-F-only Major — the
  F25/F27/F28/F32 acceptance tests referenced VulnLab OIDC/SAML, source-map/`/api/internal`,
  cache-poisoning and LLM fixtures that doc 06 §3 didn't define → added doc 06 §3.1 "Phase F fixtures".
- Phase F schema Minors (new-endpoint identity, multi-step/identity proof columns, split migrations,
  blob-GC walk) and assorted cross-refs were cleared along the way.

With those fixed, both final reviewers' criterion — no Blockers, no Majors — is satisfied across
F01–F32. "Nearly perfect" is a subjective bar; this is the strongest objective evidence available
here (independent agreement + all automated consistency checks green).

What is **not** verified here: the Swift code compiles/tests (no toolchain in the authoring
container — CI is the gate, see the caveat above), and spec implementation-note API hints are
best-effort guidance, not proven against the libraries; the acceptance tests are the source of truth
for behavior.

## Milestone checklist (summary — details in docs/03-roadmap.md)

- [x] M0 — Scaffolding (repo layout, Package.swift, project.yml, Makefile, CI, empty app window) — **CI green both platforms (`6e17d38`)**
- [x] M1 — Core model + raw HTTP/1 engine — **CI green both platforms + executable DoD PASS (`cd84c2a`)**
- [x] M2 — Plain-HTTP proxy, storage, history UI — **CI green both platforms + executable DoD PASS (`1acf39c`)**
- [x] M3a — TLS interception + CA (HTTP/1.1) — **CI green both platforms + executable DoD PASS (`054b24a`)**
- [x] M3b — HTTP/2 (client side + upstream, trailers) — **CI green both platforms + executable DoD PASS (`11cd7d5`)**
- [ ] M4a — Message editor, Intercept, Match & Replace, Send to / Copy as
- [ ] M4b — Streaming responses, WebSockets, Gulp Browser launch
- [ ] M5 — Repeater + advanced HTTP engine (HTTP/2 raw, group/race sends, streaming, paste-to-request)
- [ ] M6a — Target: site map + scope + ScopeGuard
- [ ] M6b — Import/export service, API import, MCP read surface + `send_request`
- [ ] M7 — Decoder + Comparer + JWT Workbench
- [ ] M8 — Fuzzer (with content discovery)
- [ ] M9 — Logger, GulpQL, search, Notebook, coverage index
- [ ] **Daily-driver beta** — release gate after M9 (signed + notarized build to real testers)
- [ ] M10a — Passive scanner + issue model
- [ ] M10b — gRPC & protobuf (F33)
- [ ] M11a — Crawler (static), Beacon client + dev Beacon, shared limiter + panic stop
- [ ] M11b — Active scan engine + P0 checks
- [ ] M11c — Full check catalog (incl. SCN-070…074) + crawl-and-audit
- [ ] M12a — Sessions, auth, macros, request signing
- [ ] M12b — Authz Matrix
- [ ] M13a — Browser automation: CDP crawl, recorded logins, passkeys
- [ ] M13b — DOM Probe + GraphQL Workbench
- M14 — *(retired: Sequencer moved to the Post-1.0 backlog)*
- [ ] M15 — Extensions + scripting + Check Recipes
- [ ] M16a — Reporting (bug-bounty Markdown, CSRF PoC)
- [ ] M16b — Project polish, throughput panel, coverage view + timeline
- [ ] M17 — Automation: CLI, REST API, full MCP server, scheduler
- [ ] M18 — Gulp Assistant (AI) incl. bounded agentic follow-up
- [ ] M19a — Param Discovery, secret scanner, JS Recon core
- [ ] M19b — Smuggling Probe
- [ ] M20 — macOS polish, packaging, release
- [ ] M21 — F25 SSO Workbench *(Phase F, post-1.0; suggested first with M26)*
- [ ] M22 — WebSocket fuzzing and checks (WSX, merged from F26)
- [ ] M23 — F27 JS Recon Studio (rest)
- [ ] M24 — Cache poisoning & deception check family (WCP, merged from F28)
- [ ] M25 — Issue retest (DRF, merged from F30)
- [ ] M26 — F32 LLM/AI-feature security testing (incl. MCP/agent endpoints)
- Post-1.0 backlog (unscheduled): F11 Sequencer, deployable Beacon server, Extension Gallery, MAC-011 transparent proxy, HTTP-037 HTTP/3 client

## Log

- 2026-11-06 — Specs written: core docs (00–07) + all feature specs (F01–F24) + this tracker.
  Repository is spec-only; no source yet. Next action: M0 scaffolding.
- 2026-11-07 — Spec review pass: fixed layering (BrowserDriver injection, ADR-010), scope precedence
  (ADR-011), FTS trigram limits, GulpQuery storage-agnosticism, Beacon privileged ports, single-packet
  wording. (Commit `35fee56`.)
- 2026-11-07 — **M0 scaffolding written** (unverified locally — see caveat above):
  - `Packages/GulpKit/Package.swift` with all 26 module targets + 25 test targets, the full
    dependency graph, external packages (NIO/SSL/HTTP2/Extras, certificates, crypto, GRDB,
    Hummingbird, ArgumentParser, Collections, Logging) and Swift 6 language mode. Each module has a
    documented placeholder type and a passing scaffolding test.
  - macOS modules (`GulpBrowser`/`GulpScript`/`GulpUI`/`GulpFeatures`) are defined on all platforms as
    empty shells (implementation choice refining ADR-010; doc 02 §5 updated to match — **doc changed,
    not code**).
  - App shell: `App/GulpApp.swift` + `Tool.swift` (empty `NavigationSplitView` with the doc 05 §2
    sidebar), `AppDelegate`, `Info.plist` (`.gulp` document type), entitlements (no sandbox, hardened
    runtime), asset catalog.
  - `project.yml` (XcodeGen; app + `GulpAppUITests`, Sparkle, embeds `gulp-cli`), `Makefile`,
    `Brewfile`, `.swift-format`, `.github/workflows/ci.yml` (Linux core + macOS jobs).
  - `Beacon/` package (separate, Linux/Docker) with placeholder `gulp-beacon` + `Dockerfile`.
  - Also corrected a spec error found while scaffolding: `SNIHandler` is in the `NIOTLS` module of
    swift-nio (a later review corrected an interim "NIOSSL" note; doc 01 §1 and F02 §4 are authoritative).
- 2026-11-07 — **M1 started — GulpCore byte-fidelity foundation** (unverified locally; CI is the gate):
  - `Bytes.swift` — the canonical value-semantic byte buffer (`RandomAccessCollection`, cheap slicing,
    strict vs lossy UTF-8), Foundation-free per the GulpCore dependency rule.
  - `HTTP1.swift` — the raw-preserving HTTP/1 parser + response framer: frames the start line and
    headers as byte ranges (order and duplicates preserved), never normalizes, and emits warnings
    (bare LF, obs-fold, duplicate/conflicting framing) instead of rejecting. `serialize()` is the
    identity over the input bytes (HTTP-001). Framing detection + chunk decoding + incompleteness
    (HTTP-002).
  - `Tests/GulpCoreTests` — real round-trip, edit-splice, and framing tests, each named for its
    requirement ID (replaces the scaffolding marker test).
  - **Doc reconciled to code** (CLAUDE.md §4): doc 04 §2 `ParsedRequest`/`ParsedResponse`/`HeaderField`
    marked `Hashable` (their `RawRequest`/`RawResponse` already were, which requires it).
- 2026-11-07 — **CI GREEN on both platforms** (commit `6e17d38`): M0's build gate is finally
  satisfied, and the M1 GulpCore foundation compiles and its tests pass. Reaching green meant fixing
  four real defects that only running CI could surface (none visible to the Markdown checkers or a
  no-toolchain container):
  - **GRDB/SQLite link (Linux):** GRDB 7 references `sqlite3_snapshot_*`, absent from Ubuntu's
    `libsqlite3`. `core-linux` now builds SQLite with `SQLITE_ENABLE_SNAPSHOT`+FTS5 and links it.
  - **Lint (`swift format --strict`):** never actually satisfied — fixed the new source, both
    `Package.swift` manifests (applied the toolchain's own canonical output), and the test file;
    disabled only `AlwaysUseLowerCamelCase` (ADR) to keep the spec's `http1_0`/byte-constant names.
  - **`GulpAppUITests` Info.plist:** the UI-test target couldn't code-sign; set
    `GENERATE_INFOPLIST_FILE` in `project.yml`.
  - **Swift 6 concurrency:** XCUITest APIs are `@MainActor`; annotated the test class.
  Verified via `workflow_dispatch` runs on the branch (CI triggers on push-to-main/PR/dispatch).
- 2026-11-07 — **M1 DONE** (CI run 42398666124, `cd84c2a`; DoD `Scripts/m1-dod.sh`: PASS):
  - GulpCore: full doc 04 §2 model (`HTTPTarget`, `Exchange` + supporting types, `ToolSource`
    TEXT encoding, `GulpNetworkError`/`GulpError`), the `EventBus` actor (lag markers on `Delivery`),
    exact resumable chunk scanner, HEAD/interim-aware `RawResponse`, `H2RequestSpec`.
  - GulpHTTP: `NIOHTTPEngine` — raw-byte writes, full HTTP/1 framing, pool, DNS overrides, typed
    timeouts, opt-in Content-Length/line-ending rewrites, cancellation, timing, hooks, recorder,
    group sends, upstream HTTP/CONNECT/SOCKS5 proxies + rules, gzip/deflate helpers.
  - gulp-vulnlab (raw-NIO fixtures :8088 + verbatim echo :8089) and `gulp-cli send --raw`.
  - Tests: 80 (fixture corpus, seeded fuzz, every HTTP-0xx requirement against an in-process
    server, scripted proxies incl. SOCKS5).
  - Real bugs CI caught along the way: `TCP_NODELAY` set at `SOL_SOCKET` (= `SO_DEBUG`; EACCES on
    Linux, silently wrong on macOS); negative TTFB from stamping write completion off-loop;
    ArgumentParser's sync entry point refusing an async command; NIO's async `writeAndFlush`
    overload shadowing the future-returning one. Plus, from fuzz-test design: chunk-size overflow
    and the `0`-line chunk heuristic.

- 2026-11-07 — **M2 DONE** (CI run 42416523505, `1acf39c`; DoD `Scripts/m2-dod.sh`: PASS):
  - GulpStore: schema v1 + migrations (newer schemas refused), SHA-256-deduplicated blobs with
    zlib for large bodies, FTS in the same transaction, the write coalescer (50 ms / 500 rows,
    ids assigned in memory, events after flush), paged/filtered/sorted summaries, annotations.
  - GulpProxy: HTTP/1 forward proxy (absolute-form, keep-alive, `Expect: 100-continue`,
    hop-by-hop stripping, recording with the client address) on configurable listeners.
  - GulpWorkspace: `ProjectSession` (temporary/open/Save As/close with flush), layered settings,
    recent projects, the bounded `HistoryPageCache`.
  - App + GulpFeatures: one window per project, File menu (New Temporary/New/Open/Recent/Save As),
    Proxy → HTTP History (virtualised NSTableView, column prefs, sort, highlight/comment/delete/
    copy URLs, quick filters, auto-scroll), read-only Raw/Hex viewer, the Listeners sheet.
  - gulp-cli: `proxy` (headless, flushes on SIGINT/SIGTERM), `history`, `send --via/--repeat`.
    The DoD browses VulnLab through the proxy with curl, sends 10,000 requests through it, quits,
    reopens the project and finds all 10,001 exchanges. Tests: 105 on Linux, plus the UI smoke tests.
  - Caught by CI: a closing proxy error page without `Connection: close` (the client reused a dead
    connection); swift-format's `indentConditionalCompilationBlocks: false`; the synthesized
    memberwise init of a public struct being `internal`; undeclared transitive module imports.

- 2026-11-07 — **Reviews after M2** (independent agents, no shared context):
  - **Code review** of M0–M2: 1 Blocker, 10 Majors, ~10 Minors. Fixed: the Blocker
    (Content-Length overflow trapped the process; unbounded request bodies) with a strict framer
    (agreeing decimal Content-Length, chunked-final Transfer-Encoding, 400 on malformed chunking, 413
    cap) and request framing warnings; proxy backpressure, ordered 100-continue/rejections, listener
    stop closes clients, protected framing headers; a `flock` single-writer lock per project; Save As
    holds recordings during the copy and refuses its own/an open destination; keep-alive reuse honours
    HTTP/1.0 and `Keep-Alive: timeout`; History selection/bulk actions by id, live updates under any
    sort, stale page loads dropped, reused row colours reset, model built once, lazy Raw view, bind
    errors shown, LIKE wildcards escaped. Not fixed yet (listed under carry-overs): response
    streaming, the HIS/PRJ partials, `settingsChanged`, the terminate hook, id reuse after delete.
  - **Feature review** of F01–F32 → `docs/FEATURE-REVIEW.md`. Adopted: M3 split into M3a/M3b,
    HTTP-027 (HTTP/2 trailers, P0), TLS-017 (ECH, P1), corrected TLS-015/MAC-011/BRW-002.
    Proposed (owner decision): new capabilities, re-sequencing, merges and cuts.
  - M3a progress: GulpTLS — CA (RSA/P-256), leaf minting with DNS/IP SANs and IDN A-labels,
    de-duplicated LeafMinter with LRU leaf + (host, ALPN) context caches, File/Keychain CA stores,
    ClientHello SNI/ALPN sniffer; tests do live NIOSSL handshakes against minted leaves.

- 2026-11-07 — **M3a DONE** (CI run 42424466338, `054b24a`; DoD `Scripts/m3a-dod.sh`: PASS, incl.
  a real https://example.com through the proxy):
  - GulpHTTP: upstream TLS inserted under the HTTP handler (direct, SOCKS, CONNECT tunnel); a
    custom verification callback captures the chain and the would-be result (swift-certificates
    Verifier vs the system PEM roots) — enforced only on request; TLSInfo on every exchange;
    versions/ciphers/ALPN settings in the pool key; refused connects retry all addresses.
  - GulpProxy: CONNECT → `200` → TunnelSniffer: MITM with a leaf for the SNI (replaying the
    ClientHello into NIOSSL), glob pass-through splice, or plain HTTP in the tunnel.
  - Sessions intercept with the user's CA (Keychain on macOS, 0600 file elsewhere); `gulp-cli ca
    export|show`; VulnLab `:8443`; Settings → TLS (details, export, install/remove trust, badge).
  - Caught by CI: `localhost` → `::1` first on macOS (single-address connect), BoringSSL refusing a
    server certificate without `digitalSignature`, `TLSUserEvent` living in NIOTLS, internal
    memberwise inits on public structs (twice), `catch where` spacing.

- 2026-11-08 — **Feature review adopted** (owner: "Adopt the feature review proposals"; product
  decision #7). Docs only, no code:
  - **Merged** F17, F26, F28, F29, F30, F31 into the specs they extend; the files are stubs listing
    where each requirement went (IDs kept) and the cut ones. HAR/collection import consolidated on
    one F20 service (PRJ-012).
  - **Added** PRX-050/HIS-007/REP-016 (streaming), **F33 gRPC & protobuf** (GRP-001…007; supersedes
    ADV-053), SES-016…018 (request signing), BRW-016/SES-032 (passkeys), REP-017/PRJ-013 (paste,
    other-proxy import), SCN-070…074, AI-013, LLM-009, HTTP-037; VulnLab fixtures for each.
  - **Deferred/cut**: F11 out of v1 (M14 retired), Frame Kit, PRX-048, Beacon server and Extension
    Gallery post-1.0; priority changes per FEATURE-REVIEW §3.4.
  - **Re-sequenced** without renumbering: M4a/b, M6a/b, M10a/b, M11a/b/c, M12a/b, M13a/b, M16a/b,
    M19a/b, and a **daily-driver beta** gate after M9. M3b (in progress) is unchanged.
  - Deviation: the original `featmap.py` predates letter-suffixed milestones (its README regex only
    accepts `M\d+`, and the M3a/M3b split had kept bare "M3" in headers), so it now reports every
    split feature as unindexed. D7 is checked with a suffix-aware copy (`featmap_sfx.py`, same logic)
    and `featmap2.py` (also header ↔ roadmap sections and every suffixed `Mxx` ref): both clean. All
    other checks pass (idcheck — 537 IDs as written, 544 with the new `GRP` prefix added — linkcheck,
    secnum, secref, tables).

- 2026-11-08 — **M3b DONE** (CI run 42498773075, `11cd7d5`; DoD `Scripts/m3b-dod.sh`: PASS):
  - GulpCore `HTTP2Text`: HTTP/1-style text ↔ HTTP/2 parts (HTTP-021/022); trailers stored via the
    chunked rendering an h2→h1 gateway uses (HTTP-027), re-framing for HTTP/1.1 clients.
  - GulpHTTP: ALPN derived from the version preference, h2c prior knowledge, `H2Connection` streams
    over one shared connection per key (`H2Pool`), push disabled, trailers, `negotiatedProtocol`
    pre-connect.
  - GulpProxy: ALPN mirroring (client gets h2 only when both sides do; Force-HTTP/1.1 toggles),
    HTTP/2 server pipeline with one exchange per stream; h2 upstream replies re-framed for h1 clients.
  - VulnLab `:8443` negotiates h2; History has a Protocol column; `gulp-cli history --show`.
  - Caught by CI: handlers must be `RemovableChannelHandler` to be swapped; the server's SETTINGS
    raced the switch to HTTP/2 (TLS: held by the handshake waiter; h2c on Linux: a ReadGate);
    `tooLarge(limit:)`; a captured `var` in a Sendable closure; the M3a DoD's echo check updated
    for the new h2 upstream.
  - Same branch: the feature-review adoption (docs agent; merged after all doc checkers passed).

## How to pick up work (reminder)

1. Read `CLAUDE.md` §1 (reading order) and this file.
2. Open the active milestone in `docs/03-roadmap.md`; read the referenced feature spec(s) and their
   requirement IDs.
3. Implement P0 first, tests naming requirement IDs; run `make test` + `make lint`; keep the core
   modules building on Linux.
4. Tick the box here, add a log line (date, what, any deviation), and commit referencing the IDs.
