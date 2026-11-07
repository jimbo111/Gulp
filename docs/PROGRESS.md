# Progress tracker

This is the live state of the build. Claude updates it as work lands: tick tasks in the current
milestone (keep the detail in `docs/03-roadmap.md`) and add a dated log line. Work milestones in
order; within a milestone, do P0 first.

## Current status

- **Phase**: **M2 DONE** — CI green on both platforms (run 42416523505, commit `1acf39c`), and the M2 DoD
  is an executable check (`Scripts/m2-dod.sh`, run by the Linux job): PASS. M0 and M1 done earlier.
- **Active milestone**: **M3a — TLS interception + CA (HTTP/1.1)**, then M3b (HTTP/2). M3 was split
  by the 2026-11-07 feature review (`docs/FEATURE-REVIEW.md`). GulpTLS (CA, minting, caches,
  storage, ClientHello sniffer) has landed; upstream TLS, CONNECT/MITM and the CA install UI are next.
- **Branching**: `main` holds merged milestones (PR jimbo111/Gulp#1 merged M0–M2). Work happens on
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
    instead; needs an NSWindow close hook, M16 polish). The proxy answers CONNECT with 501 until M3a
    and origin-form (invisible) requests with 400 until PRX-040.
  - M2, found by the 2026-11-07 code review (partial requirements, now stated honestly):
    - **F01 §4.3 response streaming**: responses are buffered whole (50 MB / 120 s limits), so large
      downloads and SSE/long-polling fail through the proxy. Planned with streaming exchanges (M4,
      FEATURE-REVIEW A1). Request bodies are buffered too, capped at 256 MB (413 beyond).
    - HIS-004: "add to scope" (needs M6) and "send to tools" (M5) are not there yet.
    - HIS-005: comments are edited in a dialog, not inline (UI-041 lands with the editor, M4).
    - HIS-006: in-scope (M6), MIME and method chips are missing from the UI (the query supports them).
    - PRJ-005: "Use settings from…" has an API but no UI; import from a settings file is missing.
    - PRJ-006 (P1): name/notes API only, no Project Info panel.
    - F20 §4: `settingsChanged` is declared but never published.
    - No app-terminate hook: on Cmd-Q the last ~50 ms of queued writes may be lost (window close is
      fine). Exchange ids can be reused after the newest rows are deleted and the project reopened.
- **Next action**: M3a — upstream TLS in GulpHTTP (TLS-008/009), CONNECT + MITM + pass-through in
  GulpProxy (PRX-005…007), Settings → TLS with Keychain install/trust status (MAC-001/002), VulnLab
  `:8443`, and the executable DoD. Then M3b (HTTP/2, trailers).
- **Waiting on the owner**: the scope proposals in `docs/FEATURE-REVIEW.md` §3 (add, merge, defer,
  cut). Nothing has been removed from the specs until they are decided.
- **Product decisions**: resolved by the owner and recorded in `docs/07-decisions.md` §"Product
  decisions" (MIT license; macOS 14 min; Claude-only AI in v1; OAST off until configured;
  `com.gulp.app` placeholder bundle id; no team server). Build to those.

### Documentation Definition of Done (the objective "build-ready" bar)

"Nearly perfect" is subjective, so here is the **concrete, auditable standard** the doc set is held
to, with how each criterion is measured and its status. A criterion is MET only if its stated,
reproducible check passes. (Re-run the checks after any edit; scripts live in the session scratchpad
and are pure Python over the Markdown.)

| # | Criterion (objective) | How measured | Status |
|---|---|---|---|
| D1 | Every feature has a spec file with the standard sections (Purpose, Requirements, UI, Implementation, Edge cases, Acceptance tests) | 32 `docs/features/Fxx-*.md`; grouped specs (F23) noted in docs/README | MET (32/32) |
| D2 | Every requirement row has a stable ID + priority (P0/P1/P2) | ID-table scan | MET |
| D3 | No duplicate requirement IDs; no referenced-but-undefined IDs (incl. slash-shorthand) | `idcheck` | MET (516 IDs, 0 dup, 0 dangling) |
| D4 | Every internal Markdown link, `Fxx` ref, and `Mxx` ref resolves | `linkcheck` | MET |
| D5 | Every `## N`/`### N.M` numbering sequence has no gaps/dupes | `secnum` | MET |
| D6 | Every `Fxx §N` / `doc NN §N` cross-ref points to a real section | `secref` | MET |
| D7 | Each feature's milestone agrees across its header, the README index, and the roadmap | `featmap` | MET |
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
- [ ] M3a — TLS interception + CA (HTTP/1.1) — GulpTLS landed (`996d99d`)
- [ ] M3b — HTTP/2 (client side + upstream, trailers)
- [ ] M4 — Intercept, Match & Replace, message editor, WebSockets
- [ ] M5 — Repeater + advanced HTTP engine (HTTP/2 raw, group/race sends)
- [ ] M6 — Target: site map + scope + ScopeGuard
- [ ] M7 — Decoder + Comparer
- [ ] M8 — Fuzzer
- [ ] M9 — Logger, GulpQL, search, Notebook **+ F31 Journal coverage index (fold-in)**
- [ ] M10 — Passive scanner + issue model
- [ ] M11 — Crawler + active scanner + Beacon + Check Recipes **+ F29 Governor limiter & panic stop (fold-in)**
- [ ] M12 — Sessions, auth, macros
- [ ] M13 — Gulp Browser, DOM Probe, Frame Kit
- [ ] M14 — Sequencer
- [ ] M15 — Extensions + scripting
- [ ] M16 — Reporting, engagement tools, project polish **+ F29 Governor full panel & F31 Journal full tool (fold-ins)**
- [ ] M17 — Automation: CLI, REST API, MCP server
- [ ] M18 — Gulp Assistant (AI)
- [ ] M19 — Advanced tools (Authz Matrix, JWT, Param Discovery, Smuggling, GraphQL, API import, secrets)
- [ ] M20 — macOS polish, packaging, release
- [ ] M21 — F25 SSO Workbench *(Phase F, post-1.0)*
- [ ] M22 — F26 WebSocket Security Workbench
- [ ] M23 — F27 JS Recon Studio
- [ ] M24 — F28 Web Cache Poisoning & Deception
- [ ] M25 — F30 Drift & Retest
- [ ] M26 — F32 LLM/AI-feature security testing

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

## How to pick up work (reminder)

1. Read `CLAUDE.md` §1 (reading order) and this file.
2. Open the active milestone in `docs/03-roadmap.md`; read the referenced feature spec(s) and their
   requirement IDs.
3. Implement P0 first, tests naming requirement IDs; run `make test` + `make lint`; keep the core
   modules building on Linux.
4. Tick the box here, add a log line (date, what, any deviation), and commit referencing the IDs.
