# 07 — Decisions (ADRs) and product decisions

Format: **Context → Decision → Consequences**. To add a decision, append a new ADR. Don't edit
accepted ones; supersede them.

---

## ADR-001: Native Swift app instead of Electron/Tauri or Java

- **Context**: The product is macOS-first and GUI-heavy. The reference tool is Java/Swing; the
  alternatives are web-UI shells (Electron, Tauri) or a Rust core with a Swift UI.
- **Decision**: All Swift. SwiftUI for the app structure, AppKit for high-volume views, SwiftNIO for
  networking.
- **Consequences**: + the best macOS fit, low memory, fast startup, one language for Claude to work
  in. − No Windows/Linux GUI (accepted non-goal). − SwiftUI gaps need AppKit bridging (planned for).
- **Alternative considered**: a Rust core (hyper/rustls) behind UniFFI with a SwiftUI frontend. It is
  faster to fuzz and the core is portable, but it costs two toolchains, FFI friction and a slower
  inner loop. We can revisit if the Swift engine misses its performance budgets.

## ADR-002: Our own raw HTTP engine instead of URLSession

- **Context**: Security testing must send malformed and non-canonical requests and observe exact
  responses. URLSession normalizes headers, adds its own, hides HTTP/2 framing and follows
  platform policies (ATS, cookies, caching).
- **Decision**: `GulpHTTP` writes raw bytes over NIO channels (HTTP/1) and drives
  `swift-nio-http2` at the frame level (HTTP/2).
- **Consequences**: More work (framing, pooling, decompression), but full control, including
  single-packet attacks.

## ADR-003: SQLite (GRDB) single-file projects

- **Decision**: One `.gulp` SQLite file per project, WAL, contentless FTS5 with trigram tokenizer,
  deduplicated compressed blobs.
- **Why**: Crash safety, instant open (no load step), fast paging and filtering for 1M+ rows, and
  inspectable with standard tools (`sqlite3 project.gulp`).
- **Rejected**: A bundle directory with JSON files (slow and fragile); Core Data/SwiftData (opaque
  schema, poor raw-bytes support, macOS only).

## ADR-004: GulpQL query language + JavaScript Snippets

- **Context**: Filters need to be fast, safe, cross-platform and approachable. The reference tool
  uses Java snippets.
- **Decision**: A small declarative language (GulpQL, F05) for filters and search, which can be
  translated partly to SQL for speed. JavaScript (JavaScriptCore) "Snippets" for the cases a
  declarative language can't express (custom columns, custom actions).
- **Consequences**: GulpQL works on Linux/CLI. JS Snippets are macOS-only in v1.

## ADR-005: Out-of-store distribution, no App Sandbox

- **Decision**: Developer ID signing + notarization + Sparkle updates. Hardened Runtime on, App
  Sandbox off.
- **Why**: Gulp launches browsers, binds ports, optionally changes system proxy settings, loads
  user extensions and spawns processes. The sandbox would block or seriously complicate all of
  these.

## ADR-006: Bring your own browser (managed Chromium over CDP)

- **Decision**: Don't embed Chromium. Discover an installed Chrome/Chromium/Edge/Brave, or download
  Chrome for Testing on demand. Launch it with an isolated profile and drive it over CDP.
- **Why**: Embedding Chromium (CEF) adds ~200 MB and a complex build. CDP gives full control for
  crawling, login recording and DOM Probe.

## ADR-007: OAST via a self-hostable Beacon + interactsh compatibility

- **Decision**: Ship a Beacon server (Linux binary or Docker) that the user deploys on a domain they
  control. Also implement the open interactsh client protocol, so users can point Gulp at public or
  self-hosted interactsh servers without deploying anything.
- **Why**: We can't run a shared public service. Interactsh compatibility gives zero-setup OAST
  (opt-in, with a third-party data notice).

## ADR-008: Extensions in JS (in-process) and any language (JSON-RPC, out-of-process)

- **Decision**: Two runtimes behind one API surface (F18). There is no JVM, and Java/Montoya
  compatibility is not a goal.

## ADR-009: AI is optional and provider-abstracted, Claude by default

- **Decision**: `GulpAI` defines an `LLMProvider` protocol. The first implementation uses the
  Anthropic Messages API (streaming + tool use). Off by default, explicit consent, redaction
  pipeline.

---

## ADR-010: Platform-specific engines are injected via protocols, never imported upward

- **Context**: `GulpBrowser`, `GulpScript` and the UI modules are macOS-only, but their consumers
  (`GulpCrawler`, `GulpScanner`, `GulpWorkspace`) must build and test on Linux. A direct target
  dependency on a macOS-only module is linked unconditionally by SwiftPM and breaks the Linux build;
  it also inverts the layering (an engine reaching "sideways" into a platform module).
- **Decision**: Lower modules define a protocol for the capability (e.g. `BrowserDriver` in
  `GulpCrawler`). The concrete implementation lives in the platform module (`GulpBrowser`) and is
  injected by `GulpWorkspace`. The platform modules are **defined on every platform** but wrap their
  AppKit/JavaScriptCore code in `#if canImport(...)`, so on Linux they compile to empty shells; the
  package manifest therefore has no platform branches and dependencies stay unconditional (M0
  implementation; see doc 02 §5 for the trade-off vs. `.when(platforms:)`). On Linux the shell
  provides no driver and the feature degrades (static-only crawling).
- **Consequences**: Clean layering, branch-free manifest, Linux CI stays green. Costs a little
  injection boilerplate and some empty-shell compile time on Linux.
- **Supersedes**: the earlier "`GulpCrawler` → `GulpBrowser`" edge in doc 01 §3.

## ADR-011: Scope evaluation is last-match-wins

- **Context**: The first draft of TGT-020 described scope as both "no later exclude rule" and
  "exclude wins", which are different and ambiguous semantics.
- **Decision**: Enabled rules are evaluated top-to-bottom; the **last** matching rule decides. No
  match ⇒ out of scope (so an empty rule set is "nothing in scope"). This is predictable, order is
  fully user-controlled, and the UI surfaces the deciding rule.
- **Consequences**: Simple to implement and explain; users order excludes after the includes they
  carve out of.

## ADR-012: MIT license

- **Context**: The owner chose to open-source Gulp (2026-11-07 decision #2). The license governs
  whether the Extension Gallery and update feeds can be public and how extensions may be shared.
- **Decision**: Release under the **MIT License** with a top-level `LICENSE` file. SPDX per-file
  headers are optional (MIT does not require them).
- **Consequences**: Permissive reuse; the Gallery/update feeds may be public. Note that MIT places no
  restriction on use, so the "authorized testing only" guidance (doc 00 §6) is a usage expectation
  enforced in-app (the acknowledgment and ScopeGuard), not a license term.

## ADR-013: Post-1.0 feature expansion (F25–F32) is additive, after release

- **Context**: An independent feature review proposed many capabilities beyond the v1 set (F01–F24).
  The owner asked to add features.
- **Decision**: Add eight as full specs — F25 SSO Workbench, F26 WebSocket Security, F27 JS Recon
  Studio, F28 Cache Poisoning, F29 Governor, F30 Drift & Retest, F31 Journal, F32 LLM-feature
  testing — scheduled in **Phase F (M21+)**, after the v1 release (M20). They are **additive**: each
  builds on existing v1 engines and reuses ScopeGuard/Governor/OAST, so none changes v1 scope or
  architecture. Two have P0 parts that belong earlier and are folded in: F29's shared limiter +
  panic stop in M11 and F31's coverage index in M9. Further candidates are a named backlog in
  `docs/README.md`, promoted to specs when scheduled.
- **Consequences**: v1 ships on the original M0–M20 plan unchanged; the expansion is clearly fenced
  and owner-prioritized. The one structural touch the review forced — the shared agent tool surface
  in `GulpWorkspace` (ADR-010-adjacent, doc 01 rule 6) — was needed by v1 (F21/F22) regardless.
- **Superseded in part (2026-11-08)** by product decision #7: F26, F28, F29, F30 and F31 were merged
  into the v1 specs they extend, F27's core moved into v1 (M19a), and the v1 plan was re-sequenced.

---

## Small decisions (append here)

| Date | Decision | Where |
|---|---|---|
| — | Bundle identifier `com.gulp.app` (placeholder) | doc 02 §4 |
| — | Default proxy listener `127.0.0.1:8080` | F01 |
| — | Payload position marker `§` (U+00A7) | F07 |
| — | Transform Tag delimiters `«…»` (⌥\ and ⌥⇧\ on a US keyboard) | F12 |
| 2026-11-07 | `GulpQuery` stays storage-agnostic: `sqlLowering()` returns a neutral `SQLBinding` enum, not GRDB's `DatabaseValue` | F05 §4 |
| 2026-11-07 | FTS trigram search needs 3+ chars; shorter queries fall back to a bounded scan | doc 04 §4, F05 HIS-050/052 |
| 2026-11-07 | Beacon binds privileged ports 53/443 via `CAP_NET_BIND_SERVICE` or privilege-drop, documented in deploy | F10 |
| 2026-11-07 | Single-packet send is best-effort (one `write`/flush, small payload), not a guaranteed single segment | F03 HTTP-033 |
| 2026-11-07 | M1 engine scope: plaintext HTTP/1 only. HTTPS targets fail with `.tlsFailure` and HTTP/2 preferences with `.other` naming M3; `openWebSocket` throws (M4); `singlePacket` group sends fail naming M5; `RedirectPolicy` is declared but only `.never` is honored until the Repeater (M5) | F03 §2, `NIOHTTPEngine` |
| 2026-11-07 | The first-byte timer starts when the request write is issued (not when it completes); the difference is the local write time, which is measured separately as `requestWriteMs` | F03 HTTP-005/010 |
| 2026-11-07 | Engine framing uses an exact, resumable chunk scanner (`HTTP1.scanChunked`) instead of a "is there a 0 line" heuristic, so chunk data containing `0\r\n` can't end a response early; malformed chunking falls back to read-until-close | F03 HTTP-002, doc 04 §2 |
| 2026-11-07 | Interim 1xx responses are carried as `RawResponse.interim` (each with its own bytes); `ParsedResponse.interimResponses` alone could not hold them because its byte ranges need their owning bytes | doc 04 §2 |
| 2026-11-07 | `ExchangeRecorder` (protocol in GulpHTTP, implemented by GulpStore in M2) is how the engine records exchanges; the engine records every send when a recorder is configured | F03 §4 |
| 2026-11-07 | VulnLab's M1 protocol fixtures use a raw SwiftNIO server (GulpCore parser) rather than Hummingbird, for byte-exact 1xx/chunked/verbatim-echo behavior; `/echo-raw` ends a request on a 150 ms pause, not by parsing, so malformed input round-trips | doc 06 §3, `gulp-vulnlab` |
| 2026-11-07 | HTTP-007 ships gzip/deflate (system zlib via a `CZlib` system-library target) as `ContentDecoding` + `RawResponse.decodedBody()`. **brotli and zstd are deferred** (no platform library; a pure-Swift decoder is its own project) — `decode` throws `.unsupported("br"/"zstd")` until then. Tracked in PROGRESS as an M1 carry-over | F03 HTTP-007 |
| 2026-11-07 | HTTP-006: plain-HTTP targets through an HTTP proxy use classic absolute-form proxying by default (the request line *must* change); `UpstreamProxy.tunnelPlainHTTP` instead CONNECT-tunnels them so the bytes stay exact. HTTPS always tunnels. SOCKS5 uses NIOSOCKS, whose client supports no-auth only, so SOCKS5 credentials fail with `.upstreamProxyError` for now | F03 HTTP-006, F01 PRX-041 |
| 2026-11-07 | `exchanges.response_blob` holds the response **as received on the wire** — interim 1xx responses followed by the final one (`RawResponse.wireBytes`); loading splits them back (`RawResponse(wire:)`). This keeps the store byte-exact without an extra column | doc 04 §4, GulpStore |
| 2026-11-07 | The write coalescer assigns exchange ids from an in-memory counter (seeded from `MAX(id)+1` on open) so `record` never waits on SQLite; rows flush every 50 ms / 500 items and `exchangeRecorded` is published only after the flush, so a listener always finds the row | doc 04 §4, PRJ-003 |
| 2026-11-07 | FTS rows are written in the same coalesced transaction as the exchange (not a separate background pass): the coalescer is already off the hot path, and one transaction keeps the index consistent after a crash | doc 04 §4 "FTS" |
| 2026-11-07 | A project written by a newer Gulp (unknown migrations, GRDB `hasBeenSuperseded`) is refused with `StoreError.newerSchema` rather than opened | doc 04 §4 "Migrations" |
| 2026-11-07 | `ProjectSession.store` is `private(set) var` (doc 01 §5.2 shows `let`): Save As switches the session to the new file. The engine records through a `ProjectRecorder` actor that forwards to the current store's writer, so the engine needn't be rebuilt; this adapter is also how GulpStore implements `ExchangeRecorder` without importing NIO | doc 01 §5.2, F03 §4 |
| 2026-11-07 | `LayeredSettings.set` is `async throws` (doc 04 §6 shows it synchronous) so a project value is persisted before `set` returns; `get` stays synchronous from an in-memory snapshot | doc 04 §6 |
| 2026-11-07 | `SendOptions.clientAddress` carries the proxy client's address into the recorded exchange (PRX-004), keeping one recording path (the engine) for every tool | F03 §2, F01 PRX-004 |
| 2026-11-07 | M2 proxy scope: absolute-form plain HTTP only. CONNECT answers 501 (TLS interception is M3); origin-form requests answer 400 (invisible mode PRX-040 is P1); the proxy itself answers `Expect: 100-continue`. Closing error pages carry `Connection: close` | F01 |
| 2026-11-07 | Proxy listeners are edited in a per-project sheet ("Listeners…" in the Proxy tool), since they are project settings; the app-level Settings window points there | F20 PRJ-021, doc 05 §1 |
| 2026-11-07 | **PRJ-001 carry-over:** closing a temporary project's window keeps its file in Caches (recoverable) instead of prompting to save/discard — intercepting SwiftUI's window close reliably needs an NSWindow delegate hook, deferred to polish (M16). Save As is available at any time | F20 PRJ-001 |
| 2026-11-07 | Proxy request framing is strict where guessing would desync: Content-Length must be plain decimal (≤18 digits) and duplicates must agree, Transfer-Encoding must end in `chunked`, malformed chunking is refused (400, close). Request bodies are buffered up to 256 MB (413 beyond) until request streaming lands | F01 §4.1 |
| 2026-11-07 | One writer per project: an advisory `flock` on `<project>.gulplock` (kernel-released on crash); a second open fails with `StoreError.alreadyOpen` | F20 §5 |
| 2026-11-07 | Save As pauses recording during the SQLite backup and replays the held exchanges into the new file, so nothing lands in the old file and no id is issued twice. Recording (and so proxied responses) wait for the copy | F20 PRJ-002 |
| 2026-11-07 | M3 split into M3a (TLS/CA/CONNECT, HTTP/1.1 to the client) and M3b (HTTP/2, trailers) after the feature review; scope proposals beyond scheduling await the owner (`FEATURE-REVIEW.md` §3) | roadmap |
| 2026-11-07 | Leaf minting runs in a detached task from the `LeafMinter` actor (not `NIOThreadPool`): same effect — never on an event loop — with structured de-duplication | F02 TLS-005 |
| 2026-11-07 | Lint: `AlwaysUseLowerCamelCase` disabled in `.swift-format`. It would force renaming the wire-faithful `HTTPVersion` cases (`http1_0`/`http1_1`, defined in doc 04 §2) and the byte constants `CR`/`LF`/`SP`/`HT`; keeping them is clearer and matches the spec. `AllPublicDeclarationsHaveDocumentation` stays on (CLAUDE.md §4) | `.swift-format`, verified by CI run 42346403079 |
| 2026-11-07 | Linux CI builds SQLite from source with `SQLITE_ENABLE_SNAPSHOT` + `FTS5`/`RTREE`/`JSON1`: Ubuntu's `libsqlite3` lacks `SQLITE_ENABLE_SNAPSHOT`, so GRDB 7's `DatabaseSnapshotPool`/`WALSnapshot` fail to link (`undefined reference to sqlite3_snapshot_*`). macOS uses Apple's SQLite, which has it. FTS5 is also needed for HIS-050 | `.github/workflows/ci.yml` (core-linux), ADR-003, surfaced by CI run 42346403079 |
| 2026-11-08 | **Feature-review adoption, interpretations** (product decision #7): (a) no milestone was renumbered — oversized ones were split with letter suffixes (M4a/b, M6a/b, M10a/b, M11a/b/c, M12a/b, M13a/b, M16a/b, M19a/b), M6 and M10 too because the import/MCP pull-forward and gRPC needed their own DoD; a bare "Mxx" means the group, M14 is retired and not reused. (b) Moved requirements keep their IDs and prefixes in their new home; merged specs stay as stubs, and cut requirements stay defined there as "Cut" rows. (c) Merged post-1.0 requirements (WSX, WCP, DRF) stay post-1.0, marked "(later: M22/M24/M25)" in their v1 home specs. (d) The dev Beacon (BCN-024) stays v1 because the integration and scanner-accuracy tests need a local OAST endpoint; the rest of the server is post-1.0. (e) F27 "trimmed, earlier" = JSR-001…005 + ETL-004 in M19a, JSR-006…009 in M23. (f) ETL items the review didn't name went to the tool they extend (ETL-004 → F27, ETL-006/010 → F21, ETL-009/011 → F06); ETL-007 (CSRF PoC) to F19. (g) F31 JRN-005/009 went with the timeline to F14; DRF-008 was cut with the baselines because proof replays already run the F15 session rules. (h) PRJ-013 imports other proxies' history without naming the reference suite in the UI (CLAUDE.md §4). (i) The beta gate requires a signed, notarized build, so signing/notarization (doc 02 §8) is pulled forward to the gate; Sparkle stays M20 | roadmap, README, F17/F26/F28–F31 stubs |
| 2026-11-08 | F33 stores imported gRPC schemas as blobs referenced from a `GRPCSchemaSettings` settings group and the task scheduler uses `SchedulerSettings` — no new tables for either; the only schema changes the review causes are the cut `drift_*`/`journal_checklists` tables, which are now never created | doc 04 §4, F21 §4, F33 §4 |

---

## Product decisions (resolved 2026-11-07; #7 on 2026-11-08)

These were open questions; the product owner has answered them. They are binding for v1. To change
one, ask the owner and update this list plus the "Where it applies" docs.

1. **Bundle ID** — keep the placeholder `com.gulp.app` for now; it must be replaced with the final
   reverse-DNS ID and an Apple Developer team before the first signed build — since decision #7 that
   is the **daily-driver beta** after M9, not M20.
   *Applies: doc 02 §4, `project.yml`.*
2. **License** — **MIT** (open source). The Extension Gallery and update feeds may be public. See
   ADR-012 and the `LICENSE` file. *Applies: `LICENSE`, README, doc 02 §8.*
3. **Minimum macOS** — **macOS 14 Sonoma**. Newer SwiftUI APIs go behind `if #available` with a
   Sonoma fallback. *Applies: doc 01 §1, doc 02 §1, `project.yml`.*
4. **OAST default** — **off until configured**. A fresh install preconfigures no Beacon and no public
   server; OAST is inactive until the user sets a Beacon URL or explicitly opts in to an interactsh
   server (with the third-party-egress notice). *Applies: F10 BCN-004/005.*
5. **AI providers (v1)** — **Claude (Anthropic Messages API) only**. The `LLMProvider` abstraction
   stays so OpenAI-compatible and local (Ollama) providers can be added later; they are **not** v1
   scope. *Applies: ADR-009, F22 AI-001/002/011.*
6. **Team server** — **not planned**. Gulp is single-user; sharing is by exchanging `.gulp` files and
   reports. Recorded as a non-goal. *Applies: doc 00 §3.*
7. **Feature review adopted (2026-11-08)** — the owner adopted every proposal in
   `docs/FEATURE-REVIEW.md` §3. Summary:
   - **Added** (with fresh IDs): streaming responses (PRX-050, HIS-007, REP-016; P0, M4b/M5);
     gRPC/gRPC-Web/Connect with schema-less protobuf decode as a new spec **F33** (GRP-001…007, P1,
     M10b; supersedes ADV-053); request signing — DPoP, HTTP Message Signatures, AWS SigV4
     (SES-016…018, P1, M12a); passkeys via a CDP virtual authenticator (BRW-016, SES-032, P1, M13a);
     paste-to-request and other-proxy history import (REP-017, PRJ-013, P1, M5/M6b); five scanner
     checks (SCN-070…074, P1, M11c); bounded agentic AI follow-up (AI-013, P1, M18); AI-agent/MCP
     endpoint testing (LLM-009, P1, post-1.0); an HTTP/3 Repeater client (HTTP-037, P2, post-1.0).
   - **Re-sequenced** (no renumbering; letter-suffixed splits): a **daily-driver beta** release gate
     after M9; Gulp Browser launch → M4b; the import/export service, API import and the MCP read
     surface + `send_request` → M6b; JWT Workbench → F12/M7; content discovery → F07/M8; Authz
     Matrix → M12b; GraphQL → M13b; Check Recipes → M15; M4, M6, M10, M11, M12, M13, M16 and M19 split.
   - **Merged**: F17, F26, F28, F29, F30 and F31 into the specs they extend (IDs kept; the files are
     stubs that list where each requirement went); the five HAR/collection imports consolidated on
     one service (PRJ-012).
   - **Deferred or cut**: F11 Sequencer out of v1 (Post-1.0 backlog; M14 retired); Frame Kit
     (BRW-020…022), PRX-048, GOV-004/005/008/009, JRN-004/006/007, the F30 baselines and the F17
     duplicates cut; the deployable Beacon server (BCN-020…023/025) and the Extension Gallery
     (EXT-020/021) post-1.0; P0 → P1 for DOM Probe (BRW-010/011), Check Recipes (SCN-060…062) and the
     Python SDK (EXT-012); P1 → P2 for RPT-005/009, AI-007/009 and MAC-020/022/023; RPT-012
     promoted to P1 (bug-bounty Markdown).
   *Applies: `03-roadmap.md`, `README.md`, the feature specs, doc 04 §4 (cut tables), doc 06 §3
   (new fixtures); interpretations are in the 2026-11-08 small decisions above.*
