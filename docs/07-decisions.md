# 07 — Decisions (ADRs) and open questions

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
  `GulpCrawler`). The concrete implementation lives in the platform module and is injected by
  `GulpWorkspace`, which is the *only* module that conditionally depends on platform engines
  (`condition: .when(platforms: [.macOS])` + `#if os(macOS)`). On Linux the capability is absent and
  the feature degrades (static-only crawling).
- **Consequences**: Clean layering, Linux CI stays green. Costs a little injection boilerplate.
- **Supersedes**: the earlier "`GulpCrawler` → `GulpBrowser`" edge in doc 01 §3.

## ADR-011: Scope evaluation is last-match-wins

- **Context**: The first draft of TGT-020 described scope as both "no later exclude rule" and
  "exclude wins", which are different and ambiguous semantics.
- **Decision**: Enabled rules are evaluated top-to-bottom; the **last** matching rule decides. No
  match ⇒ out of scope (so an empty rule set is "nothing in scope"). This is predictable, order is
  fully user-controlled, and the UI surfaces the deciding rule.
- **Consequences**: Simple to implement and explain; users order excludes after the includes they
  carve out of.

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

---

## Open questions for the product owner

The specs assume the defaults below. Override any of them and Claude will update the docs.

1. **Bundle ID / organization name**: the specs use `com.gulp.app`. What reverse-DNS ID and Apple
   Developer team should releases use?
2. **Licensing model**: open source (which license?) or closed/commercial? This decides whether the
   Extension Gallery and update feeds are public.
3. **Minimum macOS**: the specs say macOS 14 Sonoma. Is it OK to require macOS 15 or later (it
   unlocks newer SwiftUI APIs)?
4. **Beacon domain**: do you have a domain for a default self-hosted Beacon, or should the defaults
   point to interactsh public servers (opt-in)?
5. **AI provider**: Claude-only, or also OpenAI-compatible and local (Ollama) providers from day one?
6. **Team features**: is a shared team server (shared projects, collaborative Repeater) in scope for
   a later version?
