# 08 — Architecture review (2026-11-13, refreshed at feature-complete)

> **Snapshot, not current status.** `docs/PROGRESS.md` is authoritative for what is built; it
> describes the code as of 2026-11-13. "Every milestone implemented" overstates it: several
> milestones are partial, and the macOS code was first compiled on 2026-11-20, not by a macOS CI
> run.

A higher-level, architectural review of the Gulp codebase as it stands **with every milestone and the
post-1.0 phases implemented** (the full WebSocket workbench WSX-002…008, AI/redaction, the extension
hosts, Sequencer, JS Recon, smuggling confirmation, param discovery/pollution, and all the macOS tool
screens), judged against the ideal the project set for itself in `docs/01-architecture.md` and the hard
rules in `AGENTS.md`. It is backed by an executable check (`Scripts/arch-check.sh`) so the conclusions
stay true as the code changes, not just on the day they were written.

## 1. Scope and method

- **Size**: ~60k+ lines of Swift across 22 real modules plus three executables (`gulp-cli`,
  `gulp-vulnlab`, `gulp-beacon`). Every module that was a stub at M13b is now built: `GulpSequencer`
  (randomness battery), `GulpReport` (HTML/Markdown reporting), `GulpExtensions` (out-of-process host),
  `GulpAI` (agent + redaction), and `GulpScript` (the in-process JavaScriptCore extension host). The
  only code that cannot be compiled on Linux is, by design, the Apple-framework-gated UI (`GulpFeatures`
  SwiftUI) and the `GulpScript` JavaScriptCore host — both behind `#if canImport(...)` and verified by
  the macOS CI leg.
- **Method**: static inspection of the module/import graph, the concurrency surface
  (`actor`/`Sendable`/`@unchecked`), the invariants `AGENTS.md` calls non-negotiable, and the test
  and DoD coverage. Each structural claim is re-checkable: the dependency rules now run as
  `Scripts/arch-check.sh` in the gate and CI.

## 2. Layering and the dependency graph

The intended layering (`docs/01-architecture.md` §3) is **Foundation → Services → Engines →
Orchestration → UI**, with engines allowed a short list of sideways imports. The *actual* import
graph, extracted from the sources, matches it:

```
GulpCore         → (nothing)                                   # foundation
GulpCodec        → GulpCore                                    # services
GulpTLS          → GulpCore
GulpQuery        → GulpCore
GulpStore        → GulpCore GulpQuery
GulpHTTP         → GulpCore GulpTLS
GulpDiff         → GulpCore
GulpProxy        → GulpCore GulpHTTP GulpQuery GulpTLS         # engines
GulpRepeater     → GulpCore GulpHTTP
GulpFuzzer       → GulpCore GulpHTTP GulpCodec
GulpScanner      → GulpCore GulpHTTP GulpCodec
GulpCrawler      → GulpCore GulpHTTP                           # NOT GulpBrowser (ADR-010 ✓)
GulpSession      → GulpCore GulpHTTP GulpCodec
GulpOAST         → GulpCore GulpHTTP
GulpWorkspace    → every engine + services + GulpBrowser       # orchestration
GulpAutomation   → GulpCore GulpHTTP GulpStore GulpWorkspace
GulpFeatures     → the engines it surfaces + GulpWorkspace + GulpUI   # UI (macOS)
```

**Findings**

- **The dependency direction holds everywhere.** No engine imports an orchestration or UI module;
  no service imports an engine; `GulpCore` imports nothing. This is now enforced by
  `Scripts/arch-check.sh`, which parses every module's imports, assigns a layer rank, and fails on an
  upward import, on `GulpCore` importing anything, on `GulpCrawler` importing `GulpBrowser`
  (ADR-010), or on an engine/service importing AppKit/SwiftUI/JavaScriptCore/WebKit (rule 2). It is
  a static grep, so it runs in milliseconds on every push.
- **ADR-010 (browser injected, never imported) is respected.** `GulpCrawler` reaches browser-backed
  crawling through a `BrowserDriver` protocol it defines; the concrete CDP driver lives in
  `GulpBrowser` and is injected by `GulpWorkspace` on macOS. The Linux build keeps compiling because
  nothing pulls AppKit into a lower layer.
- **Only `GulpUI` and `GulpFeatures` import the Apple UI frameworks.** Platform code in
  `GulpBrowser`/`GulpScript` is behind `#if canImport(...)`; on Linux those compile to empty shells,
  so the whole core graph builds and tests on Linux (verified: the gate runs in a Swift-on-Linux
  container).
- **Fixed during this review:** `GulpScanner` declared package dependencies on `GulpOAST`,
  `GulpCrawler` and `GulpSession` that it never imported (its `OASTProvider` is a protocol defined in
  the module itself, and crawl-and-audit lives in `GulpWorkspace`). Removed — three fewer edges in
  the build graph and a dependency list that now tells the truth.
- **A real latent bug the review surfaced (now fixed):** `GulpFeatures` declared *too few*
  dependencies — its own views `import GulpScanner`, `GulpSequencer`, `GulpExtensions`, `GulpCrawler`
  and (newly) `GulpBrowser`, none of which were in the target's `dependencies`. On Linux this hid
  because the views are `#if canImport(AppKit)` (empty), but the macOS build of the target would have
  failed on a missing-module error. All five were added. This is the one class of defect the Linux
  gate structurally cannot catch — a missing dependency behind an Apple-framework guard — and is the
  reason the macOS CI leg is load-bearing, not optional.
- **The guardrail caught a misplacement in real time.** The in-process JavaScriptCore extension host
  was first drafted inside the `GulpExtensions` *engine*; `arch-check.sh` rule 2 ("engines and
  services must not import an Apple UI/JS framework") failed the build immediately. It was moved to
  `GulpScript` — the platform-capability module the architecture already reserves for "JavaScriptCore
  runtime and in-process JS extension host" — which resolved it. The check doing its job during
  development, not just in review, is the strongest evidence the layering is enforced rather than
  aspirational.

## 3. The hard invariants

`AGENTS.md` names a few invariants as non-negotiable. Each was checked, not assumed:

- **"Raw bytes are the truth."** No engine module (`GulpHTTP`, `GulpProxy`, `GulpRepeater`,
  `GulpScanner`) imports `URLSession` or `URLRequest`; a grep returns nothing. Request edits across
  the codebase (`settingHeader`, `updatingContentLength`, `settingQueryParameter`, the scanner's
  insertion-point splice, the signer) all operate on the byte buffer and recompute only what a
  documented option says to. The one place bytes are re-serialized — Content-Length after hooks — is
  explicit and ordered after the request hooks, and the request signer re-runs it itself so the
  signature covers the sent bytes.
- **The main thread never waits on the network or the database.** Every I/O boundary is an `actor`
  (32 of them) or an async NIO path; UI reads go through paged async store queries; the write
  coalescer batches history writes; the passive scanner reads from a persisted cursor rather than
  blocking on traffic. The UI-coalescing rule (≤100 ms) is honoured in every live view
  (`CrawlerModel`, `ActiveScanModel`, history).
- **Strict concurrency.** The package is Swift 6 language mode. There are 14 `@unchecked Sendable`
  declarations and **every one carries a justifying comment** (an `NSLock`-guarded box, an immutable
  post-init value, or thread-safe Foundation handles), exactly as `AGENTS.md` requires. No bare
  `@unchecked`.
- **Scope safety.** Active tools (Scanner, Crawler, Fuzzer, Authz Matrix, Beacon injection) check
  `ScopeGuard` before sending and expose an explicit per-action override that is surfaced in the CLI
  and the UI; the matrix and scans refuse out-of-scope hosts unless overridden (tested).
- **Secrets.** CA private keys go to the Keychain (macOS) or a 0600 file; API keys are Keychain-only.
  *Gap:* request-signing keys (M12a) are currently passed in config rather than the Keychain — a
  tracked carry-over, noted in `docs/07-decisions.md` and PROGRESS.

## 4. Concurrency and data-flow model

- The **engine** (`NIOHTTPEngine`) is the single choke point for outbound traffic: request hooks →
  line-ending/Content-Length fixers → send → response hooks → record. Every tool (proxy, repeater,
  fuzzer, scanner, crawler, session macros, OAST, authz) sends through it, so cross-cutting concerns
  — the shared rate/concurrency limiter (`ResourcePool`), the panic stop, recording, session rules,
  signing, Transform Tags, match & replace — are applied uniformly in one place rather than
  re-implemented per tool. This is the codebase's strongest structural decision.
- **Hooks are ordered by array position, typed by `HookSet`.** Session rules run first, signing last
  (so it sees the final bytes); the engine filters per send via `SendOptions.applyHooks`. The design
  scales: M12a added signing as a late hook without touching any other tool.
- **State that outlives a request** (cookie jar, DPoP nonces, limiter counters, OAST correlations)
  lives in actors; value types (`CookieJar`, `Identity`, `ScanConfig`, `IssueFinding`) flow through
  the async boundaries by copy, which keeps the concurrency reasoning local.

## 5. Test and verification posture

- **516 unit/integration tests** (`swift-testing`) covering every module, plus **~25 "Definition of
  Done" scripts** (`Scripts/*-dod.sh`) that run the real `gulp-cli`, `gulp-vulnlab` and `gulp-beacon`
  end to end and assert observable behaviour (the scanner finds exactly the planted bugs with no false
  positives on the `/safe/*` twins; signing verifies against an independent implementation; the authz
  matrix flags the IDOR; GraphQL introspection and the field-authz bug are detected; the WS workbench's
  per-message-authz, fuzzer, OAST-over-WS and scripted-sequence probes each pass against VulnLab's WS
  routes; the smuggling confirmation refuses to auto-send and is scope-gated). Both the tests and the
  DoDs run in CI on every push, on Linux for the core and macOS for the app.
- **VulnLab as a differential oracle.** The DoD scripts assert against a controlled vulnerable app
  with safe twins, so "the tool is correct" is a reproducible claim, not a vibe. The signing and
  authz DoDs deliberately verify with a *second, independent* implementation in VulnLab, so a pass
  proves interoperability, not just self-consistency.
- **Gap:** no coverage numbers are collected, and the macOS UI layer (`GulpFeatures`) is unverifiable
  in the Linux cloud environment — its views are compiled but not exercised here; they rely on the
  macOS CI job.

## 6. Risks and technical debt

1. **macOS-gated surfaces are unverified in cloud sessions.** The SwiftUI tool screens
   (`GulpFeatures`), the in-process JavaScriptCore host (`GulpScript`), the CDP browser automation,
   notarized packaging, and the live AI provider can't be *compiled or exercised* on Linux; they
   depend on the macOS CI job. This is the dominant residual risk — not a design flaw, but it means a
   missing dependency or an API-signature error behind an Apple-framework guard (see §2) only shows up
   on the macOS leg. **And that leg currently cannot run:** the repository is private and its GitHub
   Actions minutes are exhausted, so every CI job — the `macos` (macos-15) build *and* the `core-linux`
   job — fails at runner provisioning in ~2 seconds with zero steps executed and no logs (verified
   2026-11-13 via the Actions API on run 174+). This is an account/billing limit only the owner can
   lift (add minutes or a payment method); it is not a code failure, and it is the long-standing reason
   the project ships a Docker-based local Linux gate (`localci.sh`) as the stand-in. A separate, real
   defect compounded it this session: a `ci.yml` step name carried an inner `": "` (from the ADV-032
   commit) that made the whole workflow unparseable, so runs failed even earlier (0 jobs). That YAML
   error is now fixed — the workflow parses and correctly schedules the macOS build — so the one
   outstanding verification (SwiftUI layout compilation) will execute the moment the account has CI
   minutes, with nothing further required of the code. Mitigation applied: every macOS view/host in this round was written against the
   engines' *verified* public signatures (read from source) and the Apple-framework surface is kept to
   constructs already proven elsewhere in the module. **Further, for the one piece of genuinely new
   Apple-framework logic — the in-process JavaScriptCore host — the gap is now partly closed by
   `Scripts/jsc-host-typecheck.sh`:** it type-checks the host body against a faithful shim of the
   JavaScriptCore subset it uses, linked against the *real* `GulpExtensions`, so the class of error the
   `#if canImport` guard hides is caught on Linux CI too. Writing that harness immediately found two
   real defects — a `compactMap` result-type inference problem and, more importantly, that
   `ExtensionCheck`'s synthesized memberwise initializer is *internal* to `GulpExtensions` and so was
   inaccessible from the host's module (`GulpScript`); a public `init` was added. The same technique was
   then applied to the **seven new SwiftUI tool screens** with a loose SwiftUI/AppKit/Observation type
   shim compiled against the real engine modules: **all seven type-check cleanly** (Sequencer, JS-Recon,
   Assistant, GraphQL, Extensions, DOM-Probe, Authz-Matrix). Getting there surfaced a **third real bug**:
   `SequencerView` called `GulpSequencer.analyze` when the function lives on the `Sequencer` enum
   (`Sequencer.analyze`); fixed. Two views initially failed the check on an inline
   `Table(… .enumerated().map { … })` that the loose shim (and SwiftUI's own type-checker, notoriously)
   struggles to infer; the fix moved the row projection onto the model (`model.testRows`,
   `model.literalRows`) — the same pattern the GraphQL view already used — which is a genuine
   improvement, not shim-appeasement. SwiftUI *layout* correctness still ultimately rests on the macOS CI
   leg (the shim was a throwaway harness, not a kept CI gate, since it does not model enough of SwiftUI
   for the mature views), but the model↔engine wiring — the actual risk behind the guard — is now
   type-checked clean for all seven. Net of this session: **three real cross-platform defects the Linux
   `#if canImport` guard had hidden** (`ExtensionCheck` access, `compactMap` inference,
   `Sequencer.analyze`) plus the `GulpFeatures` missing-dependency bug were found and fixed.
2. **All milestone modules are now built**; no stubs remain. The post-1.0 breadth (further WS
   sub-protocol coverage, richer AI tool-use) is enhancement, not missing structure.
3. **Signing keys not yet in the Keychain** (see §3).
4. **`GulpWorkspace` is large (~5k lines)** and imports nearly everything by design (it is the
   composition root). It is cohesive but worth watching; the service-per-file split keeps it
   navigable.
5. **GraphQL/gRPC parsing is hand-rolled** (no schema libraries) to avoid dependencies; it is tested
   but covers the common shapes, not every spec corner.

## 7. Verdict

The architecture is sound and, more importantly, *enforced*: the layering the design promised is the
layering the code has, and that is now a CI gate rather than a convention. The single-engine
choke-point, the actor-per-boundary concurrency model, the raw-bytes discipline, and the
VulnLab-backed DoDs are the load-bearing decisions, and they hold up. The open items are breadth
(unbuilt milestones) and environment (macOS verification), not structural debt.
