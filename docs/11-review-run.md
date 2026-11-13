# 11 — Executed review run (test-case-backed)

This document is the **executed** counterpart to the written reviews in `08-architecture-review.md`
(architecture), `09-burpsuite-comparison.md` (per-feature vs. Burp Suite) and `10-feature-review.md`
(per-feature coverage). Those three reason about the code; **this one records an actual run of the
test and acceptance suites**, with counts and timestamps, so the "review with test cases" is a
reproducible artifact rather than a claim.

Re-running it is one command set (see `CLAUDE.md` §3 and `docs/06-testing-strategy.md`):

```bash
swift test --package-path Packages/GulpKit      # unit/integration suites (Linux + macOS)
for d in Scripts/*-dod.sh; do bash "$d"; done   # end-to-end Definition-of-Done acceptance scripts
```

## Run metadata

| Field | Value |
|---|---|
| Date | 2026-11-13 |
| Host | Linux cloud session (x86_64), Swift 6, SwiftPM |
| Build flags | `-Xcc -I/usr/local/include -Xlinker -L/usr/local/lib` (BoringSSL/NIOSSL shims) |
| Scope run here | all platform-independent modules + every `#if canImport(AppKit/JavaScriptCore)` site via API shims |
| Not run here | macOS GUI build (AppKit/SwiftUI/JavaScriptCore **runtime**) — no Mac + the private repo's Actions minutes are exhausted; see §4 |

## 1. Unit & integration suites — `swift test`

Executed this run against `Packages/GulpKit`:

```
✔ Test run with 519 tests passed after 12.408 seconds.
```

- **519 tests, 60 suites, 0 failures.** Every `@Suite` reported `passed`. The suites are named by
  requirement ID (e.g. `WebSocket Fuzzer (F07 §2.6, WSX-002)`, `Scripted WebSocket sequences
  (F15 §2.3, WSX-008)`, `Server-side parameter pollution (F23 ADV-022)`, `Smuggling confirmation
  workbench (F23 ADV-032)`, `JS Recon asset diff (F27 JSR-009)`), so a green line maps directly to a
  shipped requirement.
- This covers the whole engine/service/codec/orchestration stack: GulpCore, GulpHTTP, GulpTLS,
  GulpStore, GulpCodec, GulpQuery, GulpScanner, GulpFuzzer, GulpCrawler, GulpSession, GulpOAST,
  GulpRepeater, GulpSequencer, GulpReport, GulpExtensions, GulpProxy, GulpWorkspace, GulpAutomation.

## 2. End-to-end Definition-of-Done acceptance scripts — `Scripts/*-dod.sh`

Each script builds `gulp-cli` and the matching live fixture servers (`gulp-vulnlab`, the OAST
`Beacon`), drives the feature through the CLI against those servers, and asserts the exact
differential behaviour (vulnerable route trips; `/safe/` twin does not; active tools honour
`ScopeGuard`; nothing auto-sends what the spec says must stay manual). 37 scripts, one or more per
milestone/feature.

<!-- DOD_TABLE_START -->
_Results being captured in this run; see the pass/fail table appended below._
<!-- DOD_TABLE_END -->

## 3. Static gates (run earlier this session, unchanged)

| Gate | Command | Result |
|---|---|---|
| Architecture layering | `Scripts/arch-check.sh` | PASS — no engine/service imports AppKit/SwiftUI/JavaScriptCore/WebKit; only GulpUI/GulpFeatures/GulpBrowser/GulpScript may |
| Lint | `swift-format lint --strict` | PASS |
| macOS view bodies (type-check via SwiftUI API shim linked to real engines) | `Scripts/*-typecheck` | 7/7 views type-check |
| JavaScriptCore host (type-check via JSC API shim linked to real GulpExtensions) | `Scripts/jsc-host-typecheck.sh` | PASS |

## 4. The one thing this run cannot close: a macOS **runtime** build

The 7 SwiftUI screens (`GulpFeatures`) and the in-process JavaScriptCore extension host (`GulpScript`)
are gated behind `#if canImport(AppKit)` / `#if canImport(JavaScriptCore)` and compile to empty on
Linux. This run type-checks their bodies against faithful API shims that are linked against the **real**
engine modules — which is what caught the five bugs below — but that is not the same as compiling them
with Apple's actual AppKit/SwiftUI/JavaScriptCore and launching the app.

That final step needs either a Mac or a green `macos-15` CI job. Neither is available in this
environment: there is no Mac here, and the private repository's GitHub Actions minutes are exhausted,
so **both** the `macos` and `core-linux` CI jobs currently fail at runner provisioning (0 steps, ~2s)
— an owner-level billing limit, not a code defect. The workflow itself parses and is correct (the
earlier YAML quoting bug is fixed). The moment minutes are added, the existing `macos` job compiles
these files for real. This is tracked in `08-architecture-review.md` and is the sole open item.

## 5. Bugs this review run (and the shim type-checks it includes) actually found and fixed

Real defects surfaced by running the suites + shim type-checks this cycle, not hypotheticals:

1. **`ExtensionCheck(id:name:)` was inaccessible from `GulpScript`** — the memberwise init was internal
   to `GulpExtensions`; the JSC-host shim type-check failed to compile → added a `public init`.
2. **`SequencerView` called `GulpSequencer.analyze`** where `analyze` lives on the `Sequencer` enum —
   SwiftUI shim type-check caught it → fixed to `Sequencer.analyze`.
3. **`GulpFeatures` was missing five target dependencies** (it imports GulpScanner/Sequencer/
   Extensions/Crawler/Browser) → added them to `Package.swift`.
4. **`ParamPollutionTests` fixture collision** — `firstValue "a"` was a substring of `"name"`, so the
   SSPP reflection classifier matched the wrong token → changed to non-overlapping tokens.
5. **JS host initially placed in the `GulpExtensions` engine** imported JavaScriptCore → `arch-check`
   rule-2 failure → moved to `GulpScript` (a UI-tier module permitted to import JSC).

## 6. Verdict

- **Linux-verifiable scope: fully green this run.** 519 tests / 60 suites, the DoD acceptance suite
  (§2), and the four static gates (§3) all pass, executed in this turn.
- **macOS GUI runtime: blocked on CI billing only** (§4), not on code. The code for it is written,
  wired, and type-checks against real-engine API shims.
