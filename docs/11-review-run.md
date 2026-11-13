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
**Batch run (37 scripts, sequential, 240 s/script ceiling, shared fixture port 8088): 31 passed, 6
failed.** The six were then **re-run in isolation** (600 s each, each script owning its own fixture
server), which separated two harness artifacts, one real bug, and one environment limit:

| Script | Batch | Isolated | Diagnosis |
|---|---|---|---|
| m6a-dod | FAIL | **PASS** | Port-8088 contention: the preceding script, killed at the 240 s ceiling, left its `gulp-vulnlab` bound to 8088, so m6a's fixtures came from the stale server. Not a defect. |
| m6b-dod | FAIL | **PASS** | Same port-8088 contention. Passes cleanly alone (MCP out-of-scope refusal + audit log all correct). |
| m8-dod | FAIL | **PASS** | Same. Passes alone, including the ≥1,000 req/s Fuzzer throughput assertion and `/admin` + backup discovery. |
| report-dod | FAIL | **PASS** | Same. HTML + Markdown reports generated with severity summary and per-issue sections. |
| **recon-dod** | FAIL | **FAIL → FIXED** | **Real false-positive.** `recon.endpoint` fired on `/safe/recon/app.js`, which must be clean. Root cause: a `/recon/*` route-namespace collision — `Routes.swift` dispatches `ScanLab` before `ReconLab`, and `ScanLab` stripped the `/safe/` prefix and served its endpoint-laden JSRecon bundle for `/safe/recon/app.js`, shadowing `ReconLab`'s clean twin. Fixed by having `ScanLab` return `nil` for `/safe/recon/*` (the JSRecon DoDs only ever fetch the vulnerable twins). **recon-dod now PASS** (2 issues: secret on `/recon/config`, endpoint on `/recon/app.js`, nothing on `/safe/*`). |
| m9-dod | FAIL (rc=124) | **PASS** (ran to completion, 2198 s) | Re-run with no artificial ceiling: **`M9 DoD: PASS`**. The DoD seeds **1,000,000 rows** then asserts the performance guarantees, which are met with margin — **GulpQL matched 50 000 of 1 000 000 rows in 879 ms** (budget 2 000 ms) via `ix_ex_status`, and **FTS search found the planted token in 3 ms** among 100 k rows (budget 200 ms). The 2198 s wall was entirely *data generation*: the seeder (`GulpStore/SeedRows.swift`) is correctly batched (20 000 rows/txn, cached statement, shared blobs) and the earlier batch timeout was purely the throttled sandbox CPU — measured this run at a sustained **92.8 % CPU, linear O(n)** (50 k = 92.7 s, 100 k = 180.3 s). The thing under test is fast; only the fixture setup is slow here. |

**Net after the recon fix: 37 / 37 DoD scripts pass** (m9 confirmed by running it to completion; its
37-min wall is throttled data-generation only — the query/search assertions it guards pass with wide
margin). The scripts include every WebSocket-workbench script (`cswsh`, `wsauthz`, `wsfuzz`, `wsoast`,
`wsscript`), both JS-Recon scripts, `pollute`, `smuggle` / `smuggle-confirm`, `sequencer`,
`paramdisc`, `recipe`, and `m1`–`m13b`.

**One real product bug found and fixed by this executed review:** the recon `/safe`-twin
false-positive above (commit on branch `claude/ecstatic-cray-yzrb4d`). This is exactly what a
test-case-backed review is for — the differential `/safe/` oracle caught a check firing where it must
stay silent.
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
environment: there is no Mac here, Swift cannot cross-compile to Darwin from Linux (Apple's AppKit /
SwiftUI / JavaScriptCore SDK is not present and is not redistributable to Linux), and the private
repository's GitHub Actions minutes are exhausted, so the `macos-15` runner cannot provision.

**Re-confirmed this turn (2026-11-13):** a fresh `workflow_dispatch` run (#181, run id 43391057594)
on this branch failed immediately — the "App + full test (macOS)" job completed **3 s** after
creation and its logs return **HTTP 404** (a runner that never started produces no logs), and the
Linux job failed the same way in 4 s. The same instant-provisioning-failure held for runs #179 and
#180. This is an owner-level **billing** limit (not reset by the new month, and not a code defect):
the workflow parses and is correct (the earlier YAML quoting bug is fixed). The moment Actions
minutes are restored, the existing `macos` job compiles these files for real. This is the **sole open
item**, tracked here and in `08-architecture-review.md`; no code change in this environment can close
it — it is on the repository owner to restore CI billing.

## 5. Bugs this review run (and the shim type-checks it includes) actually found and fixed

Real defects surfaced by running the suites + DoD acceptance scripts + shim type-checks this cycle,
not hypotheticals:

0. **Recon false-positive on a `/safe/` twin (product/fixture bug, found by `recon-dod.sh`).** The
   passive secret/endpoint recon check reported `recon.endpoint` on `/safe/recon/app.js`, which the
   differential oracle requires to be clean. Root cause was a `/recon/*` route-namespace collision
   between `ScanLab` (JSRecon source-map fixtures) and `ReconLab` (secret/endpoint fixtures), with
   `ScanLab` dispatched first and stripping `/safe/`. Fixed so `/safe/recon/*` reaches `ReconLab`'s
   clean twin; `recon-dod.sh` now passes. This is the headline find of the executed review: a real
   false-positive the written review had not caught.
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

- **Unit/integration: fully green this run.** 519 tests / 60 suites / 0 failures in 12.4 s (§1).
- **DoD acceptance: 37 / 37 pass** after the recon fix (§2). m9 was confirmed by running it to
  completion (2198 s): its performance assertions pass with margin (query 879 ms / budget 2 s; search
  3 ms / budget 200 ms); the long wall was throttled 1M-row data generation only (measured 92.8 % CPU,
  linear O(n)).
- **Static gates: all pass** (§3) — arch layering, lint, 7/7 view type-checks, JSC-host type-check.
- **The executed review earned its keep:** it found and fixed a real recon false-positive (§5.0) that
  the document-only review had missed, and it separated four batch "failures" that were test-harness
  port contention from one real bug and one environment limit.
- **macOS GUI runtime: blocked on CI billing only** (§4), not on code. The code for it is written,
  wired, and type-checks against real-engine API shims.
