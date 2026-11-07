# Progress tracker

This is the live state of the build. Claude updates it as work lands: tick tasks in the current
milestone (keep the detail in `docs/03-roadmap.md`) and add a dated log line. Work milestones in
order; within a milestone, do P0 first.

## Current status

- **Phase**: M0 scaffolding written; **awaiting first CI run to verify the builds**.
- **Active milestone**: **M0 — Scaffolding** (files complete, verification pending).
- **Verification caveat**: the authoring container has **no Swift toolchain** and
  `download.swift.org` is blocked by its network policy, so `swift build`/`swift test` and
  `xcodebuild` could not be run here. `Package.swift`, `project.yml`, `.swift-format` and the CI YAML
  were statically checked (structure, YAML/JSON validity, target↔directory mapping, 110-col lint
  limit). **CI (`.github/workflows/ci.yml`) is the real gate** — the `core-linux` job runs
  `swift test` on Linux and the `macos` job runs `make generate lint test build`. Treat M0 as done
  only once that workflow is green; fix anything it flags before starting M1. (The `macos` job runs
`make bootstrap` then `make lint generate test-core build test`; the `core-linux` job runs
`swift build`/`swift test` on the whole GulpKit graph.)
- **Next action**: push, watch CI, fix any build fallout, then begin **M1** (GulpCore model + raw
  HTTP/1 engine).
- **Product decisions**: resolved by the owner and recorded in `docs/07-decisions.md` §"Product
  decisions" (MIT license; macOS 14 min; Claude-only AI in v1; OAST off until configured;
  `com.gulp.app` placeholder bundle id; no team server). Build to those.

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

**Independent build-readiness verdict (2026-11-07).** A fresh reviewer (no prior context) verified the
Phase F schema fully backs F30/F31 and rendered a go/no-go verdict on the whole 32-spec set, with
"build-ready" defined as *no Blockers and no Majors (Minors acceptable)*. It found one Major — the
F29/F31 fold-in P0 work was announced in Phase F prose but missing from the M9/M11/M16 task
lists/DoDs and this tracker, so a per-milestone builder would skip it. That is now wired in (roadmap
M9/M11/M16 + the checklist above), clearing the Major. The remaining items were Minors, addressed in
the same pass (Phase F schema: `new`-endpoint identity, multi-step/identity proof columns, split
migrations, blob-GC walk; plus doc cross-refs). With the Major fixed, the independent bar is met.

What is **not** verified here: the Swift code compiles/tests (no toolchain in the authoring
container — CI is the gate, see the caveat above), and spec implementation-note API hints are
best-effort guidance, not proven against the libraries; the acceptance tests are the source of truth
for behavior.

## Milestone checklist (summary — details in docs/03-roadmap.md)

- [ ] M0 — Scaffolding (repo layout, Package.swift, project.yml, Makefile, CI, empty app window)
- [ ] M1 — Core model + raw HTTP/1 engine
- [ ] M2 — Plain-HTTP proxy, storage, history UI
- [ ] M3 — TLS interception + CA + HTTP/2
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

## How to pick up work (reminder)

1. Read `CLAUDE.md` §1 (reading order) and this file.
2. Open the active milestone in `docs/03-roadmap.md`; read the referenced feature spec(s) and their
   requirement IDs.
3. Implement P0 first, tests naming requirement IDs; run `make test` + `make lint`; keep the core
   modules building on Linux.
4. Tick the box here, add a log line (date, what, any deviation), and commit referencing the IDs.
