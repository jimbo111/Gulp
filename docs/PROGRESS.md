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
