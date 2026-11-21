# Review dossier — Gulp specification set

> **Snapshot, not current status.** `docs/PROGRESS.md` is authoritative for what is built; it
> records the pre-code review of the spec set (2026-11-07/08). The "no toolchain" and C1/CI notes
> describe that authoring environment; the code now builds and tests on Linux and macOS.

This records the review the spec set went through, so the "build-ready" judgment is a durable,
auditable artifact rather than a claim. It covers **the Markdown specs** (32 feature specs, core docs
00–07, roadmap, schema, decisions, test strategy). It does **not** cover compiling the Swift code —
see "Scope boundary" below.

## Objective standard used

"Nearly perfect for a Claude agent to build from" is subjective, so the set is held to the concrete,
reproducible **Documentation Definition of Done (D1–D16)** in [`PROGRESS.md`](PROGRESS.md#documentation-definition-of-done-the-objective-build-ready-bar).
Each criterion names how it is measured (mostly pure-Python checkers over the Markdown). A criterion
is MET only if its stated check passes. Current result: **D1–D16 MET**; the code-compile criterion
**C1 is out of scope here** (see below).

## Independent reviews run (fresh-eyes agents, no shared context)

Each row is a separate review agent that read the files itself and rendered a verdict. Findings were
fixed; the later rows re-verify earlier fixes.

| Review | Scope | Verdict / outcome |
|---|---|---|
| Core docs (00–07) | contradictions, dangling refs, schema, build instructions | Found 4 majors (layering/manifest M0, H2RequestSpec Codable, M1 DoD `:8443`, SNIHandler module) → all fixed |
| Specs F01–F12 | per-spec defects, cross-refs, milestone order | Found majors (M1 DoD, F06→F04, F12→F10 forward deps) + minors → all fixed |
| Specs F13–F24 | same | Found a blocker (F22↔F21 layering) + majors (F14/F17 forward deps, settings panes) → all fixed |
| Networking deep (F01/F02/F03) | SwiftNIO/TLS/HTTP2 API correctness | Found majors (ALPN-not-from-SNIHandler, context-cache key, raw-H2 validation, 502-pre-connect) → all fixed |
| Scanning deep (F07/F08/F09/F10) | detection methodology soundness | Found majors (passive-test determinism, boolean-SQLi/open-redirect/CRLF methodology, interactsh tokens) → all fixed |
| Specs F25–F32 | new post-1.0 specs vs v1 | Found majors (F29↔HTTP-013, F26↔REP-012 dup, F30 schema gap, F27 module/Linux) → all fixed |
| Phase F schema + go/no-go | doc 04 Phase F tables vs F30/F31 | Schema PASS; one Major (F29/F31 fold-ins not wired into M9/M11/M16 DoDs) → fixed |
| Final panel A (holistic) | whole set buildability | **BUILD-READY (no Blockers/Majors)** |
| Final panel B (adversarial) | worst remaining problem | v1 clean; one Phase-F Major (undefined VulnLab fixtures) → fixed (doc 06 §3.1) |
| Fixture re-verify | doc 06 §3.1 vs Phase F acceptance tests | **FIX COMPLETE** — every acceptance test maps to a defined/scoped fixture |
| Rubric audit | re-derive D1–D16 independently | **14/16 verified + BUILD-READY**; caught D8/D15 over-claims → fixed |
| D8/D15 re-verify | the two fixes above | **BOTH FIXED, NO REGRESSIONS** (all M0–M26 have a DoD; tables well-formed) |
| Build dry run (M1) | implement M1 from the docs | **BUILDABLE, no Blockers**; 2 undefined public types + referenced-only types → defined |
| Build sweep (M3–M14) | can each core milestone be built from the docs | **ALL BUILDABLE** |
| Build sweep (M15–M26) | can each remaining milestone be built from the docs | **ALL BUILDABLE**; 2 cosmetic minors → fixed |
| Holistic, own-standard | reviewer's *own* definition of "nearly perfect for an AI agent to build from" (no rubric given) | **VERDICT: NEARLY PERFECT FOR BUILDING** — no blocking issues; only the inherent "Swift not compiled here" (CI's job) |

**Net:** every Blocker and Major any reviewer raised was fixed, and the findings were independently
re-verified. Constructive "build it from the docs" confirmation spans the whole roadmap M0–M26, and a
final reviewer judging against its *own* standard of "nearly perfect for building" returned exactly
that. No remaining Blockers or Majors.

## Automated consistency checks (re-run after every edit; all green)

516 requirement IDs, 0 duplicate, 0 dangling · all relative links / `Fxx` / `Mxx` references resolve ·
`## N`/`### N.M` numbering has no gaps or dupes · every `Fxx §N` / `doc NN §N` cross-ref resolves ·
spec-header / README-index / roadmap milestones agree for all 32 features · every `make` target
referenced exists · all Markdown tables well-formed · aspell (code/URLs stripped, verified
technical-terms dictionary) reports no misspellings.

## Scope boundary (what this review does and does not establish)

- **Does:** the Markdown is internally consistent, complete, and resolvable — a competent agent can
  implement milestone by milestone, with each acceptance test pointing at a defined fixture and each
  persisted requirement backed by a schema table. Independent reviewers concur: no Blockers/Majors.
- **Does not:** prove the generated Swift compiles/passes tests (criterion **C1**). This was **not
  skipped by choice — it is impossible in this container, verified by live probe (2026-11-07):** there
  is no Swift toolchain installed, the apt "swift" package is OpenStack's object store (not the
  language), and the language toolchain is distributed only from `download.swift.org`, which the
  sandbox proxy blocks — fetching both the `swift-6.0-RELEASE-ubuntu24.04.tar.gz` toolchain and the
  swiftly installer returns `403 CONNECT tunnel failed` (only `swift.org`, the marketing site, is
  allowlisted). So `swift build`, `swift test` and `xcodebuild` cannot run here by construction. C1
  is a property of the **code produced from** these docs, enforced by CI
  (`.github/workflows/ci.yml`: a Linux `swift build`/`swift test` job on the `swift:6.0-noble` image
  + a macOS `make` job). It is the gate for M0, not a property of the Markdown.
- **Inherent limit:** "nearly perfect" is a subjective bar that cannot be *proven*; the strongest
  available evidence is the objective D1–D16 result plus independent agreement that no Blockers or
  Majors remain. Both are in place.

## Final judgment

By the objective standard (D1–D16) and multiple independent reviews, the documentation set is
**build-ready**: no Blockers, no Majors. The only unmet item, C1 (Swift compiles), is out of scope in
this environment and is CI's job. Next step is implementation: let CI verify the M0 scaffolding, then
build M1 onward following [`CLAUDE.md`](../CLAUDE.md) and [`03-roadmap.md`](03-roadmap.md).

## Documentation Definition of Done (moved from PROGRESS.md on 2026-11-20)

Historical record of the pre-code documentation bar, as written on 2026-11-07/08. The C1 row and the
"no toolchain" notes describe that authoring container: the code has since been built and tested
on Linux and macOS (see `PROGRESS.md`, Current state). Requirement-ID counts below differ (516 vs
544) because they were taken before and after F33 was added.

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
