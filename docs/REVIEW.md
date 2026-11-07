# Review dossier — Gulp specification set

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

**Net:** every Blocker and Major any reviewer raised was fixed, and the final findings were
independently re-verified. The last two independent reviewers (rubric audit, D8/D15 re-verify) both
returned a clean, satisfied judgment.

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
- **Does not:** prove the generated Swift compiles/passes tests (criterion **C1**). There is no Swift
  toolchain in the authoring container and `download.swift.org` is network-blocked, so `swift build`,
  `swift test` and `xcodebuild` cannot run here. C1 is a property of the **code produced from** these
  docs, enforced by CI (`.github/workflows/ci.yml`: a Linux `swift build`/`swift test` job + a macOS
  `make` job). It is the gate for M0, not a property of the Markdown.
- **Inherent limit:** "nearly perfect" is a subjective bar that cannot be *proven*; the strongest
  available evidence is the objective D1–D16 result plus independent agreement that no Blockers or
  Majors remain. Both are in place.

## Final judgment

By the objective standard (D1–D16) and multiple independent reviews, the documentation set is
**build-ready**: no Blockers, no Majors. The only unmet item, C1 (Swift compiles), is out of scope in
this environment and is CI's job. Next step is implementation: let CI verify the M0 scaffolding, then
build M1 onward following [`CLAUDE.md`](../CLAUDE.md) and [`03-roadmap.md`](03-roadmap.md).
