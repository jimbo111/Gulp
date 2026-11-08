# F30 — Drift & Retest (baselines, regression, remediation tracking) (merged)

> Milestone: none — merged into F08 and F21 on 2026-11-08 · Modules: none of its own (was
> `GulpFeatures/Drift`) · Was scheduled: M25 (post-1.0) · Depends on: F08, F13, F15, F19, F21

## 1. Purpose

**Merged (2026-11-08 feature review, `docs/FEATURE-REVIEW.md` §3.3; product decision #7 in
`docs/07-decisions.md`).** The valuable part of this spec — a replayable proof per issue and a
retest verdict history — is an extension of the Scanner's issue model, so it moved to **F08 §2.4**,
with the headless `gulp retest` command in **F21 §2.4**. The endpoint **baselines** (snapshot a set of
endpoints and diff them over time) were cut: the Comparer (F13), the site-map compare (F04 TGT-010)
and the report delta (F19 RPT-011) cover the occasional need. Retest stays **post-1.0**: the
roadmap's M25 milestone schedules it. The requirement IDs are unchanged.

## 2. Requirements

### 2.1 Where each requirement went

| New home | Requirements (original IDs kept) | Milestone now |
|---|---|---|
| F08 Scanner §2.4 (retest proof, verdicts, history — issue part only) | DRF-003, DRF-004, DRF-005 | M25 |
| F21 Automation §2.4 (headless `gulp retest`) | DRF-009 | M25 |

### 2.2 Cut requirements

| ID | Pri | Requirement |
|---|---|---|
| DRF-001 | P0 | **Cut (2026-11-08 feature review).** Was: create a named, immutable **baseline** snapshot of selected endpoints (request/response + extracted facts). |
| DRF-002 | P0 | **Cut (2026-11-08 feature review).** Was: re-run a baseline (scope-gated), optionally re-enumerating its scope to find new/removed endpoints. |
| DRF-006 | P1 | **Cut (2026-11-08 feature review).** Was: noise masks (regex/JSONPath) for volatile fields in baseline diffs. Retest verdicts use the stored matcher instead (F08 DRF-004); F13's pre-diff transforms remain for manual comparison. |
| DRF-007 | P1 | **Cut (2026-11-08 feature review).** Was: scheduled baseline re-runs with drift-threshold notifications. (A retest can still be scheduled as a task through F21 ETL-006.) |
| DRF-008 | P1 | **Cut (2026-11-08 feature review).** Was: dedicated re-auth for proofs/baselines. Proof replays go through the engine, so the normal session-handling rules (F15) already apply. |
| DRF-010 | P2 | **Cut (2026-11-08 feature review).** Was: import an external baseline and a round-over-round retest report section. |

## 3. UI

None of its own: retest is run from an issue (or a multi-selection of issues), and the verdict shows
as a "remediation status" column in the issue list and in reports.

## 4. Implementation notes

Persistence is the post-1.0 `issue_proofs` and `retest_runs` tables (doc 04 §4, "Post-1.0 expansion
tables"); the `drift_*` baseline tables are cut and are not created. The retest verdict axis lives in
`retest_runs`, orthogonal to `issues.status`: a verdict can *update* `issues.status`, it does not
replace it.

## 5. Edge cases

Carried into F08 §2.4: an endpoint that 404s on re-run is Needs-Review ("gone" is not "patched"); a
proof that can't be re-run (a one-time token) is Needs-Review with a reason; auth expiry is handled by
the session rules before concluding.

## 6. Acceptance tests

Test 1 → F08 §7 (retest, post-1.0); test 4 → F21 §6. Tests 2 and 3 exercised the cut baselines and
are dropped. The VulnLab fixture (a vulnerable→patched toggle) is in doc 06 §3.1 (M25 row).
