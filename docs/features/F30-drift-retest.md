# F30 — Drift & Retest (baselines, regression, remediation tracking)

> Milestone: M25 (the core only needs F06/F08/F13, so it can be built earlier if desired) · Modules: `GulpFeatures/Drift` + helpers in
> `GulpHTTP`/`GulpStore` · Depends on: F03, F04, F06, F08, F13, F15, F17, F19, F21

## 1. Purpose

Engagements run in find → fix → verify cycles, and apps change over time, but Gulp today can't
**retest** a finding or detect **drift**. This captures a reproducible proof per issue (the exact
request(s) + the matcher that proved it) and a named **baseline** of selected endpoints
(request/response + derived facts), then re-runs them on demand to mark each issue/endpoint
Fixed / Still-Vulnerable / Changed / New / Removed, with history across rounds. It closes the loop
that F08 (find) and F19 (report) leave open, and goes beyond the one-shot Comparer (F13), the static
site-map compare (F04 TGT-010) and the single-report delta (F19 RPT-011) by adding *time* and
*persistence*.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| DRF-001 | P0 | Create a **baseline** from a selection (Target branch, GulpQL result set, Notebook items, or a scan's covered endpoints): store an immutable snapshot per endpoint (raw request/response bytes + extracted facts: status, headers, security-header set, param list, body hash) with a name, timestamp and the scope used. |
| DRF-002 | P0 | **Re-run** a baseline: re-issue each stored request through `GulpHTTP` (ScopeGuard-gated, Governor-limited F29) and record a new linked sample set. To detect **new/removed** endpoints (DRF-004), a re-run optionally re-enumerates the baseline's scope (site-map/crawl delta) and records appeared/disappeared endpoints as `drift_results` rows carrying their own `target_json`. |
| DRF-003 | P0 | **Retest proof per issue**: store, per F08 issue, a replayable proof (originating request(s)/insertion point + the matcher/extractor that confirmed it, auto-captured from Scanner/Repeater/Recipes or user-attached). |
| DRF-004 | P0 | **Verdicts**: re-running an issue's proof computes Fixed / Still-Vulnerable / Changed / Needs-Review with new evidence attached; re-running a baseline marks each endpoint Unchanged / Changed / New / Removed / Error, with a per-field breakdown opened in `DiffView` (UI-030). |
| DRF-005 | P0 | **History** per issue and per baseline (round, date, verdict, evidence); surface status in the issue list and in reports (F19) as a "remediation status" column. |
| DRF-006 | P1 | **Noise masking**: regex/JSONPath masks for volatile fields (dates, nonces), reusing F13 pre-diff transforms, with a "learn mask from two unchanged runs" helper. Masks are stored per endpoint (`drift_endpoints.mask_json`); a baseline-wide mask is applied as the default to each endpoint at capture time (there is no separate baseline-level mask column — per-endpoint is the superset). |
| DRF-007 | P1 | **Schedule** re-runs via the engagement scheduler (F17 ETL-006); notify (UI-090) only when drift exceeds a threshold or a fixed issue regresses. |
| DRF-008 | P1 | Authenticated proofs/baselines re-auth correctly via identities/sessions (F15). |
| DRF-009 | P1 | **Headless** via CLI/REST (F21): `gulp retest --project f.gulp --fail-on regression` exits non-zero when a previously-fixed issue is vulnerable again; SARIF/JSON includes remediation status. |
| DRF-010 | P2 | Import an external baseline (from another `.gulp` or a JSON export) to diff "their environment vs mine"; a client-facing retest report section summarizing round-over-round progress. |

## 3. UI

A Drift tool: a baselines list (name, endpoint count, last run, drift count sparkline); a run view
(per-endpoint status table → DiffView on select); and an issue-retest surface (run proof(s), see
verdict + history) that also shows as a status column in the Dashboard issue list and in reports.

## 4. Implementation notes

- Persistence is a **new additive schema** (doc 04 §4 "Post-1.0 expansion tables", the `v3_drift` migration):
  `drift_baselines`/`drift_endpoints` hold the immutable per-endpoint snapshots (DRF-001),
  `drift_runs`/`drift_results` the per-run verdicts (DRF-004), and `issue_proofs`/`retest_runs` the
  per-issue proof and retest history (DRF-003/005). Snapshots are blobs + facts JSON, independent of
  live history so later traffic/deletion can't change them (same discipline as Notebook, F14).
- The retest **verdict axis** (Fixed / Still-Vulnerable / Changed / Needs-Review) lives in
  `retest_runs`, orthogonal to `issues.status` (open/false_positive/accepted_risk/fixed): a
  Still-Vulnerable or Fixed verdict can *update* `issues.status`, it does not replace it.
- Re-run reuses the Repeater/engine send path; verdict logic compares new evidence to the stored
  proof's matcher (issue) or to the baseline snapshot (endpoint), applying masks first.
- Schedules and notifications reuse F17; headless retest reuses the F21 service layer. The only new
  persistence is the tables above; no new engine primitives.

## 5. Edge cases

- Volatile endpoints → masks (DRF-006); if still noisy, mark Needs-Review rather than a false
  Changed/Fixed.
- An endpoint that 404s on re-run → Removed, not Fixed (distinguish "gone" from "patched").
- Auth expiry between rounds → re-auth via F15 before concluding.
- A proof that can't be re-run (e.g. a one-time token) → Needs-Review with a clear reason.

## 6. Acceptance tests

1. A VulnLab issue's proof re-run after the endpoint is patched returns "Fixed" with the new
   (now-safe) evidence; before patching it returns "Still-Vulnerable".
2. Across two captures the baseline diff lists a newly-added endpoint and a resolved issue correctly,
   and masks suppress a per-response nonce (Unchanged).
3. Removing HSTS on one endpoint produces exactly one Changed row categorized "security headers".
4. `gulp retest --fail-on regression` exits non-zero when a previously-fixed issue is vulnerable
   again.
