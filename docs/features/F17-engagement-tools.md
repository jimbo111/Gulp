# F17 — Engagement tools (merged)

> Milestone: none — merged into other specs on 2026-11-08 · Modules: none of its own (was
> `GulpFeatures/Engagement`) · Was scheduled: M16 · Depends on: F05, F06, F07

## 1. Purpose

**Merged (2026-11-08 feature review, `docs/FEATURE-REVIEW.md` §3.3; product decision #7 in
`docs/07-decisions.md`).** F17 was a grab-bag of small utilities. Three of them duplicated
requirements that already existed elsewhere; the rest now live in the spec of the tool they extend,
so each ships with that tool instead of waiting for M16. The requirement IDs are unchanged, so
existing references keep working. This file stays as the record of where each requirement went.

## 2. Requirements

### 2.1 Where each requirement went

| New home | Requirements (original IDs kept) | Milestone now |
|---|---|---|
| F07 Fuzzer §2.5 (content discovery as a Fuzzer mode) | ETL-003 | M8 |
| F27 JS Recon Studio §2 (scripts/comments extraction, folded into the JS asset inventory) | ETL-004 | M19a |
| F21 Automation §2.4 (task scheduler) | ETL-006, ETL-010 | M17 |
| F19 Reporting §2.2 (CSRF PoC generator, the "small CSRF PoC" the review kept) | ETL-007 | M16a |
| doc 05 §4 `SendToMenu` (UI-040) — "Copy as" serializers | ETL-008 | M4a |
| F06 Repeater §2 (request builder, browser-like request) | ETL-009, ETL-011 | M5 |

### 2.2 Cut requirements

These duplicated existing requirements and are not built separately. The rows stay so references
resolve.

| ID | Pri | Requirement |
|---|---|---|
| ETL-001 | P0 | **Cut (2026-11-08 feature review)** — duplicate of F05 HIS-050 (global search, grouped results). Project-wide search is HIS-050/HIS-051. |
| ETL-002 | P0 | **Cut (2026-11-08 feature review)** — duplicate of F05 HIS-053 ("Find references"). |
| ETL-005 | P1 | **Cut (2026-11-08 feature review)** — duplicate of F04 TGT-008 ("Analyze target" panel). |

## 3. UI

None of its own. The moved tools appear in their home tools' UI (the Fuzzer's content-discovery
mode, the Reports tool's CSRF PoC generator, the Automation scheduler, the Send-to menu's "Copy as").

## 4. Implementation notes

See the new home specs. The `RequestExport` serializer helper (Copy as) is described with UI-040 in
doc 05 §4; the scheduler's persistence (a `SchedulerSettings` group in the `settings` table) is in
F21 §4.

## 5. Edge cases

See the new home specs.

## 6. Acceptance tests

Moved with their requirements: content discovery → F07 §6, CSRF PoC → F19 §6, Copy as → F01 §6,
scheduled scan → F21 §6.
