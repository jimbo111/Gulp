# F31 — Journal (engagement timeline, coverage map & "where was I") (merged)

> Milestone: none — merged into F04 and F14 on 2026-11-08 · Modules: none of its own (was
> `GulpFeatures/Journal`) · Was scheduled: coverage index in M9, full tool in M16 · Depends on: F04, F05, F08, F14

## 1. Purpose

**Merged (2026-11-08 feature review, `docs/FEATURE-REVIEW.md` §3.3; product decision #7 in
`docs/07-decisions.md`).** Coverage is a property of the site map, so the coverage index and view
moved to the Target spec (**F04 §2.3**). The activity timeline, the "resume" card and timeline markers
are the tester's working memory, so they moved to the Notebook (**F14 §2**). The treemap, the
per-endpoint methodology checklists and the effort rollup were cut. The requirement IDs are
unchanged, so existing references keep working.

## 2. Requirements

### 2.1 Where each requirement went

| New home | Requirements (original IDs kept) | Milestone now |
|---|---|---|
| F04 Target §2.3 (coverage index) | JRN-001 | M9 |
| F04 Target §2.3 (coverage view and "untested" filters) | JRN-002 | M16b |
| F14 Notebook §2 (activity timeline, resume card, markers, report appendix) | JRN-003, JRN-005, JRN-008, JRN-009 | M16b |

### 2.2 Cut requirements

| ID | Pri | Requirement |
|---|---|---|
| JRN-004 | P1 | **Cut (2026-11-08 feature review).** Was: an attack-surface treemap/heatmap (hosts → endpoints sized by traffic, colored by coverage or severity). |
| JRN-006 | P1 | **Cut (2026-11-08 feature review).** Was: per-endpoint coverage goals/methodology checklists. (Notebook checklists, F14 NB-008, remain the lightweight option.) |
| JRN-007 | P1 | **Cut (2026-11-08 feature review).** Was: an approximate time/effort rollup per host/day from activity gaps, exportable to CSV. |

## 3. UI

None of its own: coverage badges and filters are in the Target tool; the timeline and the resume
card are in the Notebook tool.

## 4. Implementation notes

See F04 §4 (coverage index: derived, no table) and F14 §4 (timeline; markers use `journal_markers`).
The `journal_checklists` table (JRN-006) is cut and is not created (doc 04 §4).

## 5. Edge cases

See F04 (huge site maps; "touched" vs "tested") and F14.

## 6. Acceptance tests

Tests 1 and 2 → F04 §6 (test 5); test 3 (resume card) → F14 §6 (test 4); test 4 (treemap color)
exercised the cut treemap and is dropped.
