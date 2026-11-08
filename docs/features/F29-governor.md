# F29 — Governor (global resource control + panic stop) (merged)

> Milestone: none — merged into F03 and F20 on 2026-11-08 · Modules: none of its own (was
> `GulpFeatures/Governor`) · Was scheduled: core in M11, full panel in M16 · Depends on: F03, F20

## 1. Purpose

**Merged (2026-11-08 feature review, `docs/FEATURE-REVIEW.md` §3.3; product decision #7 in
`docs/07-decisions.md`).** F03 HTTP-013 already specified the shared global + per-host token bucket,
so the Governor's limiter is now that requirement, extended in **F03 §3.4**. The panic stop and the
throughput panel are workspace controls in **F20 §2.4**. The settings-heavy extras (watchpoints,
quiet hours, dry-run preview, layered caps) were cut. The requirement IDs are unchanged, so existing
references keep working.

## 2. Requirements

### 2.1 Where each requirement went

| New home | Requirements (original IDs kept) | Milestone now |
|---|---|---|
| F03 HTTP engine §3.4 (shared limiter: global/per-host caps, adaptive backoff) | GOV-002, GOV-003, GOV-007 | M11a |
| F20 Projects & settings §2.4 (panic stop) | GOV-001 | M11a |
| F20 Projects & settings §2.4 (live throughput panel) | GOV-006 | M16b |

### 2.2 Cut requirements

| ID | Pri | Requirement |
|---|---|---|
| GOV-004 | P1 | **Cut (2026-11-08 feature review).** Was: resource watchpoints — pause active tasks and warn when project size, free disk or app memory cross thresholds (PRJ-010 retention and the F20 §5 disk-full handling cover the essential case). |
| GOV-005 | P1 | **Cut (2026-11-08 feature review).** Was: quiet hours / windows during which active tools auto-pause, integrated with the scheduler (F21 ETL-006). |
| GOV-008 | P2 | **Cut (2026-11-08 feature review).** Was: dry-run / preview of request count and time for any active tool before launch. |
| GOV-009 | P2 | **Cut (2026-11-08 feature review).** Was: caps as layered settings with a cautious user default. (Caps are ordinary Settings → Network values, which PRJ-020 already layers.) |

## 3. UI

The panic stop is a toolbar item and ⌃. (F20 GOV-001); the throughput readout is in the status bar
and Dashboard (F20 GOV-006); caps and per-host overrides are in Settings → Network.

## 4. Implementation notes

See F03 §4 ("Shared limiter").

## 5. Edge cases

See F03 §4 and F20 GOV-001 (the panic stop pauses sending, not the store's write coalescer).

## 6. Acceptance tests

Moved with their requirements: tests 1, 2 and 4 → F03 §6 (tests 6 and 7); test 3 (panic stop) →
F20 §6 (test 5).
