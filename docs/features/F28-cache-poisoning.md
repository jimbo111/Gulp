# F28 — Web Cache Poisoning & Deception Scanner (merged)

> Milestone: none — merged into F08 on 2026-11-08 · Modules: none of its own (was
> `GulpFeatures/CacheProbe`) · Was scheduled: M24 (post-1.0) · Depends on: F03, F08, F10, F13, F23

## 1. Purpose

**Merged (2026-11-08 feature review, `docs/FEATURE-REVIEW.md` §3.3; product decision #7 in
`docs/07-decisions.md`).** Cache poisoning and cache deception are a Scanner check family, not a
separate tool. All requirements moved to **F08 §3.5** with their IDs unchanged, including the
victim-safe probing rule (per-run unique cache keys). The family stays **post-1.0**: the roadmap's
M24 milestone schedules it.

## 2. Requirements

### 2.1 Where each requirement went

| New home | Requirements (original IDs kept) | Milestone now |
|---|---|---|
| F08 Scanner §3.5 (cache poisoning & deception family) | WCP-001, WCP-002, WCP-003, WCP-004, WCP-005, WCP-006, WCP-007, WCP-008 | M24 |

No requirement was cut.

## 3. UI

None of its own: the family is enabled in a scan configuration (opt-in) and its findings are Issues.
The confirmation workbench (WCP-008, P2) opens from an issue.

## 4. Implementation notes

See F08 §3.5. Probes draw from the shared limiter (F03 §3.4) and are scope-gated like every active
check.

## 5. Edge cases

See F08 §3.5 (TTL races, `Vary`, shared production caches, reflection vs cached reflection).

## 6. Acceptance tests

Moved to F08 §7 ("Cache family", post-1.0). The VulnLab fixtures are in doc 06 §3.1 (M24 row).
