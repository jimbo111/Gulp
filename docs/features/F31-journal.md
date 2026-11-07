# F31 — Journal (engagement timeline, coverage map & "where was I")

> Milestones: M9 (coverage index) and M16 (full coverage/timeline/map tool) · Modules: `GulpFeatures/Journal` ·
> Depends on: F04, F05, F08, F14

## 1. Purpose

A chronological, per-engagement record of what the tester actually did (sent to Repeater, fuzzed,
scanned, noted, flagged) joined to a **coverage view** of the attack surface: which
hosts/endpoints/params have been touched by which tool, and which are untested. The Dashboard shows
*live* tasks/issues/events; the Journal is the *historical + coverage + planning* layer a consultant
uses to plan, track progress, and avoid missing endpoints.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| JRN-001 | P0 | **Coverage index**: per endpoint (from the F04 site map), record which tools have exercised it and last-tested time, derived from the `ToolSource` on exchanges. At its M9 landing the available sources are Repeater/Fuzzer/Notebook; the Scanner (active/passive) columns populate once F08 ships (M10/M11). The index is source-agnostic, so it extends automatically as tools come online. |
| JRN-002 | P0 | **Coverage view**: the Target tree (UI-060) annotated with coverage badges, plus filters "show untested in-scope endpoints" and "show params never fuzzed". |
| JRN-003 | P0 | **Activity timeline**: a reverse-chronological feed of meaningful actions (sends, issues found, notes, scope changes, baselines) grouped by day/host, searchable with GulpQL-style filters. |
| JRN-004 | P1 | **Attack-surface treemap/heatmap** (Swift Charts): hosts → endpoints sized by traffic, colored by coverage or highest issue severity, click-through to the node. |
| JRN-005 | P1 | **"Resume where I left off"**: on project open, a card summarizing the last session (last endpoints touched, open Notebook "Investigating" items, untested in-scope count) with one-click jumps. |
| JRN-006 | P1 | **Coverage goals/checklist per host**: mark required test categories per endpoint (authz, injection, etc.) and track completion — a lightweight methodology tracker (ties to Notebook checklists NB-008 without duplicating the note model). |
| JRN-007 | P1 | **Time/effort rollup**: approximate active-testing time per host/day (from activity gaps) for engagement status, exportable to CSV. |
| JRN-008 | P2 | Pin **milestone markers** on the timeline ("got auth bypass", "client rotated creds") for the report narrative. |
| JRN-009 | P2 | Feed coverage + timeline into reports (F19) as an appendix ("endpoints tested, methodology completeness"). |

## 3. UI

A Journal tool with three views: **Coverage** (the annotated Target tree + untested filters),
**Timeline** (grouped activity feed with filters and pinned markers), and **Map** (the treemap).
A "resume" card appears on project open.

## 4. Implementation notes

- The coverage index is an aggregation over `exchanges.source` + endpoint identity (the audit dedup
  key from F09 works here too); it's derived and rebuildable from the store, so it needs no table.
  The two things that *do* need persistence — per-endpoint checklists (JRN-006) and timeline markers
  (JRN-008) — use `journal_checklists` and `journal_markers` (doc 04 §4 Post-1.0 tables).
- The timeline reads a curated subset of `GulpEvent`/stored actions; keep it cheap by querying the
  store with the existing indexes, not by holding everything in memory.
- Reuse Swift Charts (already used by the Dashboard/Sequencer) for the treemap.
- Pure read/aggregation over data Gulp already stores — no network sends.

## 5. Edge cases

- Huge site maps (100k endpoints) → virtualize the coverage tree; compute coverage incrementally.
- "Touched" vs "meaningfully tested" — a single passive view isn't an active test; categorize by
  tool so coverage isn't overstated.
- Effort rollup is an estimate from activity gaps; label it as such.

## 6. Acceptance tests

1. Sending an endpoint to Repeater then actively scanning it marks both tools covered with correct
   timestamps in the coverage index.
2. The "untested in-scope" filter lists only endpoints with no recorded tool activity.
3. The resume card's "untested in-scope" count matches the coverage index after a fixture crawl.
4. A host with one High issue renders at the High color in the treemap.
