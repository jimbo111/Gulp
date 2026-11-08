# F14 — Notebook (organizer and notes)

> Milestones: M9 (Notebook), M16b (engagement timeline, moved from F31) · Modules: `GulpStore`,
> `GulpFeatures/Notebook` · Depends on: F04, F05

## 1. Purpose

A place to stash interesting requests and write notes while testing, so findings aren't lost in the
flood of history. It's the tester's working memory for an engagement and the raw material for the
report (F19).

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| NB-001 | P0 | "Add to Notebook" (⌘⇧N) from any exchange or selection; store a snapshot of the request/response (so later traffic/edits don't change it) with a title, note (markdown) and status (To do / Investigating / Confirmed / Not an issue / Reported). |
| NB-002 | P0 | Notebook view: a list/table of items (title, host/path, status, tags, time) with the item's request/response in the MessageEditor and an editable markdown note beside it. Reorder (drag), delete, and multi-select. |
| NB-003 | P0 | Free-form note items (not tied to a request) for general observations; and per-item tags and highlight color. |
| NB-004 | P1 | Filter/search Notebook (GulpQL-ish over title/note/tags/status) and group by status or host. |
| NB-005 | P1 | Link an item to a Scanner issue (and vice versa), so manual and automated findings connect; "promote Notebook item to issue". *(later: M10a — the issue subsystem is F08/M10a; the `issues`/`issue_evidence` tables exist in schema v1 but Notebook is M9, so the link is wired when F08 lands.)* |
| NB-006 | P1 | Send a Notebook item back to Repeater/Comparer/Fuzzer (it keeps the stored request). |
| NB-007 | P1 | Include selected Notebook items in a report (F19) as manual findings, with their notes and evidence. *(later: M16a — Reporting is F19/M16a; Notebook is M9, so "include in report" activates when F19 lands. The snapshot stored at M9 is what the report later consumes.)* |
| NB-008 | P2 | Checklists/templates (e.g. an OWASP-style per-endpoint checklist) a tester can instantiate per host. |
| NB-009 | P2 | Attach screenshots or files to an item (stored as blobs). |

### Engagement timeline (moved from F31 Journal, 2026-11-08)

| ID | Pri | Requirement |
|---|---|---|
| JRN-003 | P0 | **Activity timeline**: a reverse-chronological feed of meaningful actions (sends, issues found, notes, scope changes) grouped by day/host, searchable with GulpQL-style filters; a "Timeline" view beside the Notebook list. *(Moved from F31; M16b.)* |
| JRN-005 | P1 | **"Resume where I left off"**: on project open, a card summarizing the last session (last endpoints touched, open Notebook "Investigating" items, the untested in-scope count from the coverage index, F04 JRN-001) with one-click jumps. *(Moved from F31; M16b.)* |
| JRN-008 | P2 | Pin **milestone markers** on the timeline ("got auth bypass", "client rotated creds") for the report narrative. *(Moved from F31; M16b.)* |
| JRN-009 | P2 | Feed coverage + timeline into reports (F19) as an appendix ("endpoints tested"). *(Moved from F31; M16b.)* |

## 3. UI

Notebook tool: a filterable list on the left; on the right, the saved request/response (read-only
editor) on top and the markdown note editor (with preview) below; a status/tag bar. A prominent
"New note" and the global ⌘⇧N.

## 4. Implementation notes

- Items live in `notebook_items`; a saved request/response is copied into blobs (snapshot), not
  referenced by exchange id alone, so deletion/compaction of history can't orphan a finding (keep an
  optional back-reference to the original exchange if it still exists).
- Markdown rendered with a small, safe renderer (no raw HTML execution); store the source.
- Promotion to/from issues writes the link in both `notebook_items` and `issue_evidence`.
- The timeline (JRN-003) reads a curated subset of stored actions through the existing indexes, not
  an in-memory copy. Everything except scope changes is reconstructable from timestamped rows; scope
  changes (`GulpEvent.scopeChanged` — `scope_rules` holds only the current rules) are captured as
  `log`/`LogEntry` records so the timeline can show them. Markers (JRN-008) use the
  `journal_markers` table (doc 04 §4, post-1.0 expansion tables, `v2_journal` at M16b).

## 5. Edge cases

- The original exchange is deleted → the Notebook snapshot still shows fully.
- Very large saved responses → store capped like elsewhere, with a truncation flag.
- Markdown with embedded scripts/links → sanitized on render.

## 6. Acceptance tests

1. ⌘⇧N on a history row creates an item with the exact request/response; editing later history
   doesn't change the saved snapshot.
2. Setting status and tags persists; filtering by status works; the item survives project reopen.
3. *(M16a, not M9)* "Include in report" adds the item as a manual finding with its note and
   evidence — this depends on F19 (Reporting) and is validated in M16a, not at Notebook's own M9
   milestone.
4. *(M16b)* Timeline and resume card (moved from F31): after a session of sends, a scan and a note,
   the timeline lists them grouped by day/host; on reopening the project the resume card's
   "untested in-scope" count matches the coverage index after a fixture crawl.
