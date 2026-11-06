# F14 — Notebook (organizer and notes)

> Milestone: M9 · Modules: `GulpStore`, `GulpFeatures/Notebook` · Depends on: F05

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
| NB-005 | P1 | Link an item to a Scanner issue (and vice versa), so manual and automated findings connect; "promote Notebook item to issue". |
| NB-006 | P1 | Send a Notebook item back to Repeater/Comparer/Fuzzer (it keeps the stored request). |
| NB-007 | P1 | Include selected Notebook items in a report (F19) as manual findings, with their notes and evidence. |
| NB-008 | P2 | Checklists/templates (e.g. an OWASP-style per-endpoint checklist) a tester can instantiate per host. |
| NB-009 | P2 | Attach screenshots or files to an item (stored as blobs). |

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

## 5. Edge cases

- The original exchange is deleted → the Notebook snapshot still shows fully.
- Very large saved responses → store capped like elsewhere, with a truncation flag.
- Markdown with embedded scripts/links → sanitized on render.

## 6. Acceptance tests

1. ⌘⇧N on a history row creates an item with the exact request/response; editing later history
   doesn't change the saved snapshot.
2. Setting status and tags persists; filtering by status works; the item survives project reopen.
3. "Include in report" adds the item as a manual finding with its note and evidence.
