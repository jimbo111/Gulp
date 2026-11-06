# F13 — Comparer

> Milestone: M7 · Modules: `GulpDiff`, `GulpFeatures/Comparer` · Depends on: GulpCore

## 1. Purpose

The Comparer shows the differences between two pieces of data (two responses, two requests, or
arbitrary text/bytes). Testers use it to spot subtle changes: how a response differs between a valid
and invalid input, between two users, or before and after a payload.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| CMP-001 | P0 | A list of items to compare; "Send to Comparer" adds a request or response (or paste/load). Pick any two to diff. |
| CMP-002 | P0 | Two diff granularities: **word** (token-level, good for text/HTML) and **byte/character** (precise). Toggle live. |
| CMP-003 | P0 | Visual diff: aligned side-by-side and unified views, with added/removed/changed segments colored; a summary (N modifications, M added, K deleted) and next/prev-change navigation. |
| CMP-004 | P0 | Handle large inputs (≥1 MB) within the performance budget (doc 01 §9) without freezing; computation off-main with progress for very large diffs. |
| CMP-005 | P1 | Pre-diff transforms: decode content-encoding, pretty-print JSON/XML/HTML, ignore-whitespace, ignore-case, and "sync scroll" — each a toggle applied before diffing. |
| CMP-006 | P1 | Diff two full exchanges (request+response) and also quick "diff with previous response" from Repeater (UI-030 reused). |
| CMP-007 | P2 | A hex diff mode with offsets; and an "only show changed regions" collapse. |
| CMP-008 | P2 | Export the diff (HTML/patch) and copy either side. |

## 3. UI

Comparer: an items list (label, length, source) on the left; two slots (A/B) to assign; the diff
view below with the granularity toggle, transform toggles, the change summary and navigation.

## 4. Implementation notes

- Implement a Myers O(ND) diff in `GulpDiff` over a generic `Element` so it serves both bytes
  (`UInt8`) and word tokens (`Substring`/ranges). Add a patience/histogram option for large,
  repetitive inputs to produce cleaner alignments.
- For word mode, tokenize into words + whitespace + punctuation so diffs land on meaningful
  boundaries; keep ranges back into the original bytes for precise highlighting.
- Cap work: for inputs above a threshold, first diff by lines to localize changes, then refine
  changed blocks word/byte-level (reduces the DP matrix dramatically).
- Reuse the same `DiffView` component for Repeater's response history diff.

## 5. Edge cases

- Binary data: byte mode only; show a notice and a hex view.
- Different encodings (one gzip, one plain): the decode transform normalizes before diffing.
- Huge, totally-different inputs: avoid the O(N·M) worst case via the line-localize step; show
  progress and allow cancel.

## 6. Acceptance tests

1. Two 1 MB responses differing in a few bytes diff in <1 s and highlight exactly those bytes
   (byte mode) and the containing words (word mode).
2. "Diff with previous response" in Repeater highlights a changed reflected value.
3. Ignore-whitespace + pretty-JSON makes two semantically-equal, differently-formatted JSON bodies
   show as identical.
