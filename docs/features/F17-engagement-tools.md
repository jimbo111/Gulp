# F17 — Engagement tools

> Milestone: M16 · Modules: `GulpFeatures/Engagement`, small helpers in engines · Depends on: F05, F06, F07

## 1. Purpose

A collection of small, high-value utilities testers reach for constantly. Each is accessible from
the "Engagement tools ▸" context menu (UI-040) and/or its own panel.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| ETL-001 | P0 | **Search** (project-wide): the global FTS/regex search (F05 HIS-050) surfaced as an engagement tool with grouped results and export. |
| ETL-002 | P0 | **Find references**: given a selected value (token, filename, parameter), find every request/response in the project that contains it (F05 HIS-053). |
| ETL-003 | P0 | **Discover content**: a guided content-discovery run (directory/file brute force) seeded from a URL, using wordlists + observed extensions, recursive, scope-gated — effectively a specialized Fuzzer config with a tree-style results view of found paths (status, length). |
| ETL-004 | P1 | **Find scripts/comments**: extract all JavaScript files and HTML comments seen for a host (useful for secrets/endpoints); link to the secret scanner (F23). *(The extraction is M16; the secret-scanner link activates when F23/M19 lands — later: M19.)* |
| ETL-005 | P1 | **Analyze target**: the per-host analysis panel (F04 TGT-008) — dynamic URLs, parameters, interesting observations. |
| ETL-006 | P1 | **Schedule tasks**: run a scan/crawl/fuzz at a time or on an interval, and auto-pause/resume; a simple scheduler with a task list (useful for long engagements). |
| ETL-007 | P1 | **Generate CSRF PoC**: from a request, generate an HTML form/fetch PoC that reproduces it cross-site (auto-handles method, params, content-type: form, multipart, or a fetch for JSON with the right mode), with options (auto-submit, include cookies note). Export HTML. |
| ETL-008 | P1 | **Copy as**: cURL, PowerShell, fetch (JS), Python requests, Go — from any request (part of UI-040, centralized here). |
| ETL-009 | P2 | **Manual request builder**: start a Repeater request from scratch (method/URL/headers templates). |
| ETL-010 | P2 | **Task scheduler notifications** via macOS notifications (UI-090) when scheduled tasks finish or find high-severity issues. |
| ETL-011 | P2 | **Simulate a browser request**: build a realistic request (headers, order, UA) for a given URL to compare against what the app expects. |

## 3. UI

An "Engagement tools" section with the panels (Discover content results tree, CSRF PoC generator,
Scheduler) and the ubiquitous context-menu entries. Discover-content and schedule runs show up as
Dashboard tasks.

## 4. Implementation notes

- Content discovery and "copy as" reuse existing engines (Fuzzer engine + wordlists; a request→code
  serializer). Keep the serializers in a small `RequestExport` helper used by UI-040 everywhere.
- CSRF PoC generator inspects the request's method/content-type to choose the right shape:
  - form-urlencoded / multipart / text-plain bodies → an auto-submitting HTML `<form>` (these are
    CORS "simple" content types and need no preflight) — the reliable, classic CSRF PoC.
  - A body that *requires* `Content-Type: application/json` → a simple form or `no-cors` fetch
    **cannot** set that header (no-cors restricts Content-Type to the simple set, and a custom type
    triggers a CORS preflight), so such an endpoint is generally **not** CSRF-able via a cross-site
    PoC. The generator must say exactly that (and why — preflight), rather than emit a `no-cors`
    JSON fetch that silently won't send the JSON body. It emits a working `fetch` PoC only when the
    endpoint accepts a simple content type, or when observed CORS (`Access-Control-Allow-Origin` +
    credentials) actually permits the cross-site request.
- Scheduler is a lightweight actor persisting scheduled jobs in the project; it drives existing task
  APIs. Don't over-engineer — time/interval triggers only.

## 5. Edge cases

- Content discovery must respect scope and throttle; warn on large wordlists.
- CSRF PoC for JSON endpoints that require a custom header → explain it's likely *not* CSRF-able and
  say why (preflight), rather than emitting a PoC that won't work.
- Scheduled runs while the app is closed → document that the app must be running (no background
  daemon in v1).

## 6. Acceptance tests

1. "Discover content" on VulnLab finds the hidden `/admin` and backup files present in the fixtures;
   results show as a path tree with statuses; scope is honored.
2. "Generate CSRF PoC" for a VulnLab state-changing form produces an auto-submitting HTML PoC that,
   when loaded through the Gulp Browser, reproduces the request.
3. "Copy as cURL/Python/fetch" produces runnable snippets that reproduce a request (verified against
   `/echo`).
4. A scheduled scan starts at the set time and notifies on completion.
