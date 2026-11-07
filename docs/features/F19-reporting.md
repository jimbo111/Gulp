# F19 — Reporting

> Milestone: M16 · Modules: `GulpReport`, `GulpFeatures/Reports` · Depends on: F08, F14

## 1. Purpose

Turn findings (Scanner issues + Notebook manual findings) into a clear, shareable report. Reports
are the deliverable of an engagement, so they must look professional, be self-contained, and support
machine-readable formats for CI and ticketing.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| RPT-001 | P0 | Select what to include: by issue severity/confidence/status, by host, selected issues, and selected Notebook items (manual findings). Preview the selection. |
| RPT-002 | P0 | **HTML report** (self-contained, offline): title/metadata, executive summary with counts and a severity chart, scope statement, a findings list and per-finding detail (description, severity/confidence, affected location(s), evidence with the request/response and highlighted markers, reproduction, remediation, references). Clean print/PDF styling. |
| RPT-003 | P0 | **Markdown** and **JSON** exports of the same content; **SARIF 2.1.0** export for CI/code-scanning integration. |
| RPT-004 | P0 | Evidence rendering: include the relevant request/response excerpts with marker highlights; options to truncate large bodies and to redact (RPT-010). |
| RPT-005 | P1 | Templates/branding: logo, title, author/company, an editable executive-summary and per-issue-type boilerplate; a couple of built-in themes (light/print). Save template presets. |
| RPT-006 | P1 | Severity model configurable (names/colors/order) and an optional CVSS 3.1/4.0 vector + score per issue (a small calculator UI). |
| RPT-007 | P1 | Remediation/background text pulled from the issue-definition catalog (F08 SCN-006), editable per report. |
| RPT-008 | P1 | Group findings by severity, by host, or by issue type; a table of contents and stable anchors. |
| RPT-009 | P1 | PDF output producing a tidy multi-page PDF. **Module split**: `GulpReport` builds the cross-platform formats (HTML/MD/JSON/SARIF) and must compile on Linux (doc 01 §4), so the PDF step — which uses `WKWebView` paginated printing (macOS-only) — lives in `GulpFeatures/Reports`, consuming `GulpReport`'s self-contained HTML. On Linux/CLI, PDF is unavailable (emit HTML and note it); everything else works headless. |
| RPT-010 | P1 | **Redaction**: strip or mask sensitive values (session tokens, credentials, PII) from included evidence via patterns, before export. Show what was redacted. |
| RPT-011 | P2 | Diff/"delta" report vs. a previous report (new/fixed/still-open issues) for retests. |
| RPT-012 | P2 | Ticketing export helpers (e.g. a per-issue Markdown block sized for Jira/GitHub issues) and a CSV. |
| RPT-013 | P2 | AI-assisted drafting of the executive summary and per-issue narratives (F22), clearly marked and user-edited before use. |

## 3. UI

Reports tool: a selection panel (filters + checklist of issues/notes), a template/branding panel, a
live preview, and an Export button (HTML/MD/JSON/SARIF/PDF). A redaction panel lists patterns and a
preview of masked evidence.

## 4. Implementation notes

- Build an intermediate `ReportModel` (metadata + ordered findings + evidence) decoupled from the
  output format; each exporter renders from it (HTML via a templating step, JSON/SARIF via Codable,
  Markdown via a serializer). One model → many formats keeps them consistent.
- HTML must be fully self-contained: inline CSS and any images as data URIs; no external fetches.
  Escape all evidence content; render markers as styled spans over escaped bytes.
- SARIF: map issues to `results` with `ruleId` = issue type id, `level` from severity, `locations`
  with the URL and (where meaningful) region; include `partialFingerprints` from `dedup_key` for
  stable cross-run identity.
- Redaction runs on the `ReportModel` evidence before any exporter sees it; keep the original
  untouched in the project.
- PDF: paginate the HTML with print CSS; verify page breaks don't split evidence blocks badly.

## 5. Edge cases

- Huge evidence bodies → truncate with a clear marker and a note; keep the highlighted region.
- Non-text evidence (binary) → show a hex excerpt around the marker.
- Many findings (hundreds) → the HTML stays navigable (TOC, lazy sections) and the PDF paginates.
- Redaction false negatives → patterns are best-effort; warn that manual review is advised.

## 6. Acceptance tests

1. A VulnLab scan exports a self-contained HTML report that opens offline with correct counts, a
   severity chart, and per-finding evidence with highlighted markers.
2. The SARIF export validates against the 2.1.0 schema and loads in a SARIF viewer; fingerprints are
   stable across two scans of the same target.
3. Redaction masks a session cookie in included evidence; the project's stored exchange is
   unchanged.
4. PDF output is multi-page, with a TOC and no broken evidence blocks.
