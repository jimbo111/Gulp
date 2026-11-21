# F20 — Projects and settings

> Milestones: M2 (basics), M6b (import/export service), M11a (panic stop), M16b (polish, throughput
> panel) · Modules: `GulpStore`, `GulpWorkspace`,
> `GulpFeatures/Settings` · Depends on: doc 04

## 1. Purpose

Projects hold all the data for an engagement in one `.gulp` file; settings control behavior at user
and project levels. This spec covers the project lifecycle and the settings system (individual
settings live in each feature's spec and in Settings panes listed in doc 05 §1).

## 2. Requirements

### 2.1 Projects

| ID | Pri | Requirement |
|---|---|---|
| PRJ-001 | P0 | **New temporary project**: start instantly with an in-cache `.gulp` (doc 04 §4); everything works; prompt to save on close (or discard). |
| PRJ-002 | P0 | **New project…** / **Open…** / **Save As…**: a `.gulp` file the user chooses; opening is instant (no import step) because it's the live DB. Recent projects list on the launcher and in the File menu. |
| PRJ-003 | P0 | Robust persistence: WAL + write coalescer (doc 04); a crash leaves at most the last ~50 ms of traffic unsaved; opening a project after a crash recovers cleanly. |
| PRJ-004 | P0 | Multiple projects open at once, each in its own window with its own `ProjectSession`. |
| PRJ-005 | P0 | "Use settings from…": start a project with a chosen settings profile (default, or import from a file/another project). |
| PRJ-006 | P1 | Project metadata (name, notes, created/modified, engagement scope summary) editable in a Project Info panel. |
| PRJ-007 | P1 | **Compact** (vacuum + drop unreferenced blobs) and **Rebuild indexes** (site map/FTS) actions; show project size and a breakdown (exchanges, blobs, FTS). |
| PRJ-008 | P1 | Import/merge: bring exchanges/issues from another `.gulp`, a HAR, or saved items into the current project (dedup-aware). *(The project-menu entry point of the shared import/export service, PRJ-012.)* |
| PRJ-009 | P1 | Auto-save-as reminder for long temporary sessions; optional periodic checkpoint. |
| PRJ-010 | P2 | A size cap/retention policy (e.g. cap proxy history to N items or M GB, evicting oldest non-flagged, never evicting flagged/Notebook items). |
| PRJ-011 | P2 | Open a project read-only; and a lightweight "project viewer" via the CLI (`gulp open --readonly`). |

### 2.2 Settings

| ID | Pri | Requirement |
|---|---|---|
| PRJ-020 | P0 | **Layered settings** (doc 04 §6): default → user → project override, with a clear "Applies to: User/Project" control per group in each Settings pane. |
| PRJ-021 | P0 | Settings panes — the canonical list is doc 05 §1: General, Proxy, TLS, Network, HTTP, Scanner, Beacon, Browser, Extensions, Automation, AI, Appearance, Shortcuts, Updates, Diagnostics. (Automation hosts the REST/MCP controls of F21 §3; Updates hosts Sparkle, F24 MAC-026.) Each reads/writes its `SettingsGroup`. |
| PRJ-022 | P0 | **Export/Import settings** as JSON (whole or per group); versioned with safe decoding of unknown/missing keys (fallback to defaults). |
| PRJ-023 | P1 | Reset-to-default per group and globally; a search box over all settings. |
| PRJ-024 | P1 | First-run experience: the authorized-testing acknowledgment (doc 00 §6), CA setup prompt, and an offer to install the CA / open the browser. |
| PRJ-025 | P1 | Diagnostics: log level, a "collect diagnostics bundle" action (logs + non-sensitive config), and performance counters. |
| PRJ-026 | P2 | Settings sync via a user-chosen file location (no cloud by default). |

### 2.3 Import and export (one service, 2026-11-08)

HAR/collection import used to be specified five times (HIS-044, PRJ-008, TGT-009, ADV-051, AUT-004).
The 2026-11-08 feature review consolidated it into **one service**; those five requirements are now
entry points (History, Project menu, Target, API import, CLI) that call it.

| ID | Pri | Requirement |
|---|---|---|
| PRJ-012 | P1 | **Import/export service** (`ImportExportService` in `GulpWorkspace`, UI-free so the CLI/MCP use it too): **import** HAR, Postman collections (v2.1), OpenAPI/Swagger documents (handed to ADV-050 for request building), `sitemap.xml`/URL lists, and another `.gulp` (exchanges, issues, Notebook items); **export** selected/filtered exchanges as HAR, CSV or `.gulp` items. Imports never send traffic; they are dedup-aware, tag imported exchanges `imported` (`exchange_tags`, doc 04 §4) with the source the file states (default `.proxy`), feed the site map, and report what was skipped and why. Every import entry point (HIS-044, PRJ-008, TGT-009, ADV-051, AUT-004) calls this one service. *(Consolidated by the 2026-11-08 feature review; M6b.)* |
| PRJ-013 | P1 | **Import history from other proxies** (lowers switching cost): through PRJ-012, import the reference suite's XML proxy-history export (base64 request/response items) and Caido's exported requests (JSON/HAR), plus mitmproxy HAR exports, preserving raw bytes, timestamps and comments/highlights where the format has them. The UI must not name the reference suite (AGENTS.md §4): label the format "XML proxy-history export" and auto-detect it. *(Added by the 2026-11-08 feature review, A5; M6b.)* |

### 2.4 Resource control (moved from F29 Governor, 2026-11-08)

The shared limiter itself is F03 §3.4 (GOV-002/003/007); these are its workspace-level controls.

| ID | Pri | Requirement |
|---|---|---|
| GOV-001 | P0 | **Panic stop** (⌃. plus a toolbar item and a menu command; also in the menu bar extra, MAC-020, when enabled): immediately pause all active, network-generating tasks across the project (Scanner, Crawler, Fuzzer, Beacon injection, scheduled tasks, agent-driven actions); show what was stopped and offer "resume all". It pauses *sending*, not the store's write coalescer, so queued writes still flush. *(Moved from F29; M11a.)* |
| GOV-006 | P1 | **Live throughput panel** (status bar + Dashboard): current req/s, in-flight, per-host leaders, and which cap (F03 §3.4) is the current bottleneck; caps and per-host overrides are edited in Settings → Network. *(Moved from F29; M16b.)* |

## 3. UI

- Launcher window (doc 05 §1) for project open/create and recents.
- Standard macOS Settings window (⌘,) with the panes; each setting shows its layer; a search field;
  export/import and reset.
- Project Info and maintenance (Compact/Rebuild) under a Project menu.

## 4. Implementation notes

- `ProjectStore.open(url:)` opens/creates the DB, runs migrations, and verifies integrity
  (`PRAGMA quick_check`) with recovery guidance on failure. Temporary projects use a cache path and
  are deleted on clean close unless saved (Save As copies/relocates the DB safely while open).
- `LayeredSettings` resolves per group; project overrides live in the project DB (`settings` table),
  user settings in the app-support JSON (doc 04 §5). Changing a setting emits `settingsChanged` so
  live components react (e.g. adding a proxy listener).
- Save As on a live WAL database: checkpoint, then copy the file (and clean up `-wal`/`-shm`), or use
  SQLite backup API; keep the session pointed at the new location.
- Keep every `SettingsGroup` Codable with a `version`; never crash on an unknown key.

## 5. Edge cases

- Disk full while writing → surface a clear error, keep the app alive, stop recording gracefully.
- Opening a project from a newer app version (higher schema) → refuse with a clear message rather
  than corrupting; opening an older one → migrate forward.
- A project on a network/removable volume that disappears → handle I/O errors without crashing.
- Two app instances opening the same file → advisory lock / warn (SQLite WAL allows one writer).

## 6. Acceptance tests

1. New temporary project records traffic immediately; "Save As" preserves everything and reopens
   identically; recents lists it.
2. A simulated crash (kill mid-traffic) leaves an openable project with near-complete history.
3. A user setting (e.g. default listener port) applies across projects; a project override wins
   where set; export→import reproduces the configuration.
4. Compact reduces size after deleting many exchanges; Rebuild indexes reconstructs the site map and
   FTS; quick_check passes.
5. Panic stop (moved from F29): ⌃. during a scan+fuzz leaves zero in-flight requests within one
   limiter tick and all tasks Paused; "resume all" restarts them.
6. Import/export round trip (PRJ-012): exporting 1,000 history rows as HAR and importing the file
   into a new project reproduces the same requests and responses byte-for-byte; importing the same
   HAR twice adds nothing the second time (dedup).
7. Other-proxy import (PRJ-013): the fixtures in `Tests/Fixtures/import/` (an XML proxy-history
   export, a Caido export and a mitmproxy HAR, each captured against VulnLab) import with every
   request's bytes intact and their comments/highlights carried over.
