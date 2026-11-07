# F20 — Projects and settings

> Milestones: M2 (basics), M16 (polish) · Modules: `GulpStore`, `GulpWorkspace`,
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
| PRJ-008 | P1 | Import/merge: bring exchanges/issues from another `.gulp`, a HAR, or saved items into the current project (dedup-aware). |
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
