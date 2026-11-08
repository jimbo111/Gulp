# F18 — Extensions and scripting

> Milestone: M15 · Modules: `GulpExtensions`, `GulpScript` (macOS), `SDK/` · Depends on: all engines

## 1. Purpose

Users extend Gulp without rebuilding it: add passive/active checks, new tool tabs, context-menu
actions, message editors, session actions, and automation. Two runtimes share one API:
**in-process JavaScript** (fast, no external deps) and **out-of-process JSON-RPC** (any language;
isolation; a Python SDK is provided). Lightweight **Snippets** give one-off JS for columns,
filters, payload processors and transform tags.

## 2. The Gulp Extension API (surface)

One stable, versioned API both runtimes implement. Capabilities (each gated by a manifest
permission):

| Area | What an extension can do |
|---|---|
| Registration | Register passive checks, active checks, context-menu items (UI-040), custom tool tabs, custom message-editor tabs, session actions, payload generators/processors, and intruder/fuzzer extensions. |
| HTTP | Read exchanges; send requests via the engine (`sendRequest(raw, target, options)`), scope-gated for active sends; subscribe to `onProxyRequest/Response` and `onToolRequest/Response` with the ability to modify (request/response rewriting) and to annotate (highlight/comment/notes). |
| Model | Create issues with evidence/markers; read/modify the site map and scope; read/write project-scoped key/value state (`extension_state`); read settings the user granted. |
| UI (macOS) | Provide SwiftUI/AppKit views for custom tabs and editor tabs; show simple forms/alerts; add menu items and toolbar actions. (Out-of-process extensions provide UI via a declarative schema rendered by Gulp.) |
| OAST | Request Beacon tokens and query interactions (F10). |
| Utilities | Codec/transform functions (F12), logging, and access to the active identity/cookie jar (F15) where permitted. |

## 3. Requirements

### 3.1 Runtimes and lifecycle

| ID | Pri | Requirement |
|---|---|---|
| EXT-001 | P0 | **JS runtime** (JavaScriptCore): load an extension's JS bundle in an isolated `JSContext` with the Gulp API injected as host objects; enforce CPU/time limits per callback (watchdog) and a memory cap; no ambient network/file access except through the API. |
| EXT-002 | P0 | **JSON-RPC runtime**: spawn an extension process; communicate over stdio with JSON-RPC 2.0 (Gulp→ext: events/callbacks; ext→Gulp: API calls). Length-prefixed framing; robust to crashes (restart policy); a per-call timeout. |
| EXT-003 | P0 | **Manifest** (`gulp-extension.json`): id, name, version, author, runtime (`js`/`process`), entry point/command, min API version, declared **permissions** (http-send, intercept-modify, read-traffic, create-issues, modify-scope, filesystem, network-direct, ui, oast, settings-read), and which hooks it registers. |
| EXT-004 | P0 | **Permission approval** at install/enable time: show what the extension requests; user approves; permissions enforced at the API boundary at runtime (deny + log on violation). |
| EXT-005 | P0 | Extension manager UI: install from file/folder (the Gallery, EXT-020, is post-1.0), enable/disable, per-extension log/output console, errors surfaced clearly, reload on change (dev mode). |
| EXT-006 | P1 | Extension state persistence (`extension_state`), and per-extension settings rendered from a declared schema. |
| EXT-007 | P1 | Versioned API with capability negotiation; deprecations warned; a compatibility shim layer kept small. |
| EXT-008 | P1 | Resource governance: extensions run off the main thread; a misbehaving extension can be force-stopped without taking down Gulp; aggregate CPU/memory shown in the manager. |

### 3.2 Snippets and SDKs

| ID | Pri | Requirement |
|---|---|---|
| EXT-010 | P0 | **Snippets**: small JS evaluated for custom history/Logger columns (HIS-043), GulpQL escape-hatch predicates (HIS-028), Fuzzer payload processors (FUZ-013), and Transform Tag `js(...)` (DEC-024). Pure functions over a provided message object; sandboxed and timeout-bounded; a snippet library with save/reuse. |
| EXT-011 | P0 | **JS SDK typings** (`SDK/js/gulp.d.ts`) and templates so authors get autocomplete; a sample set (header injector, a passive check, a custom column, a custom tab). |
| EXT-012 | P1 | **Python SDK** (`SDK/python/gulp_sdk`): a thin library implementing the JSON-RPC protocol with decorators (`@passive_check`, `@context_menu`, `@on_request`), so a check is a few lines. Sample extensions included. *(P0 → P1 by the 2026-11-08 feature review: no community yet.)* |
| EXT-013 | P1 | A TypeScript project template (bundled to a single JS file) for larger JS extensions. |
| EXT-014 | P2 | A WebAssembly runtime option for sandboxed native-speed extensions (future; keep the API ready). |

### 3.3 Gallery (post-1.0)

**Post-1.0 (2026-11-08 feature review)**: there is no extension community to serve yet. Both rows are
in the roadmap's Post-1.0 backlog; v1 installs extensions from a file or folder only.

| ID | Pri | Requirement |
|---|---|---|
| EXT-020 | P1 | **Extension Gallery**: browse/install community extensions from a catalog (a signed JSON index + artifacts hosted by the project). Show permissions before install, versioning, and updates. |
| EXT-021 | P2 | Ratings/categories/search; report an extension; a "verified" badge for project-reviewed ones. |

## 4. Implementation notes

- Define the API once as a protocol surface in `GulpExtensions` plus a JSON schema for the RPC
  methods/events; generate the TS typings and the Python stubs from it to avoid drift.
- JS host: bridge host objects with `JSExport`; marshal bytes as typed arrays; run each extension in
  its own context on a dedicated serial queue; a watchdog interrupts long-running JS
  (`JSContextGroup`/`isValid` checks or a cooperative yield + timer).
- Process host: a `JSONRPCConnection` over the child's stdio; map events to RPC notifications and API
  calls to requests; supervise with a restart/backoff; isolate crashes.
- Enforce permissions centrally in an `ExtensionPermissionGate` (distinct from the agent-tool-surface
  `APIGate` of doc 01 §3 rule 6 — that one is orchestration-layer and governs F21/F22; this one is in
  `GulpExtensions` and governs extension calls) that every call passes through; scope-gate any send;
  never expose raw filesystem/network unless `filesystem`/`network-direct` is granted.
- UI for out-of-process extensions: a declarative view schema (fields, tables, buttons) rendered by
  `GulpFeatures`, with actions routed back over RPC.

## 5. Edge cases

- An extension that modifies every request (perf) → run hooks with a budget and surface slow ones.
- Conflicting modifications from multiple extensions → defined order (manifest/priority) and a log
  of who changed what.
- A crashing/looping extension → isolated and force-stoppable; Gulp stays up.
- Untrusted extensions → permissions + process isolation; warn loudly for `network-direct`/
  `filesystem`.

## 6. Acceptance tests

1. The sample JS header-injector adds a header to tool requests; disabling it stops the effect.
2. The sample JS passive check raises a custom issue on matching responses, with correct markers.
3. The sample Python (JSON-RPC) extension registers a context-menu action that sends a modified
   request and creates an issue; killing the process mid-call is handled (restart, error logged).
4. A permission the extension didn't request (e.g. `http-send`) is denied at runtime and logged.
5. A Snippet column computes a value over 10k rows without blocking the UI; a snippet infinite loop
   is interrupted by the watchdog.
