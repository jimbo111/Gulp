# F21 — Automation: CLI, REST API, MCP server

> Milestones: M6b (MCP read surface + `send_request`), M17 (CLI, REST API, full MCP, scheduler), M25
> (`gulp retest`, post-1.0) · Modules: `gulp-cli`, `GulpAutomation`, `GulpWorkspace` · Depends on:
> all engines

## 1. Purpose

Drive Gulp without the GUI: a **CLI** for CI and scripting, a **REST API** for programmatic control
and integrations, and an **MCP server** so AI agents (e.g. Claude Code) can operate Gulp as a tool.
All three use the same `ProjectSession` as the app, so behavior matches.

## 2. Requirements

### 2.1 CLI (`gulp`)

| ID | Pri | Requirement |
|---|---|---|
| AUT-001 | P0 | `gulp send` — send a raw request (`--raw file\|-`, `--target`, version/connection/redirect options) and print the response (raw or `--json`), with exit codes for transport errors. |
| AUT-002 | P0 | `gulp scan --url <seed> [--config fast\|balanced\|thorough\|<file>] [--scope <file>] [--report out.html\|.json\|.sarif] [--fail-on high\|medium\|...]` — headless crawl-and-audit; progress to stderr; exits non-zero when issues at/above the threshold are found (for CI gating). |
| AUT-003 | P0 | `gulp proxy --port 8080 [--project f.gulp]` — run a headless proxy that records to a project (useful for capturing traffic in CI/e2e runs). |
| AUT-004 | P0 | `gulp project` subcommands: `new`, `info`, `compact`, `export (har\|json\|sarif)`, `import`. *(`export`/`import` are the CLI entry point of the shared import/export service, F20 PRJ-012.)* |
| AUT-005 | P1 | `gulp fuzz` — run a saved/declared Fuzzer attack headlessly and emit results (CSV/JSON). |
| AUT-006 | P1 | `gulp replay <har\|.gulp>` — replay requests through the engine/proxy (test fixtures; VulnLab-driven tests). |
| AUT-007 | P1 | `gulp api --port 9000 --token <t>` — start the REST+MCP server (AUT-010/AUT-020) headlessly against a project. |
| AUT-008 | P1 | `gulp dev generate-project --exchanges N` and other dev helpers (doc 06 §5). |
| AUT-009 | P1 | Global flags: `--project`, `--config-dir`, `--log-level`, `--quiet`, `--json`; sensible exit codes; man-page/`--help` for every command (swift-argument-parser). |

### 2.2 REST API

| ID | Pri | Requirement |
|---|---|---|
| AUT-010 | P0 | A local HTTP API (Hummingbird) bound to `127.0.0.1` by default, requiring a bearer token; CORS off; documented with an OpenAPI spec served at `/openapi.json`. Binding beyond localhost requires explicit opt-in + warning. |
| AUT-011 | P0 | Endpoints (v1): project info; query exchanges (filter via GulpQL, paged); get an exchange (request/response bytes); send a request via the engine; Repeater send; start/stop/status a scan; list issues (filterable) and get issue detail; list/append Notebook; scope read/update; Beacon interactions; tasks list/control. |
| AUT-012 | P0 | Streaming: Server-Sent Events (or WebSocket) for live events (new exchanges, issues, task progress, Beacon interactions) mirroring the `EventBus`. |
| AUT-013 | P1 | Trigger a report render and download (HTML/JSON/SARIF). |
| AUT-014 | P1 | Rate limiting and request-size limits on the API; audit log of API actions. |
| AUT-015 | P1 | Stable, versioned schema (`/v1`); errors as problem+json; pagination and filtering consistent across list endpoints. |

### 2.3 MCP server

| ID | Pri | Requirement |
|---|---|---|
| AUT-020 | P0 | An **MCP server** (Model Context Protocol) exposing Gulp capabilities as tools/resources to AI clients. Transport: stdio (for local clients like Claude Code) and/or the local HTTP transport; token-gated for the HTTP transport. *(Pulled forward by the 2026-11-08 feature review: the stdio transport ships in M6b; the HTTP transport comes with the REST API in M17.)* |
| AUT-021 | P0 | Tools: `list_exchanges(filter)`, `get_exchange(id)`, `send_request(raw/target/options)`, `repeater_send`, `start_scan(seed,config)`, `scan_status`, `list_issues(filter)`, `get_issue(id)`, `search(query)`, `get_scope`/`set_scope`, `beacon_interactions`, `add_note`. Each tool has a strict JSON schema and returns structured results sized for a model (truncate large bodies with a fetch-more affordance). *(M6b ships the read tools + `send_request`: `list_exchanges`, `get_exchange`, `send_request`, `get_scope`. The others are added as their features land — `search` and `add_note` in M9, the issue tools in M10a, `start_scan`/`scan_status`/`beacon_interactions` in M11a/M11b — and the set is complete in M17.)* |
| AUT-022 | P0 | Resources: expose issues, the site map, and selected exchanges as MCP resources an agent can read. *(Site map and exchanges in M6b; issues once F08 lands.)* |
| AUT-023 | P0 | **Safety for agent control** (M6b, with the first MCP tools): every active action (scan, send to a target, scope changes) is ScopeGuard-checked; a configurable **approval mode** can require human confirmation in the app before active tools run on an agent's behalf; all agent actions are logged and attributed (`source = .automation`/`.ai`). Off-by-default network egress; no project data leaves the machine via MCP unless the client reads it. |
| AUT-024 | P1 | Reuses the same auth/token and OpenAPI-derived schemas as the REST API where possible; a quickstart for connecting Claude Code. |
| AUT-025 | P2 | Prompts/recipes: packaged MCP "prompts" for common workflows (triage issues, explain an exchange, draft a report section) that call the tools. |

### 2.4 Scheduling and headless retest (moved from F17 and F30, 2026-11-08)

| ID | Pri | Requirement |
|---|---|---|
| ETL-006 | P1 | **Schedule tasks**: run a scan/crawl/fuzz at a time or on an interval, and auto-pause/resume; a simple scheduler with a task list (useful for long engagements). The app must be running (no background daemon in v1). *(Moved from F17.)* |
| ETL-010 | P2 | **Task scheduler notifications** via macOS notifications (UI-090) when scheduled tasks finish or find high-severity issues. *(Moved from F17.)* |
| DRF-009 | P1 | **Headless retest** via CLI/REST: `gulp retest --project f.gulp --fail-on regression` re-runs the stored issue proofs (F08 §2.4) and exits non-zero when a previously-fixed issue is vulnerable again; SARIF/JSON includes remediation status. *(Moved from F30; later: M25 — post-1.0.)* |

## 3. UI

Minimal GUI: Settings → an "Automation" area to enable the REST/MCP server, show the token (regenerate/copy), the bind address (with the egress warning), the approval mode for agent-driven active actions, and an audit log viewer. The CLI is documented in `--help` and the README.

## 4. Implementation notes

- `GulpAutomation` builds on `ProjectSession`; the REST handlers and MCP tools are thin adapters over
  the same service methods the UI uses — no duplicate logic. Define request/response DTOs once
  (Codable) and generate the OpenAPI + MCP tool schemas from them.
- Auth: a random token stored in the Keychain; constant-time comparison; per-connection rate limits.
- Streaming mirrors `EventBus`; backpressure/bounded buffers as elsewhere (doc 01 §5.3).
- MCP: implement the protocol (initialize/capabilities, tools/list, tools/call, resources) over
  stdio and the HTTP transport; keep tool outputs compact and paginated; map errors cleanly.
- Approval mode: an active action from `.automation`/`.ai` enqueues an approval the app surfaces
  (toast + dashboard); headless mode can auto-approve within scope only if explicitly configured.
- Scheduler (ETL-006) is a lightweight actor persisting scheduled jobs in the project as a
  `SchedulerSettings` group in the `settings` table (doc 04 §6; same pattern as proxy/intercept
  rules — no dedicated table); it drives the existing task APIs. Time/interval triggers only.
  Scheduled runs need the app (or `gulp api`) running; document that.

## 5. Edge cases

- Headless with no display: everything must work without AppKit (CLI/API link only the non-UI
  modules; the engine is UI-free by design — doc 01 §3).
- An agent requesting an out-of-scope or destructive action → blocked by ScopeGuard/approval; return
  a clear, structured error.
- Large result sets to an AI client → paginate and truncate with explicit continuation.
- Token leakage risk → bind localhost, short-lived regenerable token, audit log, loud warning on
  non-localhost binds.

## 6. Acceptance tests

1. `gulp scan --url http://127.0.0.1:8088 --config balanced --report out.sarif --fail-on high` exits
   non-zero on VulnLab and writes valid SARIF; `--fail-on` threshold changes the exit code.
2. REST: with a token, `GET /v1/exchanges?filter=...` paginates; `POST /v1/requests` sends and
   returns the response; the SSE stream emits new exchanges live; no-token requests get 401.
3. MCP over stdio: a client lists tools, calls `start_scan` (scope-gated), polls `scan_status`, and
   reads `list_issues`; an out-of-scope `send_request` is refused with a structured error; actions
   appear in the audit log as `.automation`.
4. CLI and GUI produce identical scan results on the same target/config (same `ProjectSession`).
5. A scheduled scan starts at the set time and notifies on completion (moved from F17).
6. *(post-1.0, M25)* `gulp retest --fail-on regression` exits non-zero when a previously-fixed issue
   is vulnerable again (moved from F30).
