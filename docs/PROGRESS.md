# Progress tracker

This is the live state of the build. Claude updates it as work lands: tick tasks in the current
milestone (keep the detail in `docs/03-roadmap.md`) and add a dated log line. Work milestones in
order; within a milestone, do P0 first.

## Current status

- **Phase**: Specification complete. Implementation not started.
- **Active milestone**: **M0 — Scaffolding** (next task).
- **Blocked on**: nothing. A few product defaults are assumed; see `docs/07-decisions.md` "Open
  questions" (bundle id, license, min macOS, Beacon domain, AI providers, team features). The
  assumptions are safe to build on; the owner can override any of them.

## Milestone checklist (summary — details in docs/03-roadmap.md)

- [ ] M0 — Scaffolding (repo layout, Package.swift, project.yml, Makefile, CI, empty app window)
- [ ] M1 — Core model + raw HTTP/1 engine
- [ ] M2 — Plain-HTTP proxy, storage, history UI
- [ ] M3 — TLS interception + CA + HTTP/2
- [ ] M4 — Intercept, Match & Replace, message editor, WebSockets
- [ ] M5 — Repeater + advanced HTTP engine (HTTP/2 raw, group/race sends)
- [ ] M6 — Target: site map + scope + ScopeGuard
- [ ] M7 — Decoder + Comparer
- [ ] M8 — Fuzzer
- [ ] M9 — Logger, GulpQL, search, Notebook
- [ ] M10 — Passive scanner + issue model
- [ ] M11 — Crawler + active scanner + Beacon + Check Recipes
- [ ] M12 — Sessions, auth, macros
- [ ] M13 — Gulp Browser, DOM Probe, Frame Kit
- [ ] M14 — Sequencer
- [ ] M15 — Extensions + scripting
- [ ] M16 — Reporting, engagement tools, project polish
- [ ] M17 — Automation: CLI, REST API, MCP server
- [ ] M18 — Gulp Assistant (AI)
- [ ] M19 — Advanced tools (Authz Matrix, JWT, Param Discovery, Smuggling, GraphQL, API import, secrets)
- [ ] M20 — macOS polish, packaging, release

## Log

- 2026-11-06 — Specs written: core docs (00–07) + all feature specs (F01–F24) + this tracker.
  Repository is spec-only; no source yet. Next action: M0 scaffolding.

## How to pick up work (reminder)

1. Read `CLAUDE.md` §1 (reading order) and this file.
2. Open the active milestone in `docs/03-roadmap.md`; read the referenced feature spec(s) and their
   requirement IDs.
3. Implement P0 first, tests naming requirement IDs; run `make test` + `make lint`; keep the core
   modules building on Linux.
4. Tick the box here, add a log line (date, what, any deviation), and commit referencing the IDs.
