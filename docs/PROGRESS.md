# Progress tracker

This is the live state of the build. Claude updates it as work lands: tick tasks in the current
milestone (keep the detail in `docs/03-roadmap.md`) and add a dated log line. Work milestones in
order; within a milestone, do P0 first.

## Current status

- **Phase**: M0 scaffolding written; **awaiting first CI run to verify the builds**.
- **Active milestone**: **M0 — Scaffolding** (files complete, verification pending).
- **Verification caveat**: the authoring container has **no Swift toolchain** and
  `download.swift.org` is blocked by its network policy, so `swift build`/`swift test` and
  `xcodebuild` could not be run here. `Package.swift`, `project.yml`, `.swift-format` and the CI YAML
  were statically checked (structure, YAML/JSON validity, target↔directory mapping, 110-col lint
  limit). **CI (`.github/workflows/ci.yml`) is the real gate** — the `core-linux` job runs
  `swift test` on Linux and the `macos` job runs `make generate lint test build`. Treat M0 as done
  only once that workflow is green; fix anything it flags before starting M1.
- **Next action**: push, watch CI, fix any build fallout, then begin **M1** (GulpCore model + raw
  HTTP/1 engine).
- **Product defaults assumed**: see `docs/07-decisions.md` "Open questions" (bundle id, license, min
  macOS, Beacon domain, AI providers, team features). Safe to build on; the owner can override.

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
- 2026-11-07 — Spec review pass: fixed layering (BrowserDriver injection, ADR-010), scope precedence
  (ADR-011), FTS trigram limits, GulpQuery storage-agnosticism, Beacon privileged ports, single-packet
  wording. (Commit `35fee56`.)
- 2026-11-07 — **M0 scaffolding written** (unverified locally — see caveat above):
  - `Packages/GulpKit/Package.swift` with all 26 module targets + 25 test targets, the full
    dependency graph, external packages (NIO/SSL/HTTP2/Extras, certificates, crypto, GRDB,
    Hummingbird, ArgumentParser, Collections, Logging) and Swift 6 language mode. Each module has a
    documented placeholder type and a passing scaffolding test.
  - macOS modules (`GulpBrowser`/`GulpScript`/`GulpUI`/`GulpFeatures`) are defined on all platforms as
    empty shells (implementation choice refining ADR-010; doc 02 §5 updated to match — **doc changed,
    not code**).
  - App shell: `App/GulpApp.swift` + `Tool.swift` (empty `NavigationSplitView` with the doc 05 §2
    sidebar), `AppDelegate`, `Info.plist` (`.gulp` document type), entitlements (no sandbox, hardened
    runtime), asset catalog.
  - `project.yml` (XcodeGen; app + `GulpAppUITests`, Sparkle, embeds `gulp-cli`), `Makefile`,
    `Brewfile`, `.swift-format`, `.github/workflows/ci.yml` (Linux core + macOS jobs).
  - `Beacon/` package (separate, Linux/Docker) with placeholder `gulp-beacon` + `Dockerfile`.
  - Also corrected a spec error found while scaffolding: `SNIHandler` is in `NIOSSL`, not
    swift-nio-extras (F02).

## How to pick up work (reminder)

1. Read `CLAUDE.md` §1 (reading order) and this file.
2. Open the active milestone in `docs/03-roadmap.md`; read the referenced feature spec(s) and their
   requirement IDs.
3. Implement P0 first, tests naming requirement IDs; run `make test` + `make lint`; keep the core
   modules building on Linux.
4. Tick the box here, add a log line (date, what, any deviation), and commit referencing the IDs.
