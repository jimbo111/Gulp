# Gulp documentation index

## Core documents

| # | File | What it covers |
|---|---|---|
| 00 | [00-vision.md](00-vision.md) | Product vision, goals and non-goals, naming map (Burp → Gulp), principles, ethics |
| 01 | [01-architecture.md](01-architecture.md) | Tech stack, repository layout, modules, dependency rules, concurrency, data flow |
| 02 | [02-build-and-dev-setup.md](02-build-and-dev-setup.md) | Toolchain, Makefile, building on macOS and Linux, CI, signing, notarization, releases |
| 03 | [03-roadmap.md](03-roadmap.md) | Ordered milestones M0–M20 with tasks and Definition of Done |
| 04 | [04-data-model-and-storage.md](04-data-model-and-storage.md) | Core Swift types, SQLite schema, project file format |
| 05 | [05-ui-ux.md](05-ui-ux.md) | Window layout, navigation, shared components, shortcuts, visual design |
| 06 | [06-testing-strategy.md](06-testing-strategy.md) | Unit, integration and UI tests, VulnLab, performance budgets |
| 07 | [07-decisions.md](07-decisions.md) | Architecture Decision Records (ADRs) and open questions |
| — | [PROGRESS.md](PROGRESS.md) | Live progress tracker; Claude updates it as work lands |

## Feature specifications (`features/`)

| ID | Feature | Milestone |
|---|---|---|
| F01 | [Proxy (intercept, match & replace, listeners)](features/F01-proxy.md) | M2, M3, M4 |
| F02 | [TLS & certificate authority](features/F02-tls-certificates.md) | M3 |
| F03 | [HTTP engine (raw send, HTTP/2, pooling, race conditions)](features/F03-http-engine.md) | M1, M3, M5 |
| F04 | [Target: site map & scope](features/F04-target-sitemap-scope.md) | M6 |
| F05 | [History, Logger, GulpQL filters & search](features/F05-history-logger-filters.md) | M2, M9 |
| F06 | [Repeater](features/F06-repeater.md) | M5 |
| F07 | [Fuzzer (Intruder-equivalent)](features/F07-fuzzer.md) | M8 |
| F08 | [Scanner (passive, active, check recipes)](features/F08-scanner.md) | M10, M11 |
| F09 | [Crawler](features/F09-crawler.md) | M11, M13 |
| F10 | [Beacon (OAST / out-of-band)](features/F10-beacon-oast.md) | M11 |
| F11 | [Sequencer](features/F11-sequencer.md) | M14 |
| F12 | [Decoder & transform tags](features/F12-decoder.md) | M7 |
| F13 | [Comparer](features/F13-comparer.md) | M7 |
| F14 | [Notebook (organizer & notes)](features/F14-notebook.md) | M9 |
| F15 | [Sessions, authentication & macros](features/F15-sessions-auth-macros.md) | M12 |
| F16 | [Gulp Browser, DOM Probe, Frame Kit](features/F16-browser.md) | M13 |
| F17 | [Engagement tools](features/F17-engagement-tools.md) | M16 |
| F18 | [Extensions & scripting](features/F18-extensions.md) | M15 |
| F19 | [Reporting](features/F19-reporting.md) | M16 |
| F20 | [Projects & settings](features/F20-projects-settings.md) | M2, M16 |
| F21 | [Automation: CLI, REST API, MCP server](features/F21-automation.md) | M17 |
| F22 | [AI assistant](features/F22-ai-assistant.md) | M18 |
| F23 | [Advanced testing tools (Authz Matrix, JWT, smuggling, GraphQL…)](features/F23-advanced-tools.md) | M19 |
| F24 | [macOS integration](features/F24-macos-integration.md) | M3, M20 |

## Format of a feature spec

Every `Fxx` file has the same sections, so it is easy to scan:

1. **Header**: milestone(s), module(s), dependencies.
2. **Purpose**: what the feature is for and how a tester uses it.
3. **Requirements**: a table of `ID | Pri | Requirement`. IDs are stable; reference them in tests
   and commits.
4. **UI**: layout and interactions.
5. **Implementation notes**: algorithms, libraries, pitfalls, and the concepts you need.
6. **Data**: tables and types it adds (detailed in doc 04).
7. **Edge cases**.
8. **Acceptance tests**: concrete checks that prove the feature works.
