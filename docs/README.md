# Gulp documentation index

## Core documents

| # | File | What it covers |
|---|---|---|
| 00 | [00-vision.md](00-vision.md) | Product vision, goals and non-goals, naming map (Burp → Gulp), principles, ethics |
| 01 | [01-architecture.md](01-architecture.md) | Tech stack, repository layout, modules, dependency rules, concurrency, data flow |
| 02 | [02-build-and-dev-setup.md](02-build-and-dev-setup.md) | Toolchain, Makefile, building on macOS and Linux, CI, signing, notarization, releases |
| 03 | [03-roadmap.md](03-roadmap.md) | Ordered milestones M0–M20 (v1) + M21–M26 (Phase F) with tasks and Definition of Done |
| 04 | [04-data-model-and-storage.md](04-data-model-and-storage.md) | Core Swift types, SQLite schema, project file format |
| 05 | [05-ui-ux.md](05-ui-ux.md) | Window layout, navigation, shared components, shortcuts, visual design |
| 06 | [06-testing-strategy.md](06-testing-strategy.md) | Unit, integration and UI tests, VulnLab, performance budgets |
| 07 | [07-decisions.md](07-decisions.md) | Architecture Decision Records (ADRs) and open questions |
| — | [PROGRESS.md](PROGRESS.md) | Live progress tracker; Claude updates it as work lands |
| — | [REVIEW.md](REVIEW.md) | Review dossier: the objective DoD, every independent review + verdict, and the build-ready judgment |

## Feature specifications (`features/`)

| ID | Feature | Milestone |
|---|---|---|
| F01 | [Proxy (intercept, match & replace, listeners)](features/F01-proxy.md) | M2, M3, M4 |
| F02 | [TLS & certificate authority](features/F02-tls-certificates.md) | M3 |
| F03 | [HTTP engine (raw send, HTTP/2, pooling, race conditions)](features/F03-http-engine.md) | M1, M3, M5 |
| F04 | [Target: site map & scope](features/F04-target-sitemap-scope.md) | M6 |
| F05 | [History, Logger, GulpQL filters & search](features/F05-history-logger-filters.md) | M2, M9 |
| F06 | [Repeater](features/F06-repeater.md) | M5 |
| F07 | [Fuzzer (Intruder-equivalent), incl. content discovery and WebSocket fuzzing](features/F07-fuzzer.md) | M8, M22 |
| F08 | [Scanner (passive, active, check recipes)](features/F08-scanner.md) | M10, M11 |
| F09 | [Crawler](features/F09-crawler.md) | M11, M13 |
| F10 | [Beacon (OAST / out-of-band)](features/F10-beacon-oast.md) | M11 |
| F11 | [Sequencer](features/F11-sequencer.md) | M14 |
| F12 | [Decoder & transform tags](features/F12-decoder.md) | M7 |
| F13 | [Comparer](features/F13-comparer.md) | M7 |
| F14 | [Notebook (organizer & notes)](features/F14-notebook.md) | M9 |
| F15 | [Sessions, authentication & macros](features/F15-sessions-auth-macros.md) | M12 |
| F16 | [Gulp Browser, DOM Probe, Frame Kit](features/F16-browser.md) | M13 |
| F18 | [Extensions & scripting](features/F18-extensions.md) | M15 |
| F19 | [Reporting](features/F19-reporting.md) | M16 |
| F20 | [Projects & settings](features/F20-projects-settings.md) | M2, M16 |
| F21 | [Automation: CLI, REST API, MCP server](features/F21-automation.md) | M17 |
| F22 | [AI assistant](features/F22-ai-assistant.md) | M18 |
| F23 | [Advanced testing tools (Authz Matrix, JWT, smuggling, GraphQL…)](features/F23-advanced-tools.md) | M19 |
| F24 | [macOS integration](features/F24-macos-integration.md) | M3, M20 |

### Post-1.0 expansion (M21+)

Added after the v1 review (see `docs/07-decisions.md` ADR-013). These build on the v1 engines and
ship after release; a few parts could be pulled earlier where noted in each spec.

| ID | Feature | Milestone |
|---|---|---|
| F25 | [SSO Workbench (OAuth/OIDC/SAML flow testing)](features/F25-sso-workbench.md) | M21 |
| F27 | [JS Recon Studio (source-map recovery & API inventory)](features/F27-js-recon-studio.md) | M23 |
| F32 | [LLM/AI-feature security testing](features/F32-llm-security.md) | M26 |

### Merged specs (2026-11-08 feature review)

These files are now short stubs that record where each requirement went (IDs unchanged) and which
were cut. See `docs/07-decisions.md` product decision #7.

| ID | Former feature | Merged into |
|---|---|---|
| F17 | [Engagement tools](features/F17-engagement-tools.md) | F07 (content discovery), F19 (CSRF PoC), F21 (scheduler), F27 (scripts/comments), F06 and doc 05 UI-040 (Copy as, request builder); search/references/analyze duplicates cut |
| F26 | [WebSocket Security Workbench](features/F26-websocket-workbench.md) | F07 (WS fuzzing), F08 (CSWSH), F23 (per-message authz), F01 (sub-protocol decoding), F15 (scripted sequences) — still post-1.0 (M22) |
| F28 | [Web Cache Poisoning & Deception scanner](features/F28-cache-poisoning.md) | F08 §3.5 check family — still post-1.0 (M24) |
| F29 | [Governor (global resource control + panic stop)](features/F29-governor.md) | F03 §3.4 (shared limiter, backoff), F20 §2.4 (panic stop, throughput panel); watchpoints/quiet hours/dry-run/layered caps cut |
| F30 | [Drift & Retest](features/F30-drift-retest.md) | F08 §2.4 (issue retest), F21 (`gulp retest`) — still post-1.0 (M25); baselines cut |
| F31 | [Journal (coverage map & engagement timeline)](features/F31-journal.md) | F04 §2.3 (coverage), F14 (timeline, resume card, markers); treemap/checklists/effort rollup cut |

### Backlog (proposed, not yet specified)

Strong candidates from the feature review, held for a future pass (one-liners only; promote to a
full `Fxx` spec when scheduled):

- **CSP Auditor & Bypass Finder** — parse/grade CSP and actively find gadget bypasses on allowlisted
  origins (beyond F08's passive "weak CSP" flag).
- **Deserialization & Object-Injection Workbench** — detect/decode Java/.NET/PHP/pickle/Ruby
  serialized objects and safe OAST-correlated detection probes (beyond F08 signposting).
- **gRPC & Protobuf Workbench** — schema-less protobuf decode, `.proto`/reflection import, gRPC-Web
  framing (promotes F23 ADV-053 to a first-class tool).
- **Arsenal** — cross-project payload/wordlist library and reusable test cases (promotes the per-
  attack UI-080 list to a managed asset).
- **Share Packs** — file-based async collaboration: export/import curated findings + comment threads
  with a review/merge gate (within the no-team-server decision).
- **Privacy Guard** — capture-time masking + egress gate for AI/OAST/clipboard (beyond F19 export
  redaction).
- **Interop Hub** — paste-to-Repeater (cURL/fetch/raw), Postman/Insomnia/mitmproxy import, HAR/`.http`
  export (consolidates scattered import/export).
- **Perspectives** — saved workspace layouts / context switching.
- **Dojo** — in-app guided onboarding and lessons driven against VulnLab.
- **Access Pack** — colorblind-safe palettes + non-color encodings beyond the doc 05 §7 baseline.
- **Target TLS/HTTPS config scanner** — testssl.sh-style protocol/cipher/chain audit of the target
  (distinct from F02, which is Gulp's own CA/MITM).

## Format of a feature spec

Every `Fxx` file has the same sections, so it is easy to scan:

1. **Header**: milestone(s), module(s), dependencies.
2. **Purpose**: what the feature is for and how a tester uses it.
3. **Requirements**: a table of `ID | Pri | Requirement`. IDs are stable; reference them in tests
   and commits.
4. **UI**: layout and interactions.
5. **Implementation notes**: algorithms, libraries, pitfalls, and the concepts you need.
6. **Edge cases**.
7. **Acceptance tests**: concrete checks that prove the feature works.

Notes on the format:

- **Data/storage**: the tables and columns every feature persists live centrally in
  [`04-data-model-and-storage.md`](04-data-model-and-storage.md), not in a per-feature "Data"
  section, so the schema stays consistent. A spec calls out its data inline only where it helps.
- **Grouped specs**: a few specs cover several related tools and are organized by sub-tool, each with
  its own requirements table, then shared Implementation notes and Acceptance tests. `F23`
  (advanced tools) is the main example.
