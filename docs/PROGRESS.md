# Progress tracker

The live state of the build. Read top-down: **Current state** is the truth today, the **milestone
checklist** says what exists per milestone, **carry-overs** list known gaps, and the **log** (newest
first) is history. Task-level detail and Definitions of Done live in `docs/03-roadmap.md`.

## Current state (2026-11-20)

Replace this block when the state changes; do not append to it.

- **Branches.** `main` is the only long-lived branch. Work happens on short-lived branches (this one:
  `macos-build`); rebase on `main` before handing back.
- **Gate.** GitHub Actions cannot run (minutes exhausted). `.github/workflows/ci.yml` is kept
  current but is not a gate. Before every commit run `make test` (macOS) or `make test-core`
  (Linux), and `make lint` (it runs `make rules` = `Scripts/arch-check.sh` + `Scripts/rules-check.sh`).
- **Toolchain.** Swift 6.1 or later. `swift-crypto` must be ≥ 4.5.1 (older versions double-free an
  `EVP_PKEY` when RSA public-key DER parsing fails, which crashed `GulpCodecTests` on macOS), and
  4.5.x needs Swift tools 6.1. Linux reference image: `swift:6.1-noble`. macOS: Xcode 27.2 / Swift 6.4.
  `make lint` uses the toolchain's `swift format`; no separate swift-format install is needed.
- **Verified on macOS (2026-11-20, `5542a1b`).** `swift test` passes all 563 GulpKit tests;
  this was the first compile of the macOS-only code in `GulpUI`, `GulpFeatures`, `GulpBrowser` and
  `GulpScript` and of the Keychain stores. `Gulp.app` builds with `xcodebuild` (BUILD SUCCEEDED). **Pending:**
  the `GulpAppUITests` result and a manual smoke test of each tool screen.
- **Verified on Linux (Swift 6.0, before the swift-crypto bump).** 563 tests, `swift format lint
  --strict`, both rule scripts. The 41 `Scripts/*-dod.sh` passed as a set before `40c513b`; after
  `40c513b` only m1, m4b, m7, m8, m10b, m11b, m12a and m12b were re-run. None has been re-run on
  Swift 6.1 / swift-crypto 4.5.1 yet.
- **Next, in order.**
  1. Record the UI test result and smoke-test every tool screen on macOS; fill the "macOS UI
     verified" column below.
  2. Re-run all 41 DoD scripts on the new toolchain.
  3. Identity credentials (`Identity.headers` / `variables`, e.g. a bearer token or a login
     macro's password) are still stored in the `.gulp` file; move them behind
     `environment.secretStore` like the signing keys (`GulpWorkspace/SessionSecrets.swift`).
  4. The "partial" rows of the checklist and the carry-overs below.
- **Conventions enforced by `Scripts/rules-check.sh`** (CLAUDE.md §4): active CLI probes send
  through `ScopedSender`; GulpWorkspace store writes go through `persisting(…)`; registry lookups use
  `require` (`IssueDefinitions`, `Transforms`), never `named(…)!`; test randomness uses
  `SplitMix64(seed:)`; VulnLab twins use `SafeTwin`; secrets go to `environment.secretStore`.
- **Picking work.** Use the checklist below, not the roadmap's checkboxes: take the first row whose
  "Engine/CLI" column is not **done**, and build only what that row lists as missing. Never
  re-implement a row marked **done**.

## Milestone checklist

"Engine/CLI + DoD (Linux)": **done** = the milestone's engine and `gulp-cli` surface exist and its
DoD script passes on Linux; **partial** lists what is missing; **not started** = no code. Evidence
names the main types and scripts. "macOS UI verified" is filled in after the macOS smoke tests.

| Milestone | Engine/CLI + DoD (Linux) | macOS UI verified |
|---|---|---|
| M0 Scaffolding | **done** (macOS CI green at `6e17d38`) | pending |
| M1 Core model + raw HTTP/1 engine | **done** (`m1-dod.sh`; macOS CI green at `cd84c2a`) | pending |
| M2 Plain-HTTP proxy, storage, history UI | **done** (`m2-dod.sh`; `1acf39c`) | pending |
| M3a TLS interception + CA | **done** (`m3a-dod.sh`; `054b24a`) | pending |
| M3b HTTP/2 | **done** (`m3b-dod.sh`; `11cd7d5`) | pending |
| M4a Message editor, Intercept, Match & Replace, Copy as | **done** (`m4a-dod.sh`; `dee2424`) | pending |
| M4b Streaming, WebSockets, Gulp Browser launch | **done** (`m4b-dod.sh`, `m4b-browser.sh`; `0b0c6f7`) | pending |
| M5 Repeater + advanced engine | **done** — `GulpRepeater`, `GroupSend`; `gulp-cli repeater/group/paste`; `m5-dod.sh` | pending |
| M6a Site map + scope + ScopeGuard | **done** — `SiteMapService`, `Scope`, `ScopeRows`; `gulp-cli scope/target`; `m6a-dod.sh` | pending |
| M6b Import/export, API import, MCP read surface | **done** — `ImportExportService`, `HAR`, `OpenAPIImport`, `MCPServer`/`MCPStdio`; `m6b-dod.sh` | pending |
| M7 Decoder, Comparer, JWT Workbench | **done** — `Transforms`, `SmartDecode`, `JWT`, `GulpDiff`; `m7-dod.sh` | pending |
| M8 Fuzzer + content discovery | **done** except Turbo mode (FUZ-032, P1) — `FuzzAttack`, `ContentDiscovery`; `m8-dod.sh` | pending |
| M9 Logger, GulpQL, search, Notebook, coverage | **done** — `GulpQuery`, `SearchRows`, `NotebookService`, `CoverageService`; `m9-dod.sh` | pending |
| Daily-driver beta (gate) | **not started** — no `Scripts/beta-dod.sh`, no signed build; the data-loss carry-overs (M2) are open | pending |
| M10a Passive scanner + issue model | **done** — `PassiveChecks`, `IssueService`, `IssueExport`; `m10a-dod.sh` | pending |
| M10b gRPC & protobuf | **done** — `Protobuf`, `RPC`, `GRPCReflection`, `RPCService`; `m10b-dod.sh` | pending |
| M11a Static crawler, Beacon client, limiter, panic stop | **done** — `GulpCrawler`, `Interactsh`, `ResourcePool`, `GovernorService`; `m11a-dod.sh` | pending |
| M11b Active scan engine + P0 checks | **done** — `ActiveEngine`, `ActiveChecks`, `InsertionPoints`; `m11b-dod.sh` | pending |
| M11c Full check catalog + crawl-and-audit | **partial** — done: crawl-audit, `scan api`, gRPC insertion points, retest, `ExtendedChecks` (CORS, host header, mass assignment, prototype pollution, upload, NoSQL/LDAP/XPath, cache); `m11c-dod.sh`, `m11c-checks-dod.sh`. Missing: SCN-071 CSPT, SCN-022 nested decoding, HPP as a scanner family (only `gulp-cli pollute`), deserialization signpost, CSS-context XSS; SCN-074 covers alg:none + weak secret only (no RS→HS, no `kid`) | pending |
| M12a Sessions, macros, request signing | **done** (P0) — `GulpSession`, `SessionHooks`, `SessionSecrets`; `m12a-dod.sh`. Missing: SES-003/014/015/040/041, a Sessions view in `GulpFeatures` | pending |
| M12b Authz Matrix | **done** (ADV-001…003) — `AuthzMatrix`, `AuthzMatrixService`; `m12b-dod.sh`. ADV-004/005/006 not started | pending |
| M13a CDP crawl, recorded logins, passkeys | **partial** — done: `CDPClient`, `BrowserAutomation`, `DOMProbe`. Not started: CRL-030…036, SES-030, BRW-016/SES-032 | pending |
| M13b DOM Probe + GraphQL Workbench | **done** — `m13b-graphql-dod.sh`; DOM Probe via `m13a-dom-probe-dod.sh` (Node + Playwright, skips when absent; not driven from Swift CDP end to end) | pending |
| M15 Extensions, scripting, Check Recipes | **partial** — done: `ExtensionHost`/`ProcessTransport`, `GulpScript/JSExtensionHost`, Check Recipes (JSON, passive). Missing: EXT-010 Snippets, EXT-011 `SDK/js/gulp.d.ts`, EXT-012 Python SDK, EXT-013, EXT-005 manager UI (`ExtensionsView` only audits a manifest), YAML and active recipes | pending |
| M16a Reporting | **partial** — `GulpReport` HTML + Markdown, `gulp-cli report`, `report-dod.sh`. Missing: ETL-007 CSRF PoC, NB-007, PDF, report view | pending |
| M16b Project polish, throughput panel, coverage view, timeline | **not started** (only data for JRN-002: `CoverageService` untested list, `gulp-cli coverage`) | pending |
| M17 CLI, REST API, full MCP, scheduler | **partial** — `gulp-cli` has ~50 subcommands; MCP has 4 tools over stdio. Missing: REST API (AUT-010…015), scheduler (ETL-006), `scan --url … --fail-on` (AUT-002), remaining MCP tools | pending |
| M18 Gulp Assistant | **partial** — `LLMProvider`, `AnthropicProvider`, `Redactor`, `Agent`. Missing: AI-002/005/006/008 and live wiring | pending |
| M19a Param Discovery, secrets, JS Recon core | **partial** — done: `ParamMiner` (ADV-020), `ParamPollution` (ADV-022), `recon.secret` (ADV-060), `JSRecon` (JSR-003/006/008/009); `paramdisc-dod.sh`, `pollute-dod.sh`, `recon-dod.sh`, `jsrecon-dod.sh`. Missing: JSR-001/002/005, ETL-004, secret-scanner view; JSR-004 only via `recon.endpoint` | pending |
| M19b Smuggling Probe | **partial** — CL.TE/TE.CL probes (ADV-030/031) and the confirmation workbench (ADV-032): `SmugglingProbe`; `smuggle-dod.sh`, `smuggle-confirm-dod.sh`. Missing: TE.TE and HTTP/2-downgrade vectors (ADV-030, P0), ADV-033. Deviation: VulnLab emulates on `/smuggle` (:8088), not a :8090 listener | pending |
| M20 macOS polish, packaging, release | **not started** — only `Scripts/release.sh` + `ExportOptions.plist`, never run | pending |
| M21 SSO Workbench | **partial** — SSO-001…005 (`SSOWorkbench`, `SAMLWorkbench`, `gulp-cli sso`); `sso-dod.sh`. Missing: live-SP SAML DoD (acceptance 3), SSO-006…010, UI | pending |
| M22 WebSocket fuzzing and checks | **done** (WSX-002…008; WSX-001 cut) — `cswsh/ws-authz/ws-fuzz/ws-oast/ws-script` DoDs. Missing: WS workbench UI | pending |
| M23 JS Recon Studio (rest) | **partial** — JSR-006/008/009 done (`JSRecon`, `jsrecon-diff-dod.sh`). JSR-007 not linked to `VulnLibraryCheck` | pending |
| M24 Cache poisoning & deception | **partial** — WCP-001…004 (`CachePoisoningCheck`, `CacheDeceptionCheck`); `cache-dod.sh`. Missing: WCP-005…008 | pending |
| M25 Issue retest | **done** — `gulp-cli retest`, `retest-dod.sh`. Deviation: no `issue_proofs`/`retest_runs` tables | pending |
| M26 LLM/AI-feature testing | **partial** — LLM-001/002/009 (`LLMInjection`, `gulp-cli llm`); `llm-dod.sh`. Missing P0: LLM-003, LLM-004; P1: LLM-005…007; UI | pending |

M14 is retired. F11 Sequencer, listed in the post-1.0 backlog, is built anyway (`GulpSequencer`,
`gulp-cli sequencer`, `sequencer-dod.sh`; doc 07, 2026-11-13). Still post-1.0 and unbuilt: the
deployable Beacon server, Extension Gallery, MAC-011 transparent proxy, HTTP-037 HTTP/3 client.

## Carry-overs by milestone

Known gaps in milestones marked done, kept so they are not silently dropped. Items owned by a later
milestone are listed there instead.

- **M1**: HTTP-007 brotli and zstd decoders (`br`/`zstd` throw `.unsupported`); SOCKS5
  username/password (no-auth only).
- **M2**: PRJ-001 save/discard prompt when closing a temporary project; History "add to scope"
  (HIS-004) and the in-scope/MIME/method chips (HIS-006); inline comment editing (HIS-005);
  PRJ-005 "Use settings from…" UI and settings-file import; PRJ-006 Project Info panel;
  `settingsChanged` is never published; **data loss**: no app-terminate flush hook (⌘Q can lose the
  last ~50 ms of queued writes) and exchange ids can be reused after deleting the newest rows and
  reopening.
- **M3a**: TLS-017 ECH; MAC-003 simulator CA install; TLS-007 PKCS#12 import; pass-through tunnels
  not logged; `TLSInfo.cipherSuite` empty; PRX-046 `http://gulp/cert.pem` landing page.
- **M3b**: HTTP-025 raw HTTP/2 from an `H2RequestSpec`; HTTP-026 connection events in the Logger;
  request trailers from h2 clients ignored; ALPN pre-connect offers `h2, http/1.1` rather than the
  client's list; a failed pre-connect completes the client handshake (then 502) instead of a TLS alert.
- **M4a**: MessageEditor Render tab, editable hex (UI-012), UI-015, Decoder popover (UI-021,
  DEC-006), DiffView (UI-030); PRX-016 auto-forward timeout; Content-Length toggle (always on);
  PRX-023/024 Match & Replace scope and test pane; History keeps the received response, not an edited
  one.
- **M4b**: RFC 8441 WebSocket over HTTP/2; permessage-deflate messages not editable; PRX-036 (P2);
  WS History loads a connection whole, no highlight/comment UI; a held WS message stays queued after
  its client leaves; the Chrome-for-Testing download is untested; no WKWebView fallback; HIS-007
  live partial updates stop past 4 MB; SSE times only for uncompressed HTTP/1 bodies.
- **M5**: HTTP-012 NTLMv2; REP-009 structured Inspector edits; REP-011 variable capture;
  REP-013…015 (P2); single-packet h2 does not check `SETTINGS_MAX_CONCURRENT_STREAMS`; Repeater WS
  logs are in memory only.
- **M6a**: the site map is a SwiftUI `List`, not the UI-060 `NSOutlineView` tree; "don't ask again"
  lasts for the session; F04 acceptance 4 (100k-row recompute) not benchmarked.
- **M6b**: OpenAPI/Swagger YAML; PRJ-008 merges exchanges only; the approval prompt UI and Settings
  → Automation; History "export selected rows"; import fixtures are hand-made, not captures.
- **M7**: brotli/zstd transforms; DEC-024 `js(name)` snippets; Repeater live tag preview and CMP-006;
  CMP-007/008 (P2); a `«jwt-sign…»` tag op.
- **M8**: FUZ-032 Turbo mode; the Snippet payload processor; FUZ-015/027/034 (P2); the dashboard's
  running-task list; F07 acceptance 1–3 are unit-tested, not in a DoD script.
- **M9**: GulpQL syntax coloring (HIS-025); custom-column and connection-view UI (HIS-042/043);
  "Find references" menu entry (HIS-053); GulpQL for scanner insertion points and Fuzzer results;
  HIS-028/045/054, NB-008/009 (P2); Compact must treat Notebook blobs as live; the Logger keeps the
  store it opened with across Save As.
- **M10a**: SCN-006 known-issues browser UI; TLS certificate-expiry observations; WS passive checks
  (post-1.0); Notebook ↔ issue promotion in the macOS views.
- **M10b**: History/Logger gRPC label and `grpc-status` column; per-field "read as" override;
  field-tree editing in the UI; decoded-tree size cap; GRP-006/007 (P2).
- **M11a**: BCN-007 promote-to-issue; status-bar Beacon health and throttled badges; crawl
  pause/resume across restarts and a stored crawl report; "Crawl from here" / "New crawl" entry
  points; OAST session persistence across restarts; a manual interop check against public interactsh.
- **M11b**: per-check configuration in the UI; the Audit pane takes History rows only; scan tasks
  are not persisted across restarts.
- **M12a**: GulpQL rule scope; identity credentials in the project file (Current state, item 3).
- **M12b**: the `/admin` self-granted-role case.

## Log

Newest first. Dates up to `40c513b` were written by Linux sessions in UTC, so the 2026-11-20 macOS
entry at the top is later than the 2026-11-21 entry below it. Within a day the order is approximate.

- 2026-11-20 — **macOS build** (`5542a1b`, Xcode 27.2 / Swift 6.4): the macOS-only code compiled
  for the first time. Three compile fixes: `ScopeRows` decodes GRDB rows inside the read (`Row` is
  not `Sendable`); `OASTHealth` gained a public initializer for `GulpFeatures`; `RepeaterView`'s
  `.popover` moved onto the options button. `PassiveScanTests` binds exported data before
  `JSONSerialization` (region isolation). `swift-crypto` now requires ≥ 4.5.1: older versions
  double-free an `EVP_PKEY` when RSA public-key DER parsing fails (`JWTKey.pem` on an EC key crashed
  `GulpCodecTests`); 4.5.x needs Swift tools 6.1, so the CI Linux image is `swift:6.1-noble` and the
  Linux minimum is Swift 6.1. Result: `swift test` 563/563 on macOS; `Gulp.app` builds with
  `xcodebuild`. UI tests not yet recorded. Docs restructured the same day (PROGRESS, roadmap, build,
  architecture layout, data model, testing).
- 2026-11-21 — **Leftovers from the agent-readiness review**: (1) session signing keys (DPoP/RFC 9421 private keys, HMAC secrets, AWS secret keys) no longer persist in the `.gulp` file — `SigningSecret.stored(ref:)` in the project, material in `WorkspaceEnvironment.secretStore` (Keychain on macOS, 0600 files elsewhere), resolved on open, inline keys from older projects migrated on open, removed rules delete their keys (`SessionSecretsTests`, mutation-checked); the old internal OAST `SecretStore` enum renamed `OASTTokenStore`. (2) `Transforms.require(_:)` replaces `named(…)!`, now banned by rules-check. (3) `HTTPTarget.hostHeader` replaces the remaining hand-rolled Host computations. 563 tests; m1, m4b, m7, m8, m10b, m11b, m12a, m12b DoDs pass. Deviation: none.
- 2026-11-20 — **Agent-readiness guardrails**: prose rules turned into checks. `Scripts/rules-check.sh` (six rules; `make rules`, run by `make lint` and CI; each rule mutation-tested to fire) + typed helpers: `ScopedSender` for the 14 active CLI probes (incl. ws-fuzz), `persisting` for 8 silent store writes, `IssueDefinitions.require` + `IssueIDCoverageTests`, seeded `SplitMix64` (fixed the flaky 1 MB byte-diff test), VulnLab `SafeTwin` + `VulnLabOwnershipTests` (new `GulpVulnLabTests` target), `HTTPTarget.hostHeader`. Deviation: none; ReconLab's dead `/recon/app.js` handler removed (ScanLab always answered it).
- 2026-11-17 — **LLM security core (F32 LLM-001/002/009, M26)**: `LLMInjection` (LLM-endpoint
  detection, prompt-injection payload library and reply classifier, MCP tool-poisoning detection);
  VulnLab `LLMLab` (`/chat` vs `/safe/chat`, `/mcp` vs `/safe/mcp`); `gulp-cli llm inject|mcp`;
  `LLMInjectionTests`; `Scripts/llm-dod.sh` PASS (acceptance 1 and 4). Still missing: P0 LLM-003
  (indirect injection) and LLM-004 (OAST exfiltration), LLM-005…007, UI.
- 2026-11-17 — **Cache poisoning and deception P0 family (F28 WCP-002…004, M24)**:
  `active.cache-poisoning` probes a list of unkeyed headers and confirms with a clean follow-up served
  the cached canary; new `active.cache-deception` (private content cacheable at a static-looking
  suffix); VulnLab `CacheLab` with `/safe/` twins; `CacheChecksTests`; `Scripts/cache-dod.sh` PASS.
  WCP-005…008 remain.
- 2026-11-17 — **Issue retest (F30 DRF-009, M25)**: `gulp-cli retest` re-runs each issue's check
  (SCN-037) with Fixed / Still-Vulnerable / Needs-Review verdicts, reopens a regressed issue, and
  `--fail-on-regression` exits non-zero; VulnLab `/lab/unpatch`; `Scripts/retest-dod.sh` PASS.
  Deviation (doc 07): reuses the stored proving exchange; no `issue_proofs`/`retest_runs` tables.
- 2026-11-17 — **SSO Workbench P0 core (F25 SSO-001…005, M21)**: `SSOWorkbench` (OAuth/OIDC flow
  reconstruction and grant-type detection, `redirect_uri` mutation probes, state/PKCE/nonce analysis)
  and `SAMLWorkbench` (decode, signed-node set, signature-stripping/XSW/audience/recipient/NotOnOrAfter
  mutations); VulnLab `SSOLab` (`/authorize` vs `/safe/authorize`, OIDC discovery document);
  `gulp-cli sso analyze|probe`; `Scripts/sso-dod.sh` PASS (acceptance 1 and 4). The live-SP SAML
  fixture (acceptance 3), SSO-006…010 and the UI remain.
- 2026-11-13 — **Linux type-checks of macOS code; extension-host crash fix**: the JavaScriptCore
  host is type-checked on Linux against a shim (`Scripts/jsc-host-typecheck.sh`, in CI), which found
  a cross-module bug; a throwaway SwiftUI shim found a third (`Sequencer.analyze`). Both extension
  hosts now share `ExtensionWire` decoding, which fixed a fatal error on malformed `findings`
  (`JSONSerialization` on a top-level scalar); 4 `ExtensionWireTests`, 523 tests. Details in
  `docs/11-review-run.md` §5.0b.
- 2026-11-13 — **JS Recon studio core (F27 JSR-003/006/008)**: `JSRecon` detects `sourceMappingURL`,
  reconstructs the original file tree from a `.map`'s `sourcesContent`, mines candidate parameter names
  (to feed Parameter Discovery, ADV-021) and flags interesting literals (cloud-storage URLs, internal
  hostnames, API bases). `gulp-cli js-recon`, VulnLab `/recon/app.js` + `/recon/app.js.map`,
  `Scripts/jsrecon-dod.sh` PASS (recovers `src/secret.js`, mines hidden params from the recovered
  source, flags the S3/internal literals). 491 tests. Burp does source-map recovery only via extensions.
- 2026-11-13 — **CSWSH probe (WSX-003, M22)**: `gulp-cli cswsh` replays a WebSocket handshake with an
  attacker `Origin` and reports endpoints that upgrade (101) without an Origin check — cross-site
  WebSocket hijacking. VulnLab's `/ws` was already Origin-blind (vulnerable); added an Origin-checking
  `/safe/ws` twin that rejects a cross-site handshake with 403. `Scripts/cswsh-dod.sh` PASS (vulnerable
  `/ws`, clean `/safe/ws`). This completes the named post-1.0 buildable checks (smuggling, CSWSH,
  cache-poisoning). WS fuzzing and per-message authz (WSX-002/004/…) remain.
- 2026-11-13 — **Smuggling Probe (F23 ADV-030/031, M19b)**: `SmugglingProbe` builds byte-exact CL.TE
  and TE.CL timing probes (conflicting Content-Length vs Transfer-Encoding framing a normalizing client
  can't send — the payoff of the "raw bytes are the truth" engine) and classifies a vector by its
  timing differential against a clean baseline. `gulp-cli smuggle`; VulnLab `/smuggle` emulates the
  desync hang (5 s on a CL+TE conflict) and `/safe/smuggle` rejects it; `Scripts/smuggle-dod.sh` PASS
  (CL.TE/TE.CL → VULNERABLE on the vuln route, no differential on the safe twin). 488 tests. The guided
  confirmation/exploitation workbench (ADV-032) stays deferred and is never auto-run.
- 2026-11-13 — **Parameter Discovery (F23 ADV-020) + web cache poisoning (F28 WCP-001)**: `ParamMiner`
  brute-forces hidden query parameters and reports the ones the server processes — a canary reflected
  in the body (`reflected`) or a status/length change isolated by binary search (`behavior change`);
  `gulp-cli discover-params` + VulnLab `/params` + `Scripts/paramdisc-dod.sh` (finds hidden
  `debug`/`trace`, clean on the safe twin). `CachePoisoningCheck` flags an unkeyed header
  (`X-Forwarded-Host`) reflected into a **cacheable** response (the cacheability is what separates it
  from host-header injection); VulnLab `/cache` + a step in `m11c-checks-dod.sh`. 486 tests; the live
  m11b DoD is unchanged (0 unexpected). Both are Param-Miner/cache-poisoning equivalents of Burp's
  Param Miner and cache-poisoning scanner.
- 2026-11-13 — **Server-side parameter pollution (F23 ADV-022)**: `ParamPollution.classify` duplicates
  each query parameter with a canary and labels how the server resolves the collision — `first-wins`,
  `last-wins`, `concatenated`, or `both` reflected. A last-wins/concatenated quirk is the primitive
  that smuggles a value past a front-end/WAF that only inspects the first occurrence. `gulp-cli pollute`,
  VulnLab `/pollute` (last-wins, vulnerable) vs `/safe/pollute` (first-wins), `ParamPollutionTests`,
  `Scripts/pollute-dod.sh` PASS. 491 tests. Deliberately a dedicated CLI analysis tool, not a scanner
  family, so it never adds probes to the differential-scan budget or false-fires on reflecting routes.
  Deviation: the first unit-test fixtures used a one-letter firstValue (`a`) that was an incidental
  substring of the surrounding `name=` text, misclassifying last-wins as both; fixtures now use distinct
  non-overlapping tokens. ADV-021 (mine candidates from the app) is already covered by JS Recon's param
  mining feeding `discover-params`.
- 2026-11-13 — **WebSocket per-message authorization (F23 WSX-004, acceptance test 8)**: `WSAuthzProbe`
  (a pure classifier in `GulpScanner`) + `gulp-cli ws-authz` replay a privileged WS message over two
  fresh `openWebSocket` connections — one under a privileged identity, one under a stripped identity
  (both set via `Cookie: sid=…` on the handshake) — and report whether the privileged action still
  succeeds for the stripped identity (`missing` / `enforced` / `inconclusive`). VulnLab gained two
  differential sockets: `/ws/authz` authorizes only at the handshake (every upgraded connection gets
  the secret → flagged) and `/safe/ws/authz` re-checks identity per message (a non-admin is refused →
  enforced). `WSAuthzProbeTests` (4) + `Scripts/wsauthz-dod.sh` PASS end-to-end against live VulnLab.
  496 tests. This is the WS-level twin of the Authz Matrix and has no built-in Burp equivalent (there
  it is a manual Repeater exercise). Also fixed two mislabeled requirement IDs: the CSWSH command and
  DoD were commented `WSX-004`; CSWSH is `WSX-003`. Remaining WS items (WS Fuzzer WSX-002/005/007,
  sub-protocol decode WSX-006, scripted sequences WSX-008) stay post-1.0.
- 2026-11-13 — **WS Fuzzer (F07 §2.6, WSX-002)**: `WSFuzzEngine` (in `GulpFuzzer`) iterates a
  `§…§`-marked message template's payloads as frames over **one** persistent `openWebSocket` connection
  — not the HTTP exchange loop — reusing only the F07 payload generators/processors (`PayloadSet`,
  `PayloadPipeline`) and the grep/extract/reflection analysis, for which `ResponseAnalyzer` gained a
  text-based `analyze(text:payloads:)` shared with the HTTP path. A testable `WSFuzzChannel` protocol
  abstracts the socket (`LiveWSChannel` in the CLI wraps `WebSocketSession` with an ordered reply queue
  + per-exchange timeout). `gulp-cli ws-fuzz`, VulnLab `/ws/fuzz` (a greeting-less echo so the first
  reply lines up with the first send), `WSFuzzerTests` (4) + `Scripts/wsfuzz-dod.sh` PASS (3 payloads
  over one socket, only the grep-matching reply flagged, echoed value extracted). 500 tests. Burp's
  Intruder does not fuzz WS messages natively.
- 2026-11-13 — **JS Recon asset diff (F27 JSR-009, test 4)**: `JSRecon.inventory(js:sourceMap:)` builds
  a recon surface (mined params, interesting literals, recovered source paths) for one asset, and
  `JSRecon.diff(from:to:)` reports what a redeploy added or removed — the newly-added endpoints/params
  are the under-tested surface a new release introduces. `gulp-cli js-recon --baseline <old>` diffs two
  live assets (refactored to build inventories via the new helper); VulnLab `/recon/app.v2.js` (+ map)
  is a superset of `/recon/app.js` adding `adminPanel`, `ssoToken` and an `admin.corp` host.
  `JSReconDiffTests` (3) + `Scripts/jsrecon-diff-dod.sh` PASS (added surface surfaces, nothing falsely
  removed). 503 tests.
- 2026-11-13 — **Smuggling confirmation workbench (F23 ADV-032)**: `SmugglingProbe.confirmation` builds
  a desync proof — an attack that smuggles an invalid `GPOST` request-start, plus an innocuous
  follow-up whose 4xx proves the desync. (Corrected 2026-11-20: this can affect other users when the
  front end reuses back-end connections across users, so it is never auto-sent.) `gulp-cli smuggle-confirm`
  is the guided workbench: **dry run by default** (prints the request pair with prominent warnings,
  sends nothing), **scope-gated** (refuses an out-of-scope host even when authorized), and it **never
  auto-sends** — a live send needs the explicit `--i-am-authorized` flag. `SmugglingConfirmTests` (3,
  verifying the conflicting framing, the GPOST prefix, and that the CL.TE Content-Length equals the
  smuggled tail length) + `Scripts/smuggle-confirm-dod.sh` (dry-run prints the warning + pair + does not
  send; authorized-but-out-of-scope is refused) PASS. 506 tests. This matches ADV-032's letter:
  "construct a follow-up that proves desync, with strong warnings and scope gating; never run
  destructive confirmations automatically."
- 2026-11-13 — **OAST-correlated blind injection over WebSocket (F07 §2.6, WSX-005)**: `gulp-cli
  ws-oast` registers an OAST payload (reusing `GulpOAST.InteractshClient`), opens one socket, carries
  the payload URL in a WebSocket message, then polls and correlates the out-of-band DNS + HTTP
  interactions back to that payload — a blind SSRF reachable only over the socket. VulnLab gained
  `/ws/ssrf` (a WS handler that, on a message carrying a Beacon-domain URL, fetches it via the existing
  `OASTLab.fetch` outbound helper). `Scripts/wsoast-dod.sh` PASS end-to-end against the dev Beacon +
  VulnLab (a WS message yields correlated `dns, http` interactions). gulp-cli gained a direct `GulpOAST`
  dependency. No unit test (live-only integration; covered by the DoD). 506 tests. Burp's Collaborator
  is not wired into WebSocket messages, so this has no Burp equivalent.
- 2026-11-13 — **WS sub-protocol decode + auto insertion points (F01 §2.4, WSX-006/007)**:
  `WSSubprotocolCodec` (in `GulpCodec`) detects and splits the transport envelope of socket.io,
  graphql-ws, SignalR, STOMP and bare JSON from their editable payload, byte-exact
  (`encode(decode(x)) == x`), with a raw/hex fallback — shared by WS history, the WS Repeater and the
  WS Fuzzer. `autoInsertionPoints` (WSX-007) wraps each JSON string/number *value* (never keys or the
  envelope) in `§…§`, and `gulp-cli ws-fuzz --auto` turns a captured message into a fuzz template
  automatically (e.g. `{"q":"PH"}` → `{"q":§"PH"§}`, socket.io `42[…]` keeps its `42` prefix).
  `WSSubprotocolTests` (10) + the `--auto` block in `Scripts/wsfuzz-dod.sh` PASS. 516 tests (the lone
  non-pass in the full run is the documented GulpDiff F13 perf flake under CPU contention, which passes
  in isolation at 0.42 s; unrelated to these changes). Burp needs an extension to understand WS
  sub-protocols.
- 2026-11-13 — **Scripted WebSocket sequences (F15 §2.3, WSX-008)**: `WSScript`/`WSScriptMatch` (in
  `GulpCodec`) model and evaluate a `send / expect / expect-regex` sequence (with optional per-step
  `@<ms>` timeouts, `#` comments) — the "send A, await a frame matching X, then send B" shape stateful
  protocols need (handshakes, subscribe/ack, login challenges). `gulp-cli ws-script` runs the script
  over **one** `openWebSocket` connection via an ordered reply queue, matching each received frame in
  order and stopping at the first miss. `WSScriptTests` (3) + `Scripts/wsscript-dod.sh` PASS (a full
  send/expect run against VulnLab `/ws`, plus a deliberately wrong expectation that stops the run). This
  completes the WebSocket workbench at the engine/CLI level (WSX-002 through WSX-008); only the macOS WS
  workbench UI remains, which cannot be verified on Linux.
- 2026-11-13 — **macOS UI: Sequencer (F11) and JS Recon (F27) screens**: added `SequencerView` and
  `JSReconView` to `GulpFeatures`, wired into the sidebar `Tool` enum and `ProjectWindow` (replacing
  their placeholder). Both are self-contained views over **pure, already-tested** engines —
  `GulpSequencer.analyze(tokens:)` → `SequencerReport` (verdict, entropy estimate, NIST-style test
  table) and `JSRecon.inventory`/`diff` (recovered sources, mined params, literals, deploy diff) — so
  they add no new untested logic, only presentation. They follow the exact pattern of the 28 existing
  views (`@MainActor @Observable` model + SwiftUI body under `#if canImport(AppKit)`), use only SwiftUI
  constructs already proven in this codebase (`HSplitView`, `Table` with an `Identifiable` row wrapper,
  `LabeledContent`, `ContentUnavailableView`), and were written against the engines' real public
  signatures (e.g. corrected to the actual `TokenVerdict` cases after reading the source). **Honesty
  caveat:** the Linux build only confirms the `#if canImport(AppKit)` guard (these compile to empty on
  Linux, as do all ~7.2k lines of `GulpFeatures`); the SwiftUI bodies compile for real only on the
  **macOS CI leg**, which cannot run in this Linux environment. Remaining macOS-gated UI: Assistant
  (needs an AI provider + key), DOM-probe (needs a live browser), the GraphQL / Authz-Matrix /
  Extensions screens, and the in-process JavaScriptCore extension host.
- 2026-11-13 — **macOS UI: Assistant, GraphQL, Extensions and DOM-Probe screens + a latent dependency
  fix**: added `AssistantView` (F18 — the pre-send redaction gate over the pure `GulpAI.Redactor`,
  showing exactly what is masked before a prompt leaves the machine), `GraphQLWorkbenchView` (F23 §5 —
  introspection → `GulpCodec.GraphQLSchema.parse`, rendered SDL, query/mutation surface),
  `ExtensionsView` (M15 — `GulpExtensions.ExtensionManifest.decode`, auditing declared runtime,
  permissions and hooks) and `DOMProbeView` (M13a — the shipped `GulpBrowser.DOMProbe.instrumentation`
  plus decoding a captured `__gulpReport` into a source→sink finding). All four are self-contained over
  **pure, already-tested** engine entry points. Wired into the `Tool` enum and `ProjectWindow` (the
  `domProbe` tool is new; `assistant`/`graphql`/`extensions` replace their placeholder). **Found and
  fixed a real latent bug:** `GulpFeatures` did not declare `GulpScanner`, `GulpSequencer`,
  `GulpExtensions`, `GulpCrawler` or `GulpBrowser` as dependencies, yet its own existing views (Scanner,
  Crawler, …) and these new ones import them — so the macOS build of this target would have failed on a
  missing-module error; added all five to the target's `dependencies`. Linux build and arch-check pass
  (these compile to empty on Linux); the SwiftUI bodies and the dependency fix are compiled for real
  only by the macOS CI leg. Only the Authz-Matrix screen (which needs live multi-identity sending via
  the workspace) and the in-process JavaScriptCore extension host remain macOS-gated.
- 2026-11-13 — **macOS UI: Authz Matrix screen (F23 §1)**: added `AuthzMatrixView`, session-backed
  (like the Scanner), wired into `ProjectWindow`. It replays the requests queued for analysis
  (`session.scanRequests` → `session.runAuthzMatrix`) as every configured identity and renders the
  verdict grid (requests × identities), with a bypassed cell — a privileged response under a lower
  identity — called out in red. The run is a cancellable task; the main thread never waits on the
  network. Written against the verified workspace signatures (`runAuthzMatrix` returns
  `AuthzMatrixResult` with `requests`/`columns`/`cells`/`cell(request:identity:)`, `AuthzVerdict` cases
  authorized/enforced/bypassed/same/needs-review). With this, **every named macOS tool screen is now
  written and wired** (Sequencer, JS-Recon, Assistant, GraphQL, Extensions, DOM-Probe, Authz-Matrix);
  all compile to empty on Linux and are verified for real only by the macOS CI leg. The single
  remaining macOS-gated item is the **in-process JavaScriptCore extension host** — an alternative
  extension runtime that needs Apple's JavaScriptCore framework, which does not exist on Linux at all,
  so it can be neither written against nor compiled in this environment (the process-based extension
  host, M15, is already shipped and tested).
- 2026-11-13 — **In-process JavaScriptCore extension host (F18 EXT-002/004, the `js` runtime)**: wrote
  `GulpScript.JSExtensionHost`, the macOS-only alternative to GulpExtensions' out-of-process host — it
  runs an extension's script in a `JSContext` and calls into it directly (`initialize` → registered
  passive checks; `passiveCheck` → findings, honoured only with the `create-issues` permission), gating
  the host API it exposes (`host.log`, `host.httpSend`) by the same manifest permissions. **Architecture
  note (and a correction):** JavaScriptCore is an Apple framework, and `arch-check` forbids an engine
  from importing one — my first draft put the host in the `GulpExtensions` engine and `arch-check`
  caught it; I moved it to `GulpScript`, the platform-capability module the architecture already
  reserves for exactly this ("JavaScriptCore runtime and in-process JS extension host"), and added its
  `GulpExtensions` dependency. The whole file is behind `#if canImport(JavaScriptCore)` (empty on Linux,
  the Linux build and arch-check pass), so its JavaScriptCore usage is compiled only by the macOS CI
  leg. Added a reference `js`-runtime example extension (`SDK/examples/js-header-leak/`). The
  `@unchecked Sendable` on the host carries the required justification comment (the `JSContext` is
  confined to synchronous calls and never shared across tasks). **With this, every leftover item is now
  implemented**; what cannot be verified in this Linux environment (the SwiftUI screens, the
  JavaScriptCore host) is exactly the code the project intentionally gates to macOS, and the macOS CI
  leg is the verifier.
- 2026-11-13 — **M20 release tooling (doc 02 §8)**: wrote the missing `Scripts/release.sh` (archive →
  sign helpers inside-out with Hardened Runtime + timestamp → notarize with notarytool → staple → build
  + notarize + staple the DMG → Sparkle appcast) and `ExportOptions.plist` (developer-id, manual
  signing), closing the `make release` gap. It runs on macOS with the release secrets as environment
  variables; `bash -n` syntax-checks it here and the plist validates. The remaining M20/M17 items
  (system-proxy toggle, Sparkle UI, accessibility audit) are in the macOS app (`GulpFeatures`), which
  can't be built or verified on Linux.
- 2026-11-13 — **M18 AI assistant core (F22 AI-001/003/013)**: `GulpAI` gained the provider-agnostic
  core — an `LLMProvider` protocol, a wire-format-tested `AnthropicProvider` (Messages API, tool use,
  usage), a `Redactor` masking auth/cookies/tokens/keys before egress, and a bounded `Agent` loop with
  step + request budgets, a cancel/panic stop, and redaction of every tool result. Verified against a
  scripted mock provider (482 tests total). The live tool-surface wiring, Keychain key and consent/chat
  UI are provider-/macOS-gated.
- 2026-11-13 — **M15 out-of-process extension host (F18 EXT-002/003/004)**: `GulpExtensions` gained the
  JSON-RPC extension runtime — manifest + approved permissions enforced at the API boundary, LSP-style
  length-prefixed framing, the `ExtensionHost` actor (initialize → declared checks; passive-check
  gated on `create-issues`; inbound `http/send` denied+logged without `http-send`), and
  `ProcessExtensionTransport` over a child's stdio. Verified against a mock transport **and a real bash
  subprocess** (475 tests total); `SDK/examples/header-leak` is a dependency-free sample extension. The
  in-process JS runtime (JavaScriptCore) and the manager UI stay macOS-gated.
- 2026-11-13 — **M13a/M13b browser automation + DOM Probe (engine core)**: built the Chrome DevTools
  Protocol client (`CDPClient`, transport-abstracted → unit-tested against a mock; command
  id-correlation, event routing, remote-error handling), a launch helper (`BrowserAutomation`: flags +
  `DevToolsActivePort` → `ws://` endpoint + engine WebSocket connect), and the DOM Probe — a
  taint-tracking instrumentation (`dom-probe.js`, `.embedInCode`-embedded so what's tested is what
  ships) that wraps DOM sinks and reports source→sink flows via a CDP binding. Verification is split by
  the environment (swift container has no Chromium libs; host has no Swift): the CDP client + launch
  helper by Swift tests (469 total), and the instrumentation against **real headless Chromium** via
  Node+Playwright (`Scripts/dom-probe-check.mjs` / `Scripts/m13a-dom-probe-dod.sh`, gated-skip in CI) —
  it reports the planted DOM XSS on VulnLab `/spa` (location.hash→innerHTML) and nothing on `/safe/spa`.
  The swift↔real-browser crawl/login/passkey integration and the macOS UI remain for a Chromium+Swift
  host.
- 2026-11-13 — **Sequencer built (F11) — outperformance increment**: `GulpSequencer`, a pure-Swift,
  Linux-testable token-randomness analyzer closing a whole named Burp tool Gulp lacked. Token → symbols
  and bits (with constant prefix/suffix stripping), a NIST SP 800-22-style battery (monobit, block
  frequency, runs, longest run, approximate entropy, cumulative sums) + a FIPS poker χ² + a per-position
  character χ², each with a p-value from an in-house regularized incomplete gamma (unit-tested against
  `Q(1,x)=e^-x` and `Q(½,x)=erfc(√x)`). Headline effective entropy = per-position Shannon × battery
  pass-rate. `gulp-cli sequencer` captures (cookie/regex) or loads a token list; VulnLab `/token/weak`
  (counter) rates Extremely poor and `/token/strong` (CSPRNG) Excellent (`Scripts/sequencer-dod.sh`, in
  CI). 11 new tests (462 total). This reverses product decision #7's deprioritization under the owner's
  standing goal to outperform Burp's full feature set (recorded in docs/07). The Swift-Charts UI and
  project-saved runs stay macOS/post-1.0 carry-overs.
- 2026-11-13 — **M11c check catalog — unrestricted file upload (SCN-073)**: `active.upload` re-sends a
  multipart upload with a dangerous extension + content-type (`.php`/`.svg`/`.html`/`.jsp`) and raises
  when the server accepts it exactly as it accepted the benign file. The body is rewritten through a
  lossless Latin-1 round-trip so binary file content survives, and the acceptance test strips both
  filenames so a reflected name doesn't defeat the comparison. VulnLab `/upload` (stores anything) vs
  `/safe/upload` (image-extension allowlist, 400 otherwise). DoD `m11c-checks` step 6 + a unit test;
  m11b DoD still 0 unexpected. This completes the Linux-buildable P1 catalog — only CSPT (browser-
  gated) remains.
- 2026-11-13 — **Per-feature review written** (`docs/10-feature-review.md`): a feature-by-feature
  review of every shipped area, each backed by the specific `@Test` cases and the executable DoD that
  prove it (451 tests across 25 targets; 24 DoD scripts). Complements `08` (architecture) and `09`
  (Burp comparison). It also records an honest test-coverage gap list found while writing it —
  `IntegrationTests` is a stub (no end-to-end flow), DB upgrade migrations are untested, and a few
  suite-advertised requirement IDs (GOV-003, BCN-005, CRL-009/010, HIS-023) have no dedicated named
  test. `09` was refreshed to mark the P1 check catalog as landed.
- 2026-11-13 — **M11c check catalog — NoSQL / XPath / LDAP injection families**: added three boolean-
  differential active checks. NoSQL (`$where`) uses JavaScript `&& '1'=='1'` / `'1'=='2'` pairs; XPath
  uses `string-length()` (a function a SQL engine rejects, so it is distinguished from SQL injection on
  real targets, not only in the lab); LDAP uses a `*` wildcard that matches where a random literal does
  not, with both payloads stripped from the comparison so a merely-reflecting endpoint can't look like a
  filter. VulnLab gained `/nosql/find`, `/xpath/user`, `/ldap/login` with safe twins; the m11c-checks
  DoD asserts each fires and its safe twin is clean, and the live m11b DoD still reports 0 unexpected /
  0 missing (no cross-matching on the SQLi/XSS/SSTI routes). The one subtle bug: the LDAP wildcard
  oracle first false-positived on every reflecting endpoint until the invalid probe's value was also
  stripped from the similarity test.
- 2026-11-13 — **M11c check catalog — prototype pollution (SCN-070) + mass assignment (SCN-072)**:
  added `PrototypePollutionCheck` (unsafe-gated; injects a random marker under `__proto__`, re-sends a
  clean request, confirms the marker leaks on an object that never set it) alongside the already-landed
  CORS, host-header, JWT and mass-assignment checks. VulnLab gained `/pp/merge` + `/profile/update`
  with `/safe/` twins. New `Scripts/m11c-checks-dod.sh` (differential: the vuln routes fire, the safe
  twins stay clean) wired into CI and the local gate; unit tests in `ActiveScanTests` for both. A
  `set -u` bug in the DoD harness (a command substitution read `$path` before it was assigned, so every
  scan collapsed onto one shared project and the safe twin inherited the vuln finding) was the only
  real defect — the scanner's per-project issue isolation, the lab and the check were all correct.
- 2026-11-13 — **Executed review run (docs/11-review-run.md)**: ran the full suites in-turn —
  `swift test` = **519 tests / 60 suites / 0 fail (12.4 s)**; the 37 `Scripts/*-dod.sh` acceptance
  scripts = **37/37 pass** after one fix (m9 confirmed by running to completion in 2198 s: query 879ms
  / search 3ms pass with margin; the long wall is throttled 1M-row data generation only — 92.8% CPU,
  O(n)). The executed
  review found a **real recon false-positive**: `recon.endpoint` fired on `/safe/recon/app.js` because
  `ScanLab` (dispatched before `ReconLab` in `Routes.swift`) stripped `/safe/` and shadowed ReconLab's
  clean twin with its endpoint-laden JSRecon bundle. Fixed: `ScanLab` returns nil for `/safe/recon/*`;
  `recon-dod.sh` now PASS. Deviation: none — fixture-routing bug only.
- 2026-11-13 — **Vulnerable JS libraries** passive check (`passive.vuln-js-library`): fingerprints
  jQuery/lodash/Bootstrap/Moment/Handlebars/AngularJS/DOMPurify versions from filenames, banners and
  VERSION strings against a bundled advisory dataset, always-on; VulnLab `/libs/old`(+safe). 446 tests.
- 2026-11-13 — **Check Recipes (SCN-060/061/064, passive) implemented**: declarative no-code checks
  (`CheckRecipe`/`RecipeMatcher`) with path/content gates, header/body/status/regex matchers and OR
  groups, and a templated issue; they join the passive scan via `PassiveScanSettings.recipes`;
  `gulp-cli scan passive --recipes <file|dir>` loads a JSON recipe library; `Scripts/recipe-dod.sh`
  PASS (added to CI/gate). Recipes are JSON (YAML a thin future layer); active recipes + editor remain.
  Closes Burp-comparison gap #3 for the no-code-check half.
- 2026-11-13 — **Capstone progress**: architecture review (`docs/08-architecture-review.md`) backed
  by `Scripts/arch-check.sh` (dependency-direction + platform rules enforced in CI; removed
  GulpScanner's 3 unused deps); Burp Suite comparison (`docs/09-burpsuite-comparison.md`); first
  outperformance increments shipped — secret & JS recon (F27) and formatted reporting (F19).
- 2026-11-13 — **Reporting (F19/M16) implemented**: `GulpReport` HTML + bug-bounty Markdown renderers
  over the issue model; `ProjectSession.generateReport`; `gulp-cli report`; `Scripts/report-dod.sh`
  PASS (added to CI/gate). PDF export and the macOS report view remain. The GulpReport stub is now
  real content.
- 2026-11-13 — **M13b GraphQL implemented** (local Linux gate): GulpCodec GraphQL (detect, introspect,
  schema parse/render, body build), Scanner GraphQL-variable insertion points, workbench checks
  (introspection-enabled, broken-object-authz), VulnLab `/graphql`+`/safe/graphql`, `gulp-cli graphql
  introspect|scan`; `Scripts/m13b-graphql-dod.sh` PASS. DOM Probe deferred to M13a's browser work.
- 2026-11-12 — **M11c partial**: GRP-005's Scanner half (protobuf-field insertion points), crawl-and-
  audit (`scan crawl-audit`), the OpenAPI scan (`scan api`), SCN-036 consolidation, SCN-037 re-test
  (`scan retest`), SCN-038's scan-wide budget; `Scripts/m11c-dod.sh` PASS. The P1 checks followed on
  2026-11-13 (entries above).
- 2026-11-12 — **M12b implemented** (local Linux gate; macOS UI unverified): `AuthzAnalysis` verdict
  logic, `runAuthzMatrix` orchestration (replay as identities under ScopeGuard, raise
  `authz.broken-access-control`), VulnLab `/safe/api/orders/{id}` enforcing twin, `gulp-cli authz
  orders`; `Scripts/m12b-dod.sh` PASS. Carry-overs above.
- 2026-11-12 — **M12a implemented** (local Linux gate; macOS UI unverified): GulpSession cookie jar,
  identities, macros + runner, session rules, validity check and request signing (DPoP RFC 9449, HTTP
  Message Signatures RFC 9421, AWS SigV4); GulpWorkspace session hooks (rules first, signer last,
  response-side cookie/nonce/staleness) with single-flight re-auth; VulnLab `/signed/*` independent
  verifiers and `/session/expire`; `gulp-cli session sign|reauth`; `Scripts/m12a-dod.sh` PASS. ECCurve
  is now Codable. Deviations and carry-overs in doc 07 and the status block above.
- 2026-11-12 — **M11b implemented** (local Linux gate; macOS views unverified): GulpScanner
  insertion points, `ActiveScan` engine, scan presets and the P0 active checks (reflected/stored XSS,
  SQLi error/boolean/time, command injection time/OAST, SSTI, path traversal, XXE in-band/OAST, SSRF
  OAST, open redirect, CRLF) with 14 issue definitions; VulnLab scan lab + safe twins +
  `Fixtures/vulnlab-active.json`; workspace scan service; `gulp-cli scan active|verify-active`;
  Scanner → Audit pane and History "Actively scan"; unit tests against an in-process fake app with
  simulated timing; `Scripts/m11b-dod.sh` PASS. Deviation: canaries aren't seeded (F08 §5; doc 07).
  Fixed on the way: absolute-form detection in `DerivedFields`; case-sensitive multipart boundaries.
- 2026-11-11 — **M11a implemented** (local Linux gate; macOS views unverified): GulpHTTP
  `ResourcePool` (global/per-host concurrency, backoff, panic pause; governed sends) and HTTP/2
  stream cancellation; GulpCrawler (normalization, page parser, forms, robots/sitemap, frontier,
  budgets, cookie jar, re-auth hook); GulpOAST interactsh client (checked against the interactsh
  source) + engine transport; schema v7 OAST rows; Beacon package `BeaconKit` + `gulp-beacon --dev`
  (HTTP API + capture, UDP DNS); workspace network settings, active-task registry + panic stop,
  crawl service, OAST service (`beacon()` tag, recorder linking, polling, Test Beacon); VulnLab crawl
  lab, blind `/fetch`, `/lab/burst`; CLI `crawl`, `oast`, `governor`; Crawl/Beacon views and the
  panic-stop toolbar item; `Scripts/m11a-dod.sh` PASS. Deviation: interactsh's AES mode is CTR, not
  GCM (F10 corrected). Fixed on the way: HTTP/2 cancellation ran streams to completion; governed
  sends were capped at 6 connections per host.
- 2026-11-11 — **M10a implemented** (local Linux gate; macOS view unverified): GulpCore issue model;
  GulpStore issues (dedup upsert keeping triage, evidence capped, overrides, notes, filters,
  Notebook links; schema v6); GulpScanner definitions catalog and passive checks; live passive
  scanning from a persisted cursor; JSON/SARIF export; manifest verification; VulnLab security
  baseline + PassiveLab planted routes with /safe/ twins + `vulnlab-issues.json`; Dashboard issues
  view; `gulp-cli issues|scan`; `Scripts/m10a-dod.sh` PASS. Fixed on the way: deleting a History row
  (or replacing a streaming one) failed on foreign keys from rows without ON DELETE.
- 2026-11-10 — **M10b implemented** (local Linux gate; macOS views unverified): GulpCodec protobuf
  wire codec, RPC framing (gRPC, gRPC-Web binary/text, Connect streaming/unary) with trailers,
  descriptor models, `.proto` parser, named decode + JSON, reflection messages; VulnLab gRPC lab +
  `Fixtures/grpc/vulnlab.proto`; workspace RPC service (schemas inline in settings, reflection
  fetch, decode, edit, send from Repeater); Fuzzer protobuf positions; grep sees trailers;
  `gulp-cli grpc`, `fuzz --grpc-field`; Protobuf tab, gRPC Schemas sheet, Repeater message editor;
  `Scripts/m10b-dod.sh` PASS. Deviation: schemas inline instead of blobs (doc 07). Fixed on the
  way: HTTP/2 pool race on cold concurrent bursts; CRLF-as-one-Character splitting bugs.
- 2026-11-10 — **M9 implemented** (local Linux gate; macOS views unverified): GulpQuery (GulpQL lexer,
  parser, Codable AST, field catalog, evaluator, SQL lowering with never-NULL comparisons and
  two-sided ranges); GulpStore query layer (push-down + residual, `gulpql_regexp`, cached residual
  paging, planner statistics), search (trigram prefilter + verification, decoded bodies, regex
  prefilter, short-query scan, reindex), Notebook rows (blob snapshots), coverage rows, connection
  view, synthetic seeder; schema v5 (lowercase hosts, Notebook index and `truncated`); workspace
  queries, saved filters, Logger settings, Notebook service, CoverageService; GulpQL in intercept
  rules and M&R conditions; VulnLab reflected-XSS lab; Logger/search/Notebook views; CLI commands;
  `Scripts/m9-dod.sh` PASS. Fixed on the way: SQLite scanned instead of using `ix_ex_status` for a
  one-sided range (now two-sided); VulnLab's home page linked `/xss/html`, which didn't exist;
  GulpFeatures didn't declare its GulpFuzzer dependency (M8).
- 2026-11-10 — **M8 implemented** (local Linux gate; macOS view unverified): GulpFuzzer positions
  (`§…§`, auto-mark), lazy payload sources (lists, files, numbers, dates, brute force, null, same as
  base, recursive grep) and processors (incl. Decoder ops and Transform Tags), the four attack
  types, grep match/extract, reflection, baseline anomalies, the attack runner (lanes, rps cap,
  delays, retries, stop conditions, pause/resume/cancel, ScopeGuard) with saved attacks (schema
  tables `fuzzer_attacks`/`fuzzer_results`), content discovery with soft-404 fingerprints, bundled
  wordlists; VulnLab `/login` (single-use CSRF), `/account`, `/admin`, backup files; Fuzzer view and
  Send to Fuzzer; `gulp-cli fuzz|discover|wordlists`; `Scripts/m8-dod.sh` PASS. Fixed on the way:
  ScopeGuard refusals were counted as sent + errors ("sent 9, errors 9") — now `refused`.
- 2026-11-09 — **M7 implemented** (local Linux gate; macOS views unverified): GulpCodec transform
  registry (URL/HTML/Base64/32/58/hex/numbers/escapes/JSON/compression/hashes incl. SHA-3/HMAC/
  converters), Smart Decode, Transform Tags + TransformTagHook (Repeater/Fuzzer only), project tag
  variables; GulpDiff (Myers, word/byte, line localisation, positional alignment for same-shape
  inputs, pre-diff transforms); JWT Workbench core (all JWS algorithms, PEM/JWK/JWKS, attack
  helpers, cracking); VulnLab JWT lab (`/api/login`, `/api/me`, `/safe/api/me`, key/JWKS);
  `gulp-cli decode|diff|jwt`, `repeater --var/--no-tags`; ToolInbox; `Scripts/m7-dod.sh` PASS.
  Fixed on the way: unicode-escape didn't escape backslashes (round-trip test); a formatter-wrapped
  `..<` parsed as two statements; Myers paired changes far apart in repetitive text.
- 2026-11-09 — **M6b implemented** (local Linux gate; macOS menus unverified): GulpCodec traffic
  formats (HAR in/out with `_gulp` raw bytes, Postman v2.1, XML proxy history, Caido, sitemap/URL
  lists, OpenAPI 3.x/Swagger 2.0 JSON with schema-aware values, CSV); ImportExportService (dedup by
  target + bytes + start time, `imported` tag, `.gulp` merge and export); schema v4 (request-blob
  index, `audit_log`); MCP stdio server with ScopeGuard, approval policy and audit log;
  `gulp-cli project import|export|info|audit`, `gulp-cli mcp`, `send --repeat` `{n}`; VulnLab
  `/openapi.json` + `/api/*`; `Scripts/m6b-dod.sh` PASS.
- 2026-11-09 — **M6a implemented** (local Linux gate; macOS UI unverified): site map trie +
  live service + inferred links (TGT-001…003), endpoints/notes/Analyze target/Delete branch
  (TGT-002/004/007/008), filters incl. 404/MIME and `{id}` folding (TGT-005/006), schema v3
  `site_map_notes`; scope rules, ScopeGuard, `in_scope` recompute (TGT-020…023), proxy uses scope
  (TGT-024/PRX-045), scope JSON (TGT-025); Repeater out-of-scope confirmation; `gulp-cli scope` /
  `target`, `proxy --use-scope`, `repeater --allow-out-of-scope`; VulnLab home page `/`;
  `Scripts/m6a-dod.sh` PASS. Fixed: closing a session now cancels and awaits the site map
  listener first (a concurrent read made the close checkpoint fail with "database is locked").
- 2026-11-09 — **M5 implemented** (local Linux gate; macOS views unverified): Repeater REP-001…007,
  REP-010 (groups, Send group, results), REP-012 (WebSocket tabs), REP-016 (streaming + Stop), REP-017
  (paste cURL/fetch/raw); PRX-035; engine HTTP-011 (pipelining), HTTP-012 (Basic + Digest), HTTP-013
  (throttle), HTTP-030…036 (group modes, single-packet h2/h1, timing report, TCP_NODELAY), redirect
  following. `Scripts/m5-dod.sh` PASS: a single-packet h2 group redeems the VulnLab coupon 20/20
  (sequential control: once), last-byte sync over HTTP/1 20/20, a pasted cURL reproduces its request,
  `/sse` streams in a Repeater tab. GitHub Actions minutes ran out here; from this point the Linux
  job was reproduced locally in Docker (doc 07, 2026-11-09).
- 2026-11-08 — **M4b DONE** (CI run 42504816428, `0b0c6f7`; DoD `Scripts/m4b-dod.sh` + `Scripts/m4b-browser.sh`: PASS):
  - Streaming (PRX-050/HIS-007): responses go to the client as they arrive; the row is recorded
    pending at the first bytes, refreshed every 250 ms with what arrived (live length/duration),
    completed in place; arrival marks feed the History Events tab (SSE id/event/data/time) and a
    chunk timeline. VulnLab `/sse[?n=]`.
  - WebSockets (PRX-030…034): upgrade on a fresh HTTP/1.1 connection, then a per-direction frame
    pump forwarding original frame bytes; with WS Match & Replace rules or WS Intercept, whole
    messages are rewritten/held and re-framed only if changed; recording in `ws_connections` /
    `ws_messages` (edits and drops kept), permessage-deflate decoded for the record; Proxy →
    WebSockets History tab; VulnLab `/ws` echo; `gulp-cli ws`, `history --websockets`.
  - Gulp Browser (BRW-001…004): discovery (Chrome for Testing download on macOS), isolated
    per-listener profile, `--proxy-server` + `<-loopback>` bypass removal, SPKI pins of the CA and
    shared leaf key (the proxy now sends the CA after the leaf), `--disable-quic` and quiet-session
    flags; ⌘⇧O toolbar button; launched browsers terminated on quit; `gulp-cli browser`.
    `GULP_SUPPORT_DIR` points the workspace at one folder with a file CA store (CI, automation).
  - Caught by CI: the HTTP/1 handler unwrapped raw WebSocket writes as request commands (writes now
    pass through after a 101); the upgrade exchange's row wasn't flushed before the
    `ws_connections` foreign key referenced it; a streamed row raced the first-chunk check in a test.
  - Decisions: WS relay / WS Intercept / permessage-deflate / no RFC 8441 rows in `07-decisions.md`.
- 2026-11-08 — **M4a DONE** (CI run 42500664587, `dee2424`; DoD `Scripts/m4a-dod.sh`: PASS):
  - GulpCodec `RequestExport`: Copy as cURL (exact bytes via ANSI-C quoting), PowerShell, fetch,
    Python requests (bytes literal), Go.
  - GulpProxy `MatchReplace`: rules on a byte-exact Latin-1 view (headers add/rewrite/remove, bodies
    with Content-Length kept right, first lines, query/form params), presets, `MatchReplaceHook`
    (proxy always, tools per rule); the engine records the original of any edited request.
  - GulpProxy `InterceptQueue`: request/response toggles, AND/OR regex conditions (line-anchored),
    held items await Forward (edited) / Drop; wired into HTTP/1 and HTTP/2 client paths.
  - GulpUI `MessageEditor` (+ Linux-tested `MessageText`/`MessageInspection`); GulpFeatures Proxy
    tabs (History, Intercept with a rules sheet, Match & Replace), History "Copy as" menu.
  - gulp-cli: `proxy --add-header/--intercept-replace`, `copy-as`, `history --show` with originals.
  - Caught by CI: missing `import Foundation` (UUID), ArraySlice concatenation, a lint line break,
    `^` in header conditions needing line anchors.
- 2026-11-08 — **M3b DONE** (CI run 42498773075, `11cd7d5`; DoD `Scripts/m3b-dod.sh`: PASS):
  - GulpCore `HTTP2Text`: HTTP/1-style text ↔ HTTP/2 parts (HTTP-021/022); trailers stored via the
    chunked rendering an h2→h1 gateway uses (HTTP-027), re-framing for HTTP/1.1 clients.
  - GulpHTTP: ALPN derived from the version preference, h2c prior knowledge, `H2Connection` streams
    over one shared connection per key (`H2Pool`), push disabled, trailers, `negotiatedProtocol`
    pre-connect.
  - GulpProxy: ALPN mirroring (client gets h2 only when both sides do; Force-HTTP/1.1 toggles),
    HTTP/2 server pipeline with one exchange per stream; h2 upstream replies re-framed for h1 clients.
  - VulnLab `:8443` negotiates h2; History has a Protocol column; `gulp-cli history --show`.
  - Caught by CI: handlers must be `RemovableChannelHandler` to be swapped; the server's SETTINGS
    raced the switch to HTTP/2 (TLS: held by the handshake waiter; h2c on Linux: a ReadGate);
    `tooLarge(limit:)`; a captured `var` in a Sendable closure; the M3a DoD's echo check updated
    for the new h2 upstream.
  - Same branch: the feature-review adoption (docs agent; merged after all doc checkers passed).
- 2026-11-08 — **Feature review adopted** (owner: "Adopt the feature review proposals"; product
  decision #7). Docs only, no code:
  - **Merged** F17, F26, F28, F29, F30, F31 into the specs they extend; the files are stubs listing
    where each requirement went (IDs kept) and the cut ones. HAR/collection import consolidated on
    one F20 service (PRJ-012).
  - **Added** PRX-050/HIS-007/REP-016 (streaming), **F33 gRPC & protobuf** (GRP-001…007; supersedes
    ADV-053), SES-016…018 (request signing), BRW-016/SES-032 (passkeys), REP-017/PRJ-013 (paste,
    other-proxy import), SCN-070…074, AI-013, LLM-009, HTTP-037; VulnLab fixtures for each.
  - **Deferred/cut**: F11 out of v1 (M14 retired), Frame Kit, PRX-048, Beacon server and Extension
    Gallery post-1.0; priority changes per FEATURE-REVIEW §3.4.
  - **Re-sequenced** without renumbering: M4a/b, M6a/b, M10a/b, M11a/b/c, M12a/b, M13a/b, M16a/b,
    M19a/b, and a **daily-driver beta** gate after M9. M3b (in progress) is unchanged.
  - Deviation: the original `featmap.py` predates letter-suffixed milestones (its README regex only
    accepts `M\d+`, and the M3a/M3b split had kept bare "M3" in headers), so it now reports every
    split feature as unindexed. D7 is checked with a suffix-aware copy (`featmap_sfx.py`, same logic)
    and `featmap2.py` (also header ↔ roadmap sections and every suffixed `Mxx` ref): both clean. All
    other checks pass (idcheck — 537 IDs as written, 544 with the new `GRP` prefix added — linkcheck,
    secnum, secref, tables).
- 2026-11-07 — **M3a DONE** (CI run 42424466338, `054b24a`; DoD `Scripts/m3a-dod.sh`: PASS, incl.
  a real https://example.com through the proxy):
  - GulpHTTP: upstream TLS inserted under the HTTP handler (direct, SOCKS, CONNECT tunnel); a
    custom verification callback captures the chain and the would-be result (swift-certificates
    Verifier vs the system PEM roots) — enforced only on request; TLSInfo on every exchange;
    versions/ciphers/ALPN settings in the pool key; refused connects retry all addresses.
  - GulpProxy: CONNECT → `200` → TunnelSniffer: MITM with a leaf for the SNI (replaying the
    ClientHello into NIOSSL), glob pass-through splice, or plain HTTP in the tunnel.
  - Sessions intercept with the user's CA (Keychain on macOS, 0600 file elsewhere); `gulp-cli ca
    export|show`; VulnLab `:8443`; Settings → TLS (details, export, install/remove trust, badge).
  - Caught by CI: `localhost` → `::1` first on macOS (single-address connect), BoringSSL refusing a
    server certificate without `digitalSignature`, `TLSUserEvent` living in NIOTLS, internal
    memberwise inits on public structs (twice), `catch where` spacing.
- 2026-11-07 — **Reviews after M2** (independent agents, no shared context):
  - **Code review** of M0–M2: 1 Blocker, 10 Majors, ~10 Minors. Fixed: the Blocker
    (Content-Length overflow trapped the process; unbounded request bodies) with a strict framer
    (agreeing decimal Content-Length, chunked-final Transfer-Encoding, 400 on malformed chunking, 413
    cap) and request framing warnings; proxy backpressure, ordered 100-continue/rejections, listener
    stop closes clients, protected framing headers; a `flock` single-writer lock per project; Save As
    holds recordings during the copy and refuses its own/an open destination; keep-alive reuse honours
    HTTP/1.0 and `Keep-Alive: timeout`; History selection/bulk actions by id, live updates under any
    sort, stale page loads dropped, reused row colours reset, model built once, lazy Raw view, bind
    errors shown, LIKE wildcards escaped. Not fixed yet (listed under carry-overs): response
    streaming, the HIS/PRJ partials, `settingsChanged`, the terminate hook, id reuse after delete.
  - **Feature review** of F01–F32 → `docs/FEATURE-REVIEW.md`. Adopted: M3 split into M3a/M3b,
    HTTP-027 (HTTP/2 trailers, P0), TLS-017 (ECH, P1), corrected TLS-015/MAC-011/BRW-002.
    Proposed (owner decision): new capabilities, re-sequencing, merges and cuts.
  - M3a progress: GulpTLS — CA (RSA/P-256), leaf minting with DNS/IP SANs and IDN A-labels,
    de-duplicated LeafMinter with LRU leaf + (host, ALPN) context caches, File/Keychain CA stores,
    ClientHello SNI/ALPN sniffer; tests do live NIOSSL handshakes against minted leaves.
- 2026-11-07 — **M2 DONE** (CI run 42416523505, `1acf39c`; DoD `Scripts/m2-dod.sh`: PASS):
  - GulpStore: schema v1 + migrations (newer schemas refused), SHA-256-deduplicated blobs with
    zlib for large bodies, FTS in the same transaction, the write coalescer (50 ms / 500 rows,
    ids assigned in memory, events after flush), paged/filtered/sorted summaries, annotations.
  - GulpProxy: HTTP/1 forward proxy (absolute-form, keep-alive, `Expect: 100-continue`,
    hop-by-hop stripping, recording with the client address) on configurable listeners.
  - GulpWorkspace: `ProjectSession` (temporary/open/Save As/close with flush), layered settings,
    recent projects, the bounded `HistoryPageCache`.
  - App + GulpFeatures: one window per project, File menu (New Temporary/New/Open/Recent/Save As),
    Proxy → HTTP History (virtualised NSTableView, column prefs, sort, highlight/comment/delete/
    copy URLs, quick filters, auto-scroll), read-only Raw/Hex viewer, the Listeners sheet.
  - gulp-cli: `proxy` (headless, flushes on SIGINT/SIGTERM), `history`, `send --via/--repeat`.
    The DoD browses VulnLab through the proxy with curl, sends 10,000 requests through it, quits,
    reopens the project and finds all 10,001 exchanges. Tests: 105 on Linux, plus the UI smoke tests.
  - Caught by CI: a closing proxy error page without `Connection: close` (the client reused a dead
    connection); swift-format's `indentConditionalCompilationBlocks: false`; the synthesized
    memberwise init of a public struct being `internal`; undeclared transitive module imports.
- 2026-11-07 — **M1 DONE** (CI run 42398666124, `cd84c2a`; DoD `Scripts/m1-dod.sh`: PASS):
  - GulpCore: full doc 04 §2 model (`HTTPTarget`, `Exchange` + supporting types, `ToolSource`
    TEXT encoding, `GulpNetworkError`/`GulpError`), the `EventBus` actor (lag markers on `Delivery`),
    exact resumable chunk scanner, HEAD/interim-aware `RawResponse`, `H2RequestSpec`.
  - GulpHTTP: `NIOHTTPEngine` — raw-byte writes, full HTTP/1 framing, pool, DNS overrides, typed
    timeouts, opt-in Content-Length/line-ending rewrites, cancellation, timing, hooks, recorder,
    group sends, upstream HTTP/CONNECT/SOCKS5 proxies + rules, gzip/deflate helpers.
  - gulp-vulnlab (raw-NIO fixtures :8088 + verbatim echo :8089) and `gulp-cli send --raw`.
  - Tests: 80 (fixture corpus, seeded fuzz, every HTTP-0xx requirement against an in-process
    server, scripted proxies incl. SOCKS5).
  - Real bugs CI caught along the way: `TCP_NODELAY` set at `SOL_SOCKET` (= `SO_DEBUG`; EACCES on
    Linux, silently wrong on macOS); negative TTFB from stamping write completion off-loop;
    ArgumentParser's sync entry point refusing an async command; NIO's async `writeAndFlush`
    overload shadowing the future-returning one. Plus, from fuzz-test design: chunk-size overflow
    and the `0`-line chunk heuristic.
- 2026-11-07 — **CI GREEN on both platforms** (commit `6e17d38`): M0's build gate is finally
  satisfied, and the M1 GulpCore foundation compiles and its tests pass. Reaching green meant fixing
  four real defects that only running CI could surface (none visible to the Markdown checkers or a
  no-toolchain container):
  - **GRDB/SQLite link (Linux):** GRDB 7 references `sqlite3_snapshot_*`, absent from Ubuntu's
    `libsqlite3`. `core-linux` now builds SQLite with `SQLITE_ENABLE_SNAPSHOT`+FTS5 and links it.
  - **Lint (`swift format --strict`):** never actually satisfied — fixed the new source, both
    `Package.swift` manifests (applied the toolchain's own canonical output), and the test file;
    disabled only `AlwaysUseLowerCamelCase` (ADR) to keep the spec's `http1_0`/byte-constant names.
  - **`GulpAppUITests` Info.plist:** the UI-test target couldn't code-sign; set
    `GENERATE_INFOPLIST_FILE` in `project.yml`.
  - **Swift 6 concurrency:** XCUITest APIs are `@MainActor`; annotated the test class.
  Verified via `workflow_dispatch` runs on the branch (CI triggers on push-to-main/PR/dispatch).
- 2026-11-07 — **M1 started — GulpCore byte-fidelity foundation** (unverified locally; CI is the gate):
  - `Bytes.swift` — the canonical value-semantic byte buffer (`RandomAccessCollection`, cheap slicing,
    strict vs lossy UTF-8), Foundation-free per the GulpCore dependency rule.
  - `HTTP1.swift` — the raw-preserving HTTP/1 parser + response framer: frames the start line and
    headers as byte ranges (order and duplicates preserved), never normalizes, and emits warnings
    (bare LF, obs-fold, duplicate/conflicting framing) instead of rejecting. `serialize()` is the
    identity over the input bytes (HTTP-001). Framing detection + chunk decoding + incompleteness
    (HTTP-002).
  - `Tests/GulpCoreTests` — real round-trip, edit-splice, and framing tests, each named for its
    requirement ID (replaces the scaffolding marker test).
  - **Doc reconciled to code** (CLAUDE.md §4): doc 04 §2 `ParsedRequest`/`ParsedResponse`/`HeaderField`
    marked `Hashable` (their `RawRequest`/`RawResponse` already were, which requires it).
- 2026-11-07 — **M0 scaffolding written** (unverified at the time: no toolchain in the authoring container):
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
  - Also corrected a spec error found while scaffolding: `SNIHandler` is in the `NIOTLS` module of
    swift-nio (a later review corrected an interim "NIOSSL" note; doc 01 §1 and F02 §4 are authoritative).
- 2026-11-07 — Spec review pass: fixed layering (BrowserDriver injection, ADR-010), scope precedence
  (ADR-011), FTS trigram limits, GulpQuery storage-agnosticism, Beacon privileged ports, single-packet
  wording. (Commit `35fee56`.)
- 2026-11-06 — Specs written: core docs (00–07) + all feature specs (F01–F24) + this tracker.
  Repository is spec-only; no source yet. Next action: M0 scaffolding.
