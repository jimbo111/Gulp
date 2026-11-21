# AGENTS.md — instructions for coding agents working on Gulp

You are building **Gulp**, a native macOS web-security testing suite (intercepting proxy + Repeater,
Fuzzer, Scanner, etc.). The `docs/` folder is the source of truth. Follow it. If the docs and the
code disagree, fix one of them in the same change and say which one in the commit message.

## 1. Reading order (do this at the start of every session)

1. `docs/PROGRESS.md` — "Current state" (gate, toolchain, next steps) and the milestone checklist.
2. `docs/03-roadmap.md` — the milestone you are working on and its Definition of Done.
3. `docs/01-architecture.md` — module boundaries and dependency rules (always applies).
4. The feature spec(s) for the milestone: `docs/features/Fxx-*.md`.
5. When relevant: `docs/04-data-model-and-storage.md`, `docs/05-ui-ux.md`, `docs/06-testing-strategy.md`.

Don't read every feature spec up front. Read the ones the current milestone lists.

## 2. Workflow per task

1. Pick work from the milestone checklist in `docs/PROGRESS.md`, not from the roadmap's checkboxes:
   the first row whose "Engine/CLI" column is not **done**, and only the items that row lists as
   missing (one milestone at a time, in order, unless the user says otherwise). Never re-implement a
   row marked **done**.
2. Read the requirement IDs it references (for example `PRX-003`). Every requirement has a priority:
   - **P0**: must ship in that milestone.
   - **P1**: parity feature; do it in the milestone unless it is listed as deferred.
   - **P2**: beyond parity or polish; do it only when the milestone says so or the user asks.
3. Write tests first, or alongside the code. Tests name the requirement ID, for example
   `func test_PRX003_upstreamProxyChaining()`.
4. Implement it in the module the architecture doc assigns.
5. Run `make test` (or `swift test --package-path Packages/GulpKit` on Linux) and `make lint`.
6. Update `docs/PROGRESS.md`: the milestone's checklist row (and "Current state" if it changed), plus a
   log entry at the top of the log (date, what, any deviation).
7. Commit with a message like `M3: TLS leaf minting with SNI (TLS-002, TLS-003)`.

## 3. Commands

```bash
make bootstrap   # install xcodegen via Homebrew, resolve packages
make generate    # xcodegen generate -> Gulp.xcodeproj (git-ignored)
make build       # build the macOS app (Debug)
make run         # build and launch Gulp.app
make test        # swift test for GulpKit + xcodebuild test for app/UI tests
make test-core   # swift test only (works on Linux too)
make lint        # `swift format lint --strict` (toolchain's swift-format), after `make rules`
make rules       # Scripts/arch-check.sh + Scripts/rules-check.sh (hard rules as grep checks; Linux too)
make vulnlab     # run the intentionally vulnerable local test server on :8088
make beacon      # run the OAST Beacon server locally (dev mode, high ports)
```

The toolchain minimum is **Swift 6.1** (swift-crypto ≥ 4.5.1 needs tools 6.1). GitHub Actions CI
cannot run at the moment, so `make test` + `make lint` locally is the only gate.

On **Linux** (for example cloud Claude sessions), `xcodebuild` is unavailable. Build and test the
platform-independent modules with `swift build` / `swift test --package-path Packages/GulpKit`.
Modules that need Apple frameworks keep that code behind `#if canImport(...)` and compile to empty
shells on Linux (see architecture §4). Never break the Linux build of the core modules.
If SwiftPM cannot find zlib/sqlite headers on Linux, pass
`SWIFTPM_FLAGS="-Xcc -I/usr/local/include -Xlinker -L/usr/local/lib"` (to `make test-core` and to the
`Scripts/*-dod.sh` scripts), as CI does.

## 4. Hard rules

- **Raw bytes are the truth.** Never round-trip a user-edited request through `URLRequest`,
  `URLSession` or any parser that normalizes it. The HTTP engine (`GulpHTTP`) sends exactly the
  bytes the user wrote, unless a documented option such as "Update Content-Length" says otherwise.
- **The main thread never waits on the network or the database.** UI reads go through paged, async
  queries, and UI updates from traffic are coalesced (at most every 100 ms).
- **Respect the dependency direction** in `docs/01-architecture.md`. Engines never import UI.
  `GulpCore` imports nothing from Gulp.
- **Scope safety.** Active tools (Scanner active audit, Crawler, Fuzzer, Beacon payload injection)
  must check `ScopeGuard` before sending, unless the user explicitly overrides it for that action.
- **No secrets in the repo.** CA private keys go to the Keychain (macOS) or a 0600 file. API keys go
  to the Keychain only.
- **Don't copy PortSwigger code, text, icons or product names** into the UI. Use Gulp's names (the
  mapping is in `docs/00-vision.md` §4). Implementing the same *ideas* is fine.
- Swift 6 language mode with strict concurrency, and no `@unchecked Sendable` without a comment that
  justifies it.
- Public types and functions in GulpKit get a `///` doc comment.
- `Scripts/rules-check.sh` enforces several of these rules mechanically, and the matching types make
  the right thing the easy thing: active CLI probes send through `ScopedSender` (`GulpHTTP`), store
  writes in `GulpWorkspace` go through `persisting(_:events:_:)`, issue ids resolve via
  `IssueDefinitions.require`, test randomness uses `SplitMix64(seed:)` from `GulpTestSupport`, and
  VulnLab safe twins use `SafeTwin`. When the check fires, fix the code. A real exception gets the
  marker comment the rule names, with a reason.
- When a spec is ambiguous, choose the simplest behavior that meets the acceptance tests, write the
  decision in `docs/07-decisions.md` (as a new ADR or under "Small decisions"), and continue. Ask the
  user only for product-level choices.

## 5. Definition of Done (every milestone)

- All P0 requirements of the milestone are implemented and have tests.
- `make test` and `make lint` pass. The core modules also build on Linux.
- The feature works end-to-end in the running app against VulnLab (`make vulnlab`), where it applies.
- `docs/PROGRESS.md` is updated, and any spec deviation is written down.
