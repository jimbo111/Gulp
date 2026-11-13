# Progress tracker

This is the live state of the build. Claude updates it as work lands: tick tasks in the current
milestone (keep the detail in `docs/03-roadmap.md`) and add a dated log line. Work milestones in
order; within a milestone, do P0 first.

## Current status

- **Phase**: **M4b DONE** — CI green on both platforms (run 42504816428, commit `0b0c6f7`); the M4b
  DoD: `Scripts/m4b-dod.sh` (Linux CI) PASS — `curl -N` through `gulp-cli proxy` to VulnLab `/sse`
  receives each event as it is sent (≈800 ms between first and last of 5), the row completes, and a
  WebSocket conversation (`gulp-cli ws` → VulnLab `/ws`) appears in WebSockets history in both
  directions with close code 1000; `Scripts/m4b-browser.sh` (macOS CI) PASS — headless Chrome
  launched by the Gulp Browser launcher through the proxy loads `https://localhost:8443` with no
  certificate interstitial (SPKI pin of the Gulp CA) and the request is in history. M1–M4a DoD
  scripts still pass in the same run.
- **Active milestone**: capstone (architecture review + Burp-comparison-driven outperformance).
  Implemented through M12b and M13b-GraphQL on the Linux-testable core; four outperformance
  increments shipped (secret/JS recon, reporting, Check Recipes, vulnerable-JS-libraries). Remaining
  leftover phases are macOS/browser/external-gated (M13a CDP, M17 polish, M18 live AI, M20
  notarization) or deferred (M11c injection-style P1 checks). All non-UI work is in CI with DoDs;
  `Scripts/arch-check.sh` enforces the architecture.
- **Branching**: `main` holds merged milestones (PRs jimbo111/Gulp#1 M0–M2, #2 review fixes,
  #3 M3a, then M3b + the feature-review adoption). Work happens on
  the session branch and is merged by PR once CI is green.
- **Build verification**: the authoring container has no Swift toolchain (`download.swift.org` is
  blocked), so CI (`.github/workflows/ci.yml`) is the gate and runs on **every branch push**:
  `core-linux` (`swift:6.0-noble`: build + all tests + the M1 and M2 DoD scripts) and `macos`
  (`make lint generate test-core build test`, incl. the app UI smoke tests).
- **Carry-overs** (tracked, not silently dropped):
  - M1: HTTP-007 brotli and zstd decoders (gzip/deflate ship; `br`/`zstd` throw `.unsupported`);
    SOCKS5 username/password (NIOSOCKS client is no-auth only). Redirect following is declared but
    `.never`-only until the Repeater (M5).
  - M2: PRJ-001 save/discard prompt on closing a temporary project (the file is kept in Caches
    instead; needs an NSWindow close hook, M16b polish). The proxy answers CONNECT with 501 until M3a
    and origin-form (invisible) requests with 400 until PRX-040.
  - M2, found by the 2026-11-07 code review (partial requirements, now stated honestly):
    - **F01 §4.3 response streaming**: responses are buffered whole (50 MB / 120 s limits), so large
      downloads and SSE/long-polling fail through the proxy. Now specified as PRX-050/HIS-007 (M4b,
      FEATURE-REVIEW A1). Request bodies are buffered too, capped at 256 MB (413 beyond).
    - HIS-004: "add to scope" (needs M6a) and "send to tools" (M5) are not there yet.
    - HIS-005: comments are edited in a dialog, not inline (UI-041 lands with the editor, M4a).
    - HIS-006: in-scope (M6a), MIME and method chips are missing from the UI (the query supports them).
    - PRJ-005: "Use settings from…" has an API but no UI; import from a settings file is missing.
    - PRJ-006 (P1): name/notes API only, no Project Info panel.
    - F20 §4: `settingsChanged` is declared but never published.
    - No app-terminate hook: on Cmd-Q the last ~50 ms of queued writes may be lost (window close is
      fine). Exchange ids can be reused after the newest rows are deleted and the project reopened.
- **M3a carry-overs**: TLS-017 ECH handling (P1); MAC-003 simulator install (P1); TLS-007 PKCS#12
  import (PEM import works); pass-through tunnels are not yet logged (PRX-007 "tunnel entry" needs
  the Logger, M9); `TLSInfo.cipherSuite` is empty (NIOSSL doesn't expose the negotiated suite);
  PRX-046 `http://gulp/cert.pem` landing page (P1) not yet served.
- **M3b carry-overs**: raw HTTP/2 from an `H2RequestSpec` (HTTP-025, P1) arrives with the Repeater
  (M5); HTTP-026 (P1) connection events in the Logger (M9); request trailers from h2 clients are
  ignored; ALPN pre-connect offers upstream `h2, http/1.1` rather than the client's exact list
  (decision log); a failed pre-connect still completes the client handshake (the request then gets
  a 502) instead of aborting it with a TLS alert.
- **M4a carry-overs**: MessageEditor Render tab, editable hex (UI-012), auto-scroll-to-match
  (UI-015), Decoder popover (UI-021, with M7), DiffView (UI-030, with M7); Send-to destinations
  arrive with their tools (Repeater M5, …); intercept P1s (GulpQL rules PRX-015, auto-forward timeout
  PRX-016, Content-Length toggle — always on for edits); Match & Replace P1s (scope PRX-023, test
  pane PRX-024, GulpQL conditions PRX-025); an edited *response* is sent to the client but History
  keeps the received one; "in scope" intercept conditions are always true until scope (M6a).
- **M4b carry-overs**: WebSocket over HTTP/2 (RFC 8441 extended CONNECT, part of PRX-030) is not
  offered — browsers fall back to HTTP/1.1 upgrades; permessage-deflate messages are decompressed
  for display but can't be edited (the "Turn off WebSocket compression" preset negotiates it away,
  PRX-034); PRX-035 (send a WS message to Repeater) arrives with REP-012 in M5; PRX-036 (P2) not
  scheduled; WS History loads a connection's messages whole (no paging yet) and has no
  highlight/comment UI; a WS message held in Intercept when its client goes away stays queued until
  decided. Gulp Browser: the Chrome-for-Testing download (macOS) is not exercised by CI; no
  WKWebView fallback when the download is declined; the headed launch and quit-cleanup are covered
  by the launcher unit test, the end-to-end check is headless. HIS-007: live partial-row updates
  stop past 4 MB (the row still completes); SSE event *times* are shown for HTTP/1 bodies without a
  Content-Encoding (HTTP/2 or compressed streams list events without times).
- **M5 status — implementation complete; macOS verification pending** (2026-11-09):
  - GitHub Actions minutes are exhausted (owner confirmed), so CI can't run. The Linux CI job is
    reproduced locally instead: Docker with the same `swift:6.0-noble` image (Swift 6.0.3) plus
    SQLite built from Ubuntu's source package with CI's flags (`www.sqlite.org` is blocked by the
    sandbox proxy), and swift-format 600.0.0 built from source for `lint --strict`.
  - Local gate at `ecb9c3b`: build OK, **219/219 tests**, **M1, M2, M3a, M3b, M4a, M4b and M5 DoD
    scripts PASS**, lint clean. The M5 DoD (`Scripts/m5-dod.sh`, also added to CI): a sequential
    control redeems the coupon once; a single-packet group over HTTP/2 redeems it 20/20 (final-write
    spread 0.00 ms — one flush); last-byte sync over HTTP/1 20/20 (0.63 ms); a pasted cURL
    reproduces its request against `/echo`; `/sse` streams through a Repeater tab (~200 ms apart).
  - **Not verified (no macOS here):** the SwiftUI/AppKit code written since CI stopped —
    `GulpFeatures/RepeaterView.swift`, the History "Send to Repeater" menu/⌘R button, the
    WebSockets History menu item and `App/ProjectWindow.swift` changes. The first macOS CI run
    (`make lint generate test-core build test` + `Scripts/m4b-browser.sh`) must pass before M5 is
    marked DONE and merged.
  - Done in M5: REP-001…007, REP-010 (groups + Send group + results), REP-012 (WebSocket tabs),
    REP-016 (streaming + Stop), REP-017 (paste); PRX-035; HTTP-011 (pipelining), HTTP-012 (Basic +
    Digest), HTTP-013 (throttle), HTTP-030…036 (group modes, single-packet h2/h1, timing report,
    TCP_NODELAY); engine redirect following (REP-006).
- **M5 carry-overs**: HTTP-025 raw HTTP/2 from an `H2RequestSpec` (needs a hand-written frame
  encoder; not started); HTTP-012 NTLMv2 (MD4 + three-message connection affinity); REP-009
  structured Inspector edits; REP-011 variable capture (needs Transform Tags, M7); REP-013…015 (P2);
  single-packet h2 does not yet detect `SETTINGS_MAX_CONCURRENT_STREAMS` < group size (it falls
  back only when h2 isn't negotiated); the Repeater keeps WebSocket logs per session in memory (not
  in WebSockets History). (The `in-scope` redirect mode now follows the project scope — done in M6a.)
- **M6a status — implementation complete; macOS verification pending** (2026-11-09):
  - Local gate: build OK, **240/240 tests** (three runs in a row), **M1…M5 and M6a DoD scripts
    PASS**, lint clean. The M6a DoD (`Scripts/m6a-dod.sh`, also added to CI): curl browses VulnLab
    through `gulp-cli proxy` and `gulp-cli target` prints the tree with the visited paths and the
    home page's links as inferred nodes; filters hide inferred/404-only nodes and fold `{id}`;
    `gulp-cli scope` adds an include and an exclude and `--test` names the deciding rule; the
    in-scope view shows only `/race`; with `--use-scope` the proxy records only the in-scope request
    of three; scope JSON exports and imports into another project; `gulp-cli repeater` refuses an
    out-of-scope target (exit 3, "Target is out of scope. Send anyway?") and sends it with
    `--allow-out-of-scope`; Analyze target lists parameters and flags the `to` redirect parameter.
  - Done in M6a: TGT-001…008 (TGT-004's "Actively scan this branch" and "Crawl from here" are
    disabled menu items until the Scanner/Crawler), TGT-020…025, PRX-045; the M5 `in-scope`
    redirect mode.
  - **Not verified (no macOS here):** `GulpFeatures/TargetView.swift` (Site map + Scope tabs), the
    Repeater's out-of-scope confirmation and badge, `App/ProjectWindow.swift` (`.target`).
- **M6a carry-overs**: the site map tree is a SwiftUI hierarchical `List`, not the UI-060
  NSOutlineView `TreeView` (virtualized, lazy children) — needed before 100k-node maps are smooth;
  "don't ask again for this host" lasts for the session (not stored per project); History's
  "add to scope" menu item and in-scope filter chip (HIS-004/006) are still to add to the History
  UI; F04 acceptance 4 (100k-row recompute without UI freeze) is batched (2,000 rows per write) but
  not benchmarked.
- **M6b status — implementation complete; macOS verification pending** (2026-11-09):
  - Local gate (clean build): **260+ tests pass**, **M1…M6a and M6b DoD scripts PASS**, lint clean.
    The M6b DoD (`Scripts/m6b-dod.sh`, also in CI): VulnLab's `/openapi.json` imports as 4 requests
    (every `/api/*` operation, bearer placeholder on `/api/me`) shown in the site map as not yet
    sent; 1,000 proxied exchanges → HAR → a new project byte-for-byte (the `_gulp` raw fields of
    both exports are identical) and a second import adds nothing; the XML proxy-history, Caido and
    mitmproxy fixtures import with bytes, comments and highlights; over MCP stdio a scripted client
    (the JSON-RPC lines Claude Code sends) lists history, sends an in-scope request (recorded as
    `automation`) and gets a structured `out_of_scope` error for an out-of-scope one — both in the
    audit log as `mcp:claude-code`.
  - Done in M6b: PRJ-012 (ImportExportService), PRJ-013, PRJ-008 (exchanges), HIS-044 (HAR/CSV/
    `.gulp` export, HAR import), TGT-009, ADV-050, ADV-051, ADV-052 (value generation), AUT-004
    (`project import/export/info/audit`), AUT-020 (stdio), AUT-021 (`list_exchanges`, `get_exchange`,
    `send_request`, `get_scope`), AUT-022 (site map, scope, exchanges), AUT-023 (ScopeGuard, approval
    policy, audit log).
  - **Not verified (no macOS here):** File → Import… / Export History menu items in
    `App/ProjectWindow.swift`.
- **M6b carry-overs**: OpenAPI/Swagger **YAML** (JSON only — no YAML parser in the dependency set);
  PRJ-008 merges exchanges only (issues and Notebook items once those features exist); the approval
  mode's in-app prompt (toast + dashboard) and Settings → Automation (F21 §3) — headless supports
  `deny` (default) and `in-scope`; the MCP HTTP transport and REST API (M17); History's "export
  selected rows" menu (the service takes ids; the menu exports everything); the import fixtures are
  hand-made in each format's published shape, not captures (doc 06).
- **M7 status — implementation complete; macOS verification pending** (2026-11-09):
  - Local gate (clean build): **278/278 tests**, **M1…M7 DoD scripts PASS**, lint clean. The M7 DoD
    (`Scripts/m7-dod.sh`, also in CI): URL → Base64 → gunzip decodes and the reversed chain
    re-encodes byte-identically; Smart Decode solves the 8 fixtures with the right chains; a word
    diff of two 1 MB responses finds exactly the 3 changed bytes in ~150 ms (debug build); an
    `alg:none` admin token (sent through a Repeater `«var(token)»` tag), an RS→HS256 confusion token
    and a `kid`→/dev/null token are accepted by VulnLab `/api/me` and rejected by `/safe/api/me`; the
    weak HMAC secret is cracked from `Wordlists/jwt-secrets.txt` and an admin token signed with it;
    JWKS verification works; Transform Tags build a Basic header and the toggle sends them literally.
  - Done in M7: DEC-001…006 (DEC-006 as the Decoder's level panes, not yet the popover), DEC-020…023,
    CMP-001…005, ADV-010…012, ADV-013 (the Transform Tag side).
  - **Not verified (no macOS here):** `GulpFeatures/DecoderViews.swift` (Decoder, Comparer, JWT
    Workbench), History's Send to Comparer/Decoder items, the Repeater tag toggle, `App/ProjectWindow`.
- **M7 carry-overs**: brotli/zstd operations (no library in the dependency set); the Inspector
  decoder popover over a selection (DEC-006, UI-021); DEC-024 `js(name)` snippets (F18); the Repeater
  live tag preview pane and "diff with previous response" (CMP-006) — the service has
  `previewTags`; CMP-007/008 (P2); a JWT tag op (`«jwt-sign…»`) and the Fuzzer payload processor
  (ADV-013, M8); variable capture from responses (REP-011) still feeds `var()` by hand.
- **M8 status — implementation complete; macOS verification pending** (2026-11-10):
  - Local gate (clean build): **292/292 tests**, **M1…M8 DoD scripts PASS**, lint clean. The M8 DoD
    (`Scripts/m8-dod.sh`, also in CI): with no scope the attack sends nothing (9 rows refused,
    "sent 0 of 9"); after scoping VulnLab, a 2 × 100 cluster bomb sends 10,000 requests at
    ≈2,500 req/s (debug build; ≥ 1,000 required), every one recorded in History, and a grep column
    finds the single `a=100&b=100` row; grep-extract pulls 50 unique CSRF tokens from 50 `/login`
    responses; Discover content finds `/admin` (403), `/index.html.bak`, `/backup.zip`, `/.old/`
    (403) and `/.old/config.php~` (~9,000 probes in ≈2.5 s) and records them in the site map.
  - Done in M8: FUZ-001…004, FUZ-010…014 (FUZ-013 without the Snippet processor), FUZ-020…024,
    FUZ-026, FUZ-030, FUZ-031, ETL-003 (content discovery), FUZ-011 bundled wordlists; Send to
    Fuzzer from History; `gulp-cli fuzz|discover|wordlists`.
  - **Not verified (no macOS here):** `GulpFeatures/FuzzerView.swift` (Positions, Payloads,
    Settings, Results, Discover content), History's Send to Fuzzer item, `App/ProjectWindow`.
- **M8 carry-overs**: Turbo mode (FUZ-032, P1, "optional, last within the milestone" — HTTP/1
  pipelining and HTTP/2 multiplexing exist in the engine since M5; the scriptable generator needs
  Snippets, F18); FUZ-025 OAST column (M11a, needs Beacon); FUZ-033 shared resource pool beyond the
  engine's per-host throttle (lands with the shared limiter, M11a); the Snippet payload processor
  (F18); FUZ-015/027/034 (P2: charts etc.); a JWT `«jwt-sign…»` tag op; the dashboard's running-task
  list; F07 acceptance tests 1–3 (username enumeration, password spray, recursive grep against
  `/login`) are covered by unit tests with a fake engine and the CLI, not yet by a DoD script.
- **M9 status — implementation complete; macOS verification pending** (2026-11-10):
  - Local gate (clean build): **321/321 tests**, **M1…M9 DoD scripts PASS**, lint clean. The M9 DoD
    (`Scripts/m9-dod.sh`, also in CI): `resp.status >= 500 and req.host ~ "api"` matches exactly
    50,000 of 1,000,000 seeded rows in ≈750 ms (debug build; < 2 s required), fully pushed down and
    planned through `ix_ex_status`, and an equivalent spelling agrees; `reflected("q")` flags exactly
    the VulnLab `/xss/html?q=` row; the coverage index shows `/xss/html` observed (proxy only),
    `/echo` tested (fuzzer×3) and `/account` tested (repeater), and a Notebook item marks its
    endpoint tested; a Notebook item keeps status/tags and its filter finds it after reopening;
    search finds a planted token in a request and its response among 100k rows in a few ms.
  - Done in M9: HIS-020…027 (HIS-025 without syntax coloring in the field), HIS-040…044,
    HIS-050…053 (find-references as a store/CLI call), NB-001…004, NB-006, JRN-001; GulpQL in
    intercept rules (PRX-015) and Match & Replace conditions (PRX-025); `gulp-cli query|search|
    logger|filters|notebook|coverage|seed`, `history --connections`, `query --column`.
  - **Not verified (no macOS here):** `GulpFeatures/QueryViews.swift` (GulpQL field, Logger,
    search sheet), `NotebookView.swift`, the History filter bar/menu changes, the intercept and M&R
    rule fields, `App/ProjectWindow` (Logger, Notebook, ⌘⇧F).
- **M9 carry-overs**: syntax coloring inside the GulpQL field (HIS-025; a SwiftUI `TextField` can't
  color — needs an `NSTextView`); custom-column and connection-view *UI* (HIS-042/043; store, GulpQL
  column type and CLI exist); a "Find references" context-menu entry (HIS-053); GulpQL for scanner
  insertion points (M11) and Fuzzer result filters (HIS-027's remaining users); HIS-028/045/054
  (P2); NB-005 (M10a), NB-007 (M16a), NB-008/009 (P2); the coverage view (JRN-002, M16b); Compact
  must treat Notebook blobs as live; the Logger keeps the store it opened with across Save As.
- **M10a status — implementation complete; macOS verification pending** (2026-11-11):
  - Local gate (clean build): **338/338 tests**, **M1…M10a DoD scripts PASS**, lint clean. The M10a
    DoD (`Scripts/m10a-dod.sh`, also in CI): curl browses all 63 routes of
    `Tests/Fixtures/vulnlab-issues.json` (HTTP and, through TLS interception, HTTPS) via
    `gulp-cli proxy`, whose live passive scanner records the issues; `gulp-cli issues verify` finds
    exactly the 35 expected (route, type) pairs and nothing else (none on `/safe/*`); a second browse
    adds no issue, only evidence; the CORS issue's markers highlight the reflected `Origin` in the
    request and response; the SARIF export carries every issue.
  - Done in M10a: SCN-001…007 (SCN-005 as the Dashboard view; SCN-007 as JSON + SARIF), the F08
    §3.1 passive catalog (32 definitions incl. every [P0]), live passive scanning (F08 §4), NB-005
    (link + promote Notebook items); `gulp-cli issues list|show|set|export|verify|definitions`,
    `gulp-cli scan passive`.
  - **Not verified (no macOS here):** `GulpFeatures/IssuesView.swift` (Dashboard tree, detail with
    highlighted evidence, filters, bulk status, passive-scan menu), `App/ProjectWindow` (Dashboard).
- **M10a carry-overs**: issue HTML export (F19, M16a); a "known issues" browser UI (SCN-006 — the
  catalog and `gulp-cli issues definitions` exist); TLS certificate-expiry observations (F02 data
  doesn't carry certificate dates yet); WebSocket passive checks (post-1.0, §3.6); Notebook ↔ issue
  promotion in the macOS views (the service exists).
- **M10b status — implementation complete; macOS verification pending** (2026-11-10):
  - Local gate (clean build): **366/366 tests**, **M1…M10b DoD scripts PASS**, lint clean. The M10b
    DoD (`Scripts/m10b-dod.sh`, also in CI) runs F33 tests 1–4 against VulnLab: curl sends gRPC over
    HTTP/2 through `gulp-cli proxy` to `vulnlab.Echo/Say`, and `gulp-cli grpc show` decodes it
    schema-less with `grpc-status: 0` from the HTTP/2 trailers; `grpc schemas fetch` (reflection)
    and, separately, `grpc schemas import --proto` name the fields; `grpc call --set
    message=edited-in-gulp` re-sends from a Repeater tab over HTTP/2 and gets the edited echo with an
    18-byte length prefix and the trailers; gRPC-Web text (HTTP/1.1) and Connect unary decode; and
    `fuzz --grpc-field message` sends 4 re-encoded payloads that VulnLab parses (status 0) and
    echoes.
  - Done in M10b: GRP-001…005 (GRP-005's Fuzzer half; Scanner insertion points are M11c) — the
    protobuf wire codec, gRPC/gRPC-Web(text)/Connect framing with trailers, hand-written descriptor
    models and `.proto` parser, named decode and proto3 JSON, reflection client and server
    messages, project schemas, edit-and-resend, Fuzzer protobuf positions; VulnLab's gRPC services
    (Echo, Orders with a planted SQLi + SafeOrders, reflection, gRPC-Web, Connect);
    `gulp-cli grpc show|schemas|call`, `fuzz --grpc-field`. Fixed on the way: an HTTP/2 pool race
    that failed ~⅓ of a cold concurrent burst (HTTP-023); `"\r\n"` being a single Swift
    `Character` broke CRLF splitting in four places; grep-match didn't see trailers.
  - **Not verified (no macOS here):** `GulpFeatures/GRPCViews.swift` (Protobuf tab in every
    response pane, gRPC Schemas sheet), Repeater's "Edit Message" sheet, the Fuzzer's protobuf
    fields box, `App/ProjectWindow` (toolbar button, schema provider).
- **M10b carry-overs**: History/Logger "gRPC" protocol label and `grpc-status` column (GRP-001's
  last sentence — needs a derived column; `grpc show` and the Protobuf tab show both); the per-field
  "read as" override remembered per path and method (F33 §5 — the CLI/UI show the heuristic
  reading); field-tree editing in the UI (the sheet edits by path or JSON); a decoded-tree size cap
  (§5; depth is capped at 32); GRP-006/007 (P2: streaming replay, rich error details, "Copy as
  grpcurl"); Scanner insertion points inside protobuf (GRP-005, M11c).
- **M11a status — implementation complete; macOS verification pending** (2026-11-11):
  - Local gate: all tests and **M1…M11a DoD scripts PASS**, lint clean. The M11a DoD
    (`Scripts/m11a-dod.sh`, also in CI) runs VulnLab and two dev Beacons: a static crawl of `:8088`
    reaches all 32 routes of `Tests/Fixtures/vulnlab-crawl.txt`, reports the two out-of-scope links
    and the logout link without fetching them, and fills the site map; Test Beacon passes; a Repeater
    request with `«beacon(url)»` to the blind SSRF yields DNS and HTTP interactions tied to its
    exchange; a token-protected Beacon refuses registration without the token; the Fuzzer's OAST
    column flags exactly the two payload rows; a 2,000 req/s fuzz plus a crawl peak at ≈1,006 req/s
    under a 1,000 cap and at 50 in flight under a 50 budget (130 wanted); a 503 burst drives the
    rate from ≈300/s to ≈37/s with the throttled flag, then it recovers; the panic stop cuts every
    in-flight request (0 within one tick), pauses the fuzz and the crawl, and resume completes both
    with no errors.
  - Done in M11a: CRL-001…010 (static; CRL-006 as the hook point), BCN-001…006 (BCN-003/006 in the
    Beacon tool), BCN-024 (dev Beacon), FUZ-025 (`fuzz --oast-wait`), DEC-021 `beacon()`, GOV-001…003
    and GOV-007; `gulp-cli crawl`, `oast configure|payload|test|list`, `governor set|caps-drill|
    backoff-drill|panic-drill`, `repeater --oast-wait`, `fuzz --tags`. Fixed on the way: HTTP/2
    sends ignored cancellation (a cut stream ran to completion); governed sends were capped at 6
    connections per host; the crawler's robots/sitemap fetches weren't reported as pages; a
    site-map rebuild race, SQLITE_BUSY on closing the old file after Save As, and a timing-only
    throttle test (doc 07).
  - **Not verified (no macOS here):** `GulpFeatures/CrawlerView.swift` (crawl sheet + progress,
    Beacon tool), the panic-stop toolbar item (⌃.) in `App/ProjectWindow`.
- **M11a carry-overs**: BCN-007 "promote to issue" (the Scanner's OAST checks raise issues in
  M11b); the status-bar Beacon health and per-host "throttled" badges (the data is there:
  `OASTService.currentHealth`, `ResourcePool.throttledHosts`; the panel is GOV-006, M16b); crawl
  pause/resume across app restarts and a stored crawl report (F09 §4); "Crawl from here" in Target
  and "New crawl" on the Dashboard (the crawl lives under Scanner); persisting the OAST session
  across restarts (Keychain-held key); a manual interop check against a public interactsh server;
  the deployable Beacon (BCN-020…023, 025: post-1.0).
- **M11b status — implementation complete; macOS verification pending** (2026-11-12):
  - Local gate: all tests and **M1…M11b DoD scripts PASS**, lint clean. The M11b DoD
    (`Scripts/m11b-dod.sh`, also in CI) runs VulnLab and the dev Beacon, configures OAST, and runs
    `gulp-cli scan active --manifest Tests/Fixtures/vulnlab-active.json --config balanced` over the
    32 vulnerable and safe-twin routes: 20 findings, `verify-active: 0 missing, 0 unexpected`
    (including `active.cmd.oast`, `active.xxe.oast` and `active.ssrf.oast` through the Beacon), and
    no issue on any `/safe/` route (about 1,150 probes in ≈11 s).
  - Done in M11b: SCN-020…038 — insertion points (query, form, JSON, XML + whole body, multipart,
    cookies, chosen headers, REST path segments, custom ranges), the `ActiveScan` engine (baselines
    with volatility, per-point budgets, concurrency, pause/resume/cancel, OAST grace, in-scan dedup),
    presets (passive-only, light, balanced, thorough, custom), the P0 checks of F08 §3.2 with the
    §3.4 methodology, the workspace scan service (ScopeGuard, governed `scanner` traffic, findings
    as issues), `gulp-cli scan active|verify-active`, History "Actively scan" → Scanner → Audit
    (presets, unsafe and out-of-scope gates with confirmation, live findings, ≤100 ms refresh).
    Fixed on the way: `DerivedFields` mis-read `?url=http://…` targets as absolute-form; multipart
    boundaries were lowercased; VulnLab CRLF stripping missed `"\r\n"` (doc 07).
  - **Not verified (no macOS here):** `GulpFeatures/ScannerView.swift` (Audit pane) and the History
    "Actively scan" menu item.
- **M11b carry-overs**: per-check configuration in the UI (families can be disabled in the config
  JSON/CLI); the Audit pane takes History rows only ("Actively scan" from the site map and
  Repeater come with crawl-and-audit, M11c); scan tasks aren't persisted across restarts (F08 §2.3's
  resumable task, with M11c's crawl-and-audit task).
- **M12a status — implementation complete; macOS UI pending** (2026-11-12): GulpSession (cookie jar,
  identities, macros, rules, validity, request signing) + GulpWorkspace hooks + VulnLab `/signed/*`
  + `gulp-cli session sign|reauth`; `Scripts/m12a-dod.sh` PASS and in CI. Deferred: jar import/export
  (SES-003), rule tester (SES-014), client certs/platform auth per identity (SES-040/041), GulpQL rule
  scope, Keychain key storage, and the macOS Sessions UI; recorded login + passkeys stay M13a.
- **M12b status — implementation complete; macOS matrix UI pending** (2026-11-12): the Authz Matrix
  (replay as identities, verdicts, bypass issues) + VulnLab enforcing twin + `gulp-cli authz orders`;
  `Scripts/m12b-dod.sh` PASS and in CI. Carry-overs: ADV-004 live mode, ADV-005 per-identity CSRF,
  ADV-006 id-walking, the `/admin` self-granted-role case, and the macOS matrix view.
- **M13b status — GraphQL done; DOM Probe deferred** (2026-11-13): the GraphQL Workbench (detection,
  introspection + schema model + render, query build, variable insertion points, introspection-exposed
  and broken-object-authz checks) + VulnLab `/graphql`(+safe) + `gulp-cli graphql`; `Scripts/m13b-graphql-dod.sh`
  PASS and in CI. The DOM Probe half (BRW-010…015) needs the managed browser/CDP and ships with M13a.
- **M11c status — partial** (2026-11-12): done and in CI (`Scripts/m11c-dod.sh` PASS): GRP-005's
  Scanner half (protobuf-field insertion points; the gRPC-Web SQLi is found, the safe twin clean),
  crawl-and-audit (`scan crawl-audit`), the OpenAPI scan (`scan api`, all operations), SCN-036
  consolidation, SCN-037 re-test (`scan retest`; still present → fixed after `/lab/patch`), SCN-038's
  scan-wide budget. **Deferred (not built in this session):** the remaining P1 active checks of F08
  §3.2 (CORS confirmation, host header, HPP, deserialization signpost, NoSQL/LDAP/XPath, CSS XSS
  context), the passive vulnerable-JS-library and secret checks, SCN-070…074 and SCN-022 nested
  decoding. They stay open in the roadmap.
- **Next action**: when CI minutes return, run CI on the branch head, fix any macOS compile issues
  in the new SwiftUI code (M5…M11a views), then open the M5…M11a PRs and merge; the daily-driver
  beta's release work (signed + notarized build, real testers) needs macOS. Meanwhile continue with
  M11b on the Linux-testable core.
- **Waiting on the owner**: GitHub Actions minutes (CI is the only macOS build available).
- Earlier waiting items: nothing. The scope proposals in `docs/FEATURE-REVIEW.md` §3 were
  **adopted on 2026-11-08** (product decision #7 in `docs/07-decisions.md`) and applied to the specs:
  merges, cuts, deferrals, new requirements (incl. F33) and the re-sequenced roadmap with letter-
  suffixed splits and a daily-driver beta gate after M9.
- **Product decisions**: resolved by the owner and recorded in `docs/07-decisions.md` §"Product
  decisions" (MIT license; macOS 14 min; Claude-only AI in v1; OAST off until configured;
  `com.gulp.app` placeholder bundle id — to be replaced before the beta's signed build; no team
  server; #7 the feature review adopted). Build to those.

### Documentation Definition of Done (the objective "build-ready" bar)

"Nearly perfect" is subjective, so here is the **concrete, auditable standard** the doc set is held
to, with how each criterion is measured and its status. A criterion is MET only if its stated,
reproducible check passes. (Re-run the checks after any edit; scripts live in the session scratchpad
and are pure Python over the Markdown.)

| # | Criterion (objective) | How measured | Status |
|---|---|---|---|
| D1 | Every feature has a spec file with the standard sections (Purpose, Requirements, UI, Implementation, Edge cases, Acceptance tests) | 33 `docs/features/Fxx-*.md` since 2026-11-08 (27 active specs incl. the new F33, plus 6 merged stubs F17/F26/F28–F31 that keep the section headings); grouped specs (F23) noted in docs/README | MET (32/32) |
| D2 | Every requirement row has a stable ID + priority (P0/P1/P2) | ID-table scan | MET |
| D3 | No duplicate requirement IDs; no referenced-but-undefined IDs (incl. slash-shorthand) | `idcheck` | MET (544 IDs incl. the new `GRP` prefix, 0 dup, 0 dangling — re-run 2026-11-08; was 516) |
| D4 | Every internal Markdown link, `Fxx` ref, and `Mxx` ref resolves | `linkcheck` | MET |
| D5 | Every `## N`/`### N.M` numbering sequence has no gaps/dupes | `secnum` | MET |
| D6 | Every `Fxx §N` / `doc NN §N` cross-ref points to a real section | `secref` | MET |
| D7 | Each feature's milestone agrees across its header, the README index, and the roadmap | `featmap` (a suffix-aware copy since 2026-11-08) + `featmap2` (also checks roadmap sections and every suffixed `Mxx` ref) | MET (re-run 2026-11-08) |
| D8 | Every feature is scheduled in the roadmap with a Definition of Done | roadmap M0–M26 inspection | MET |
| D9 | Every acceptance test maps to a defined or milestone-scoped VulnLab fixture/endpoint | doc 06 §3 + §3.1; independently re-verified | MET |
| D10 | Every persisted requirement has a backing table/column; all FKs resolve | doc 04 §4 incl. Phase F tables; independently verified | MET |
| D11 | Module layering is acyclic; Linux-building modules don't depend on macOS-only ones; `Package.swift` matches doc 01 §3 | architecture + manifest cross-check | MET |
| D12 | Each milestone's tasks need only capabilities built by then; forward deps marked "(later: Mxx)" | roadmap deferral list + per-spec notes | MET |
| D13 | No contradictions across docs on load-bearing points | multi-panel independent review | MET (no Blockers/Majors) |
| D14 | Prose has no misspellings (code/URLs excluded) | aspell with a verified technical-terms dictionary | MET (0 unknown real words) |
| D15 | All Markdown tables are well-formed (any in-cell pipe escaped as backslash-pipe) | table-shape check | MET |
| D16 | Independent fresh-eyes review finds no Blocker/Major | 10 agent reviews incl. a final 2-reviewer panel + targeted re-verifications | MET |
| C1 | The Swift code compiles and tests pass | `swift build`/`swift test`, `xcodebuild` | **OUT OF SCOPE / ENVIRONMENT-IMPOSSIBLE (live-verified 2026-11-07)**: no toolchain installed; the apt `swift` package is OpenStack, not the language; and the toolchain host `download.swift.org` returns `403 CONNECT tunnel failed` through the sandbox proxy (toolchain tarball + swiftly both blocked; only `swift.org` allowlisted). This is a *code* gate enforced by CI (`.github/workflows/ci.yml`), not a Markdown property. |

D1–D16 are MET. C1 is not a documentation criterion and cannot be run here; it is the CI gate for the
code produced *from* these docs. By this objective standard the documentation is build-ready.

**Independently audited (2026-11-07).** A fresh auditor re-derived all 16 criteria from the files
(not trusting this status column) and returned **14/16 cleanly verified, FINAL JUDGMENT: BUILD-READY
(no Blocker, no Major)**. It correctly caught that D8 and D15 had been over-claimed: M18/M19 lacked a
`**DoD:**` line (D8), and the D15 row above itself had an unescaped in-cell pipe (D15). Both were
Minor and both are now fixed (DoD lines added to roadmap M18/M19; this row reworded), so D8 and D15
now genuinely hold. The independent judgment that the objective bar is met therefore stands with the
status column accurate.

### Documentation verification (as of the last review)

The specs were reviewed in several passes, including independent fresh-eyes agent reviews of the core
docs, F01–F12, F13–F24 and F25–F32. Every core doc (00–07) and all **32** feature specs have been
read end to end, and the following consistency checks all pass over the **whole** set (F01–F32) —
re-run them after any doc edit:

- **Requirement IDs**: **516** defined across the spec tables (incl. the Phase F prefixes
  SSO/WSX/JSR/WCP/GOV/DRF/JRN/LLM), no duplicates, and every `Fxx-NNN` reference resolves to a defined
  ID (including slash-shorthand like `MAC-010/011`).
- **Links**: every relative Markdown link resolves; every `Fxx` feature reference has a file; every
  `Mxx` milestone reference is defined in the roadmap.
- **Section numbering**: `## N.`/`### N.M` sequences have no gaps or duplicates in any doc.
- **Section cross-refs**: every `Fxx §N` / `doc NN §N` points to a section that exists.
- **Feature↔milestone**: each spec header, the roadmap body, and the README index agree.
- **Make targets**: every `make <target>` mentioned in the docs exists in the Makefile.
- **Tables**: all Markdown tables are well-formed (literal `|` in cells escaped as `\|`).
- **Spelling**: aspell over the prose (code/URLs stripped) shows only legitimate technical terms.

**Independent build-readiness verdict (2026-11-07).** Multiple fresh-eyes reviewers (no prior context)
checked the set, with "build-ready" defined as *no Blockers and no Majors (Minors acceptable)*. The
Majors they found were fixed and re-verified:
- F29/F31 fold-in P0 work was missing from the M9/M11/M16 task lists/DoDs and this tracker → wired in;
  an independent re-verification then confirmed each milestone carries both a task bullet and a DoD.
- A **final two-reviewer panel** over the whole set converged: the holistic reviewer returned
  BUILD-READY; the adversarial reviewer found v1 (M0–M20) clean and one Phase-F-only Major — the
  F25/F27/F28/F32 acceptance tests referenced VulnLab OIDC/SAML, source-map/`/api/internal`,
  cache-poisoning and LLM fixtures that doc 06 §3 didn't define → added doc 06 §3.1 "Phase F fixtures".
- Phase F schema Minors (new-endpoint identity, multi-step/identity proof columns, split migrations,
  blob-GC walk) and assorted cross-refs were cleared along the way.

With those fixed, both final reviewers' criterion — no Blockers, no Majors — is satisfied across
F01–F32. "Nearly perfect" is a subjective bar; this is the strongest objective evidence available
here (independent agreement + all automated consistency checks green).

What is **not** verified here: the Swift code compiles/tests (no toolchain in the authoring
container — CI is the gate, see the caveat above), and spec implementation-note API hints are
best-effort guidance, not proven against the libraries; the acceptance tests are the source of truth
for behavior.

## Milestone checklist (summary — details in docs/03-roadmap.md)

- [x] M0 — Scaffolding (repo layout, Package.swift, project.yml, Makefile, CI, empty app window) — **CI green both platforms (`6e17d38`)**
- [x] M1 — Core model + raw HTTP/1 engine — **CI green both platforms + executable DoD PASS (`cd84c2a`)**
- [x] M2 — Plain-HTTP proxy, storage, history UI — **CI green both platforms + executable DoD PASS (`1acf39c`)**
- [x] M3a — TLS interception + CA (HTTP/1.1) — **CI green both platforms + executable DoD PASS (`054b24a`)**
- [x] M3b — HTTP/2 (client side + upstream, trailers) — **CI green both platforms + executable DoD PASS (`11cd7d5`)**
- [x] M4a — Message editor, Intercept, Match & Replace, Send to / Copy as — **CI green both platforms + executable DoD PASS (`dee2424`)**
- [x] M4b — Streaming responses, WebSockets, Gulp Browser launch — **CI green both platforms + executable DoD PASS (`0b0c6f7`)**
- [ ] M5 — Repeater + advanced HTTP engine (HTTP/2 raw, group/race sends, streaming, paste-to-request) — *implemented; local Linux gate + DoD PASS; awaiting macOS CI*
- [ ] M6a — Target: site map + scope + ScopeGuard — *implemented; local Linux gate + DoD PASS; awaiting macOS CI*
- [ ] M6b — Import/export service, API import, MCP read surface + `send_request` — *implemented; local Linux gate + DoD PASS; awaiting macOS CI*
- [ ] M7 — Decoder + Comparer + JWT Workbench — *implemented; local Linux gate + DoD PASS; awaiting macOS CI*
- [ ] M8 — Fuzzer (with content discovery) — *implemented; local Linux gate + DoD PASS; awaiting macOS CI*
- [ ] M9 — Logger, GulpQL, search, Notebook, coverage index — *implemented; local Linux gate + DoD PASS; awaiting macOS CI*
- [ ] **Daily-driver beta** — release gate after M9 (signed + notarized build to real testers)
- [ ] M10a — Passive scanner + issue model — *implemented; local Linux gate + DoD PASS; awaiting macOS CI*
- [ ] M10b — gRPC & protobuf (F33) — *implemented; local Linux gate + DoD PASS; awaiting macOS CI*
- [ ] M11a — Crawler (static), Beacon client + dev Beacon, shared limiter + panic stop — *implemented; local Linux gate + DoD PASS; awaiting macOS CI*
- [ ] M11b — Active scan engine + P0 checks — *implemented; local Linux gate + DoD PASS; awaiting macOS CI*
- [ ] M11c — Full check catalog (incl. SCN-070…074) + crawl-and-audit — *partial: crawl-and-audit, API scan, gRPC points, re-test done; P1 active checks landed — CORS, host-header, JWT (alg:none/weak-secret), mass assignment (SCN-072), server-side prototype pollution (SCN-070), NoSQL/`$where`, XPath (via `string-length()`), LDAP (wildcard) and unrestricted file upload (SCN-073); only remaining: CSPT (SCN-071, browser-gated)*
- [ ] M12a — Sessions, auth, macros, request signing
- [ ] M12b — Authz Matrix
- [ ] M13a — Browser automation: CDP crawl, recorded logins, passkeys
- [ ] M13b — DOM Probe + GraphQL Workbench
- M14 — *(retired: Sequencer moved to the Post-1.0 backlog)*
- [ ] M15 — Extensions + scripting + Check Recipes
- [ ] M16a — Reporting (bug-bounty Markdown, CSRF PoC)
- [ ] M16b — Project polish, throughput panel, coverage view + timeline
- [ ] M17 — Automation: CLI, REST API, full MCP server, scheduler
- [ ] M18 — Gulp Assistant (AI) incl. bounded agentic follow-up
- [ ] M19a — Param Discovery, secret scanner, JS Recon core
- [ ] M19b — Smuggling Probe
- [ ] M20 — macOS polish, packaging, release
- [ ] M21 — F25 SSO Workbench *(Phase F, post-1.0; suggested first with M26)*
- [ ] M22 — WebSocket fuzzing and checks (WSX, merged from F26)
- [ ] M23 — F27 JS Recon Studio (rest)
- [ ] M24 — Cache poisoning & deception check family (WCP, merged from F28)
- [ ] M25 — Issue retest (DRF, merged from F30)
- [ ] M26 — F32 LLM/AI-feature security testing (incl. MCP/agent endpoints)
- Post-1.0 backlog (unscheduled): F11 Sequencer, deployable Beacon server, Extension Gallery, MAC-011 transparent proxy, HTTP-037 HTTP/3 client

## Log

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
  - Also corrected a spec error found while scaffolding: `SNIHandler` is in the `NIOTLS` module of
    swift-nio (a later review corrected an interim "NIOSSL" note; doc 01 §1 and F02 §4 are authoritative).
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
- 2026-11-09 — **M6a implemented** (local Linux gate; macOS UI unverified): site map trie +
  live service + inferred links (TGT-001…003), endpoints/notes/Analyze target/Delete branch
  (TGT-002/004/007/008), filters incl. 404/MIME and `{id}` folding (TGT-005/006), schema v3
  `site_map_notes`; scope rules, ScopeGuard, `in_scope` recompute (TGT-020…023), proxy uses scope
  (TGT-024/PRX-045), scope JSON (TGT-025); Repeater out-of-scope confirmation; `gulp-cli scope` /
  `target`, `proxy --use-scope`, `repeater --allow-out-of-scope`; VulnLab home page `/`;
  `Scripts/m6a-dod.sh` PASS. Fixed: closing a session now cancels and awaits the site map
  listener first (a concurrent read made the close checkpoint fail with "database is locked").
- 2026-11-09 — **M6b implemented** (local Linux gate; macOS menus unverified): GulpCodec traffic
  formats (HAR in/out with `_gulp` raw bytes, Postman v2.1, XML proxy history, Caido, sitemap/URL
  lists, OpenAPI 3.x/Swagger 2.0 JSON with schema-aware values, CSV); ImportExportService (dedup by
  target + bytes + start time, `imported` tag, `.gulp` merge and export); schema v4 (request-blob
  index, `audit_log`); MCP stdio server with ScopeGuard, approval policy and audit log;
  `gulp-cli project import|export|info|audit`, `gulp-cli mcp`, `send --repeat` `{n}`; VulnLab
  `/openapi.json` + `/api/*`; `Scripts/m6b-dod.sh` PASS.
- 2026-11-09 — **M7 implemented** (local Linux gate; macOS views unverified): GulpCodec transform
  registry (URL/HTML/Base64/32/58/hex/numbers/escapes/JSON/compression/hashes incl. SHA-3/HMAC/
  converters), Smart Decode, Transform Tags + TransformTagHook (Repeater/Fuzzer only), project tag
  variables; GulpDiff (Myers, word/byte, line localisation, positional alignment for same-shape
  inputs, pre-diff transforms); JWT Workbench core (all JWS algorithms, PEM/JWK/JWKS, attack
  helpers, cracking); VulnLab JWT lab (`/api/login`, `/api/me`, `/safe/api/me`, key/JWKS);
  `gulp-cli decode|diff|jwt`, `repeater --var/--no-tags`; ToolInbox; `Scripts/m7-dod.sh` PASS.
  Fixed on the way: unicode-escape didn't escape backslashes (round-trip test); a formatter-wrapped
  `..<` parsed as two statements; Myers paired changes far apart in repetitive text.
- 2026-11-10 — **M8 implemented** (local Linux gate; macOS view unverified): GulpFuzzer positions
  (`§…§`, auto-mark), lazy payload sources (lists, files, numbers, dates, brute force, null, same as
  base, recursive grep) and processors (incl. Decoder ops and Transform Tags), the four attack
  types, grep match/extract, reflection, baseline anomalies, the attack runner (lanes, rps cap,
  delays, retries, stop conditions, pause/resume/cancel, ScopeGuard) with saved attacks (schema
  tables `fuzzer_attacks`/`fuzzer_results`), content discovery with soft-404 fingerprints, bundled
  wordlists; VulnLab `/login` (single-use CSRF), `/account`, `/admin`, backup files; Fuzzer view and
  Send to Fuzzer; `gulp-cli fuzz|discover|wordlists`; `Scripts/m8-dod.sh` PASS. Fixed on the way:
  ScopeGuard refusals were counted as sent + errors ("sent 9, errors 9") — now `refused`.
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
- 2026-11-12 — **M11b implemented** (local Linux gate; macOS views unverified): GulpScanner
  insertion points, `ActiveScan` engine, scan presets and the P0 active checks (reflected/stored XSS,
  SQLi error/boolean/time, command injection time/OAST, SSTI, path traversal, XXE in-band/OAST, SSRF
  OAST, open redirect, CRLF) with 14 issue definitions; VulnLab scan lab + safe twins +
  `Fixtures/vulnlab-active.json`; workspace scan service; `gulp-cli scan active|verify-active`;
  Scanner → Audit pane and History "Actively scan"; unit tests against an in-process fake app with
  simulated timing; `Scripts/m11b-dod.sh` PASS. Deviation: canaries aren't seeded (F08 §5; doc 07).
  Fixed on the way: absolute-form detection in `DerivedFields`; case-sensitive multipart boundaries.


- 2026-11-12 — **M12a implemented** (local Linux gate; macOS UI unverified): GulpSession cookie jar,
  identities, macros + runner, session rules, validity check and request signing (DPoP RFC 9449, HTTP
  Message Signatures RFC 9421, AWS SigV4); GulpWorkspace session hooks (rules first, signer last,
  response-side cookie/nonce/staleness) with single-flight re-auth; VulnLab `/signed/*` independent
  verifiers and `/session/expire`; `gulp-cli session sign|reauth`; `Scripts/m12a-dod.sh` PASS. ECCurve
  is now Codable. Deviations and carry-overs in doc 07 and the status block above.

- 2026-11-12 — **M12b implemented** (local Linux gate; macOS UI unverified): `AuthzAnalysis` verdict
  logic, `runAuthzMatrix` orchestration (replay as identities under ScopeGuard, raise
  `authz.broken-access-control`), VulnLab `/safe/api/orders/{id}` enforcing twin, `gulp-cli authz
  orders`; `Scripts/m12b-dod.sh` PASS. Carry-overs above.

- 2026-11-13 — **M13b GraphQL implemented** (local Linux gate): GulpCodec GraphQL (detect, introspect,
  schema parse/render, body build), Scanner GraphQL-variable insertion points, workbench checks
  (introspection-enabled, broken-object-authz), VulnLab `/graphql`+`/safe/graphql`, `gulp-cli graphql
  introspect|scan`; `Scripts/m13b-graphql-dod.sh` PASS. DOM Probe deferred to M13a's browser work.

- 2026-11-13 — **Reporting (F19/M16) implemented**: `GulpReport` HTML + bug-bounty Markdown renderers
  over the issue model; `ProjectSession.generateReport`; `gulp-cli report`; `Scripts/report-dod.sh`
  PASS (added to CI/gate). PDF export and the macOS report view remain. The GulpReport stub is now
  real content.
- 2026-11-13 — **Capstone progress**: architecture review (`docs/08-architecture-review.md`) backed
  by `Scripts/arch-check.sh` (dependency-direction + platform rules enforced in CI; removed
  GulpScanner's 3 unused deps); Burp Suite comparison (`docs/09-burpsuite-comparison.md`); first
  outperformance increments shipped — secret & JS recon (F27) and formatted reporting (F19).

- 2026-11-13 — **Check Recipes (SCN-060/061/064, passive) implemented**: declarative no-code checks
  (`CheckRecipe`/`RecipeMatcher`) with path/content gates, header/body/status/regex matchers and OR
  groups, and a templated issue; they join the passive scan via `PassiveScanSettings.recipes`;
  `gulp-cli scan passive --recipes <file|dir>` loads a JSON recipe library; `Scripts/recipe-dod.sh`
  PASS (added to CI/gate). Recipes are JSON (YAML a thin future layer); active recipes + editor remain.
  Closes Burp-comparison gap #3 for the no-code-check half.

- 2026-11-13 — **Vulnerable JS libraries** passive check (`passive.vuln-js-library`): fingerprints
  jQuery/lodash/Bootstrap/Moment/Handlebars/AngularJS/DOMPurify versions from filenames, banners and
  VERSION strings against a bundled advisory dataset, always-on; VulnLab `/libs/old`(+safe). 446 tests.

## How to pick up work (reminder)

1. Read `CLAUDE.md` §1 (reading order) and this file.
2. Open the active milestone in `docs/03-roadmap.md`; read the referenced feature spec(s) and their
   requirement IDs.
3. Implement P0 first, tests naming requirement IDs; run `make test` + `make lint`; keep the core
   modules building on Linux.
4. Tick the box here, add a log line (date, what, any deviation), and commit referencing the IDs.
