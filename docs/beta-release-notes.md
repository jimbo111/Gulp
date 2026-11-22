# Gulp 0.1.0 beta — release notes

The daily-driver beta: the manual-testing core of Gulp, for a small group of testers. Report
problems through [GitHub issues](https://github.com/jimbo111/Gulp/issues/new/choose) (the bug
template asks for the steps, the macOS version and what you expected).

## Install

`Gulp-0.1.0-beta.zip` (built by `Scripts/beta-build.sh`; its SHA-256 is published next to it) holds a
universal `Gulp.app` (Apple silicon and Intel, macOS 14 or later). It is signed ad hoc and **not
notarized**, so the first launch is blocked: right-click `Gulp.app` and choose **Open**, or open
**System Settings > Privacy & Security** and choose **Open Anyway**. The command-line tool is inside
the app at `Gulp.app/Contents/Helpers/gulp`.

The bundle ID is `io.github.jimbo111.gulp`. A Mac that ran a development build from before 0.1.0
(`com.gulp.app`) gets a new certificate authority: trust the new one in your browser, and enter
request-signing secrets again.

## What the beta covers

- **Proxy**: HTTP/1.1, HTTP/2, TLS interception from a local CA, streaming responses and SSE,
  WebSockets; Intercept and Match & Replace; the Gulp Browser (Chrome, pre-configured to use Gulp).
- **Repeater**: exact bytes, raw HTTP/2, race sends (single-packet, parallel, sequential), paste a
  request.
- **Target**: site map and scope; active tools refuse out-of-scope targets.
- **Import**: HAR, OpenAPI (JSON), Postman, other proxies' history; the read-only MCP surface.
- **Decoder, JWT Workbench, Comparer, Fuzzer** (with content discovery), **Logger, GulpQL, search,
  Notebook**.

`Scripts/beta-dod.sh` drives one project through all of these against VulnLab, then quits and
reopens it and checks every artifact.

## In the app, but not part of the beta

These open and work in part; they are not what the beta asks you to test: the scanner (passive and
active) and crawler, sessions and macros, the Authz Matrix (it has no identities editor yet),
extensions (the manager only audits a manifest), reports (CLI only), the Assistant (redaction
preview only), DOM Probe (CLI only), and the specialist workbenches. `docs/PROGRESS.md` lists what
each one is missing.

## Known gaps in the beta tools

- **Content**: brotli and zstd response bodies are not decoded; SOCKS5 upstreams without
  authentication only; no PKCS#12 import for client certificates; no ECH.
- **Projects**: closing a temporary project does not ask to save it (it stays recoverable in
  Caches); no Project Info panel; no "Use settings from another project" UI.
- **History**: no "add to scope" from a row, no in-scope/MIME/method chips, no inline comment
  editing; no GulpQL syntax coloring; no custom columns.
- **Message editor**: no Render tab and no editable hex view; Content-Length is always updated on
  send.
- **Intercept / Match & Replace**: no auto-forward timeout; rules have no per-scope setting or test
  pane; History keeps the response as received, not as edited.
- **WebSockets**: no WebSockets over HTTP/2; compressed (permessage-deflate) messages cannot be
  edited; a connection's history loads whole; a held message stays queued after its client leaves.
- **Gulp Browser**: each launch records two of Chrome's own background requests (Gaia account check,
  component update) as out-of-scope rows.
- **Repeater**: no NTLMv2; no structured Inspector edits; no variable capture; single-packet HTTP/2
  does not respect the server's stream limit; WebSocket logs are not saved.
- **Target**: the site map is a list, not a tree view; "don't ask again" for an out-of-scope send
  lasts for the session.
- **Import**: OpenAPI and Swagger YAML are not read.
- **Fuzzer**: no Turbo mode; no Snippet payload processor.

Measured on an M4 Pro: proxy overhead 0.06 ms median, about 13,000 requests/s through the proxy, a
1M-row project opens in under a second. Cold start and scrolling frame times have not been measured.
