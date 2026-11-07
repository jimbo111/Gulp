# 01 — Architecture

## 1. Tech stack

| Concern | Choice | Why (details in doc 07) |
|---|---|---|
| Language | Swift 6, language mode 6 (strict concurrency) | Native, fast, one language for UI and engine |
| UI | SwiftUI for the app shell, forms and settings; **AppKit** (via `NSViewRepresentable`) for heavy views: history tables (`NSTableView`), the message editor (`NSTextView`, TextKit 2), hex view, site-map outline (`NSOutlineView`) | SwiftUI `Table` and `TextEditor` don't scale to 1M rows or multi-MB syntax-highlighted bodies |
| State | Observation framework (`@Observable`) for view models | macOS 14+ |
| Networking | SwiftNIO 2.x: `swift-nio` (NIOCore/NIOPosix/NIOHTTP1, and `SNIHandler` lives in its **NIOTLS** module), `swift-nio-ssl` (NIOSSL), `swift-nio-http2` (NIOHTTP2), `swift-nio-extras` (NIOHTTPCompression, NIOSOCKS) | Byte-level control, server and client, HTTP/2 frames, high throughput |
| Certificates | `swift-certificates` (X.509 building and signing), `swift-crypto` + `_CryptoExtras` (RSA) | Pure Swift, cross-platform |
| Storage | SQLite through **GRDB.swift** (WAL, FTS5) | Crash-safe single-file projects, fast paging and search |
| Logging | `swift-log` (OSLog backend on macOS) | Standard |
| CLI | `swift-argument-parser` | Standard |
| HTTP servers (REST API, Beacon, VulnLab) | **Hummingbird 2** (built on NIO) | Saves writing routing by hand |
| Scripting | **JavaScriptCore** (macOS) for Snippets and in-process extensions | Built into macOS, sandboxable |
| Out-of-process extensions | JSON-RPC 2.0 over stdio | Any language (a Python SDK is provided) |
| Browser automation | Chrome DevTools Protocol (CDP) over WebSocket to a managed Chromium | Crawling, DOM Probe, login recording |
| Charts | Swift Charts | Sequencer, dashboard |
| Updates | Sparkle 2 | De facto standard for apps distributed outside the App Store |
| Project generation | XcodeGen (`project.yml`) | A text project file that Claude can edit; `.xcodeproj` is git-ignored |

Minimum OS: **macOS 14 Sonoma**. Development toolchain: the latest stable Xcode (Swift 6.x).

## 2. Repository layout

```
Gulp/
├── CLAUDE.md
├── README.md
├── LICENSE                          # MIT (docs/07 decision #2)
├── Makefile
├── Brewfile                         # Homebrew deps for `make bootstrap` (xcodegen, swift-format)
├── project.yml                      # XcodeGen spec: Gulp.app target + GulpAppUITests
├── .swift-format                    # formatting rules
├── .github/workflows/ci.yml
├── App/                             # macOS app target (thin: composition + windows)
│   ├── GulpApp.swift                # @main, WindowGroup/DocumentGroup, commands
│   ├── AppDelegate.swift
│   ├── Info.plist
│   ├── Gulp.entitlements
│   └── Resources/ (Assets.xcassets, Credits.rtf)
├── Packages/
│   └── GulpKit/                     # ALL logic lives here (SwiftPM)
│       ├── Package.swift
│       ├── Sources/
│       │   ├── GulpCore/            # models, bytes, parsing, scope, events (no deps on other Gulp modules)
│       │   ├── GulpCodec/           # encoders/decoders/hashes/compression (Decoder backend)
│       │   ├── GulpQuery/           # GulpQL lexer/parser/evaluator
│       │   ├── GulpStore/           # GRDB persistence, migrations, FTS, project files
│       │   ├── GulpTLS/             # CA, leaf minting, cert cache, client certs
│       │   ├── GulpHTTP/            # raw HTTP engine (H1/H2 client), connection pool, race sync
│       │   ├── GulpProxy/           # NIO proxy server, intercept pipeline, match & replace, WS
│       │   ├── GulpSession/         # cookie jar, session rules, macros, identities
│       │   ├── GulpRepeater/        # repeater model & send logic (UI-free)
│       │   ├── GulpFuzzer/          # attack engine, payload generators/processors, grep
│       │   ├── GulpScanner/         # passive/active checks, insertion points, issue model, recipes
│       │   ├── GulpCrawler/         # HTML/JS link extraction, crawl frontier, (CDP-backed mode)
│       │   ├── GulpOAST/            # Beacon client + interactsh client
│       │   ├── GulpSequencer/       # token capture + statistical tests
│       │   ├── GulpDiff/            # Myers diff, similarity scoring
│       │   ├── GulpBrowser/         # Chromium discovery/launch, CDP client  (macOS only)
│       │   ├── GulpScript/          # JavaScriptCore runtime, Snippets, JS extension host (macOS only)
│       │   ├── GulpExtensions/      # extension manager, JSON-RPC host, API surface
│       │   ├── GulpReport/          # HTML/MD/JSON/SARIF report generation
│       │   ├── GulpAI/              # LLM provider abstraction, prompts, redaction
│       │   ├── GulpAutomation/      # REST API + MCP server (Hummingbird)
│       │   ├── GulpWorkspace/       # ProjectSession: wires engines + store + event bus for one project
│       │   ├── GulpUI/              # reusable AppKit/SwiftUI components (macOS only)
│       │   ├── GulpFeatures/        # feature screens + view models (macOS only)
│       │   ├── gulp-cli/            # headless executable
│       │   └── gulp-vulnlab/        # intentionally vulnerable test server (executable)
│       └── Tests/  (one test target per module, + IntegrationTests)
├── Beacon/                          # OAST server: separate SwiftPM package, deployable on Linux/Docker
│   ├── Package.swift
│   ├── Sources/gulp-beacon/
│   └── Dockerfile
├── SDK/
│   ├── js/gulp.d.ts                 # TypeScript typings for JS extensions
│   └── python/gulp_sdk/             # out-of-process extension SDK
├── Scripts/                         # build, sign, notarize, dmg, fixtures
└── docs/
```

## 3. Layering and dependency rules

```
                ┌────────────────────────────────────────────────┐
  App layer     │ App/ (Gulp.app)          gulp-cli              │
                └───────────────┬────────────────────┬───────────┘
                ┌───────────────▼─────────┐          │
  UI            │ GulpFeatures → GulpUI   │ (macOS)  │
                └───────────────┬─────────┘          │
                ┌───────────────▼────────────────────▼───────────┐
  Orchestration │ GulpWorkspace (ProjectSession) · GulpAutomation │
                │ GulpAI  (both build on the GulpWorkspace tool    │
                │          surface; see rule 6)                   │
                └───────────────┬────────────────────────────────┘
                ┌───────────────▼────────────────────────────────┐
  Engines       │ GulpProxy GulpRepeater GulpFuzzer GulpScanner   │
                │ GulpCrawler GulpSequencer GulpSession GulpOAST  │
                │ GulpBrowser GulpScript GulpExtensions           │
                │ GulpReport                                      │
                └───────────────┬────────────────────────────────┘
                ┌───────────────▼────────────────────────────────┐
  Services      │ GulpHTTP  GulpTLS  GulpStore  GulpQuery         │
                │ GulpCodec GulpDiff                              │
                └───────────────┬────────────────────────────────┘
                ┌───────────────▼────────────────────────────────┐
  Foundation    │ GulpCore                                        │
                └────────────────────────────────────────────────┘
```

Rules:

1. A module may import only modules in the **same or lower** layers. Engines may import each other
   only where this table allows it:
   - `GulpScanner` → `GulpOAST`, `GulpCrawler`, `GulpSession`
   - `GulpCrawler` → `GulpSession`. It must **not** import `GulpBrowser` (that would pull a
     macOS-only module into the Linux build and invert the layering). Browser-backed crawling is
     reached through a `BrowserDriver` protocol defined in `GulpCrawler`; the concrete CDP
     implementation lives in `GulpBrowser` and is injected by `GulpWorkspace` on macOS (rule 5). On
     Linux the driver is simply absent and only static-mode crawling is available.
   - `GulpFuzzer` → `GulpOAST`, `GulpSession`
   - `GulpExtensions` → any engine (it exposes them to extensions)
2. Engines never import `GulpUI`, `GulpFeatures`, SwiftUI or AppKit.
3. `GulpCore` has no dependencies except `swift-collections` and `swift-log`.
4. The platform-capability modules (`GulpBrowser`, `GulpScript`, `GulpUI`, `GulpFeatures`) are
   **defined on every platform** (no `#if os(macOS)` in the manifest); their AppKit/JavaScriptCore
   code is wrapped in `#if canImport(...)` so on Linux they compile to empty shells. Dependencies on
   them are plain and unconditional, and the package graph is identical on macOS and Linux
   (doc 02 §5; ADR-010). Everything compiles on Linux; only the shells are empty there.
5. Cross-cutting behavior goes through **protocols defined in a lower layer** and implemented in a
   higher one. Example: `GulpHTTP` defines `RequestHook`; `GulpSession` and `GulpExtensions`
   implement it; `GulpWorkspace` registers them.
6. **Agent tool surface.** The set of capabilities an automated/AI caller can invoke (list/send
   exchanges, start a scan, read issues, change scope…) — its request/response DTOs, JSON schemas,
   and the `APIGate` that enforces ScopeGuard, the approval mode and the audit log — is defined once
   in **`GulpWorkspace`** (orchestration). Both `GulpAutomation` (REST/MCP, F21) and `GulpAI`
   (assistant, F22) are orchestration-layer consumers that depend on `GulpWorkspace` and reuse that
   one definition; `GulpAI` additionally uses `GulpReport` for drafting. Neither imports the other,
   and `GulpWorkspace` does **not** depend on `GulpAI`/`GulpAutomation` (that would cycle) — the app
   and `GulpFeatures` compose them on top.

## 4. Linux compatibility matrix

| Module | Linux | Notes |
|---|---|---|
| GulpCore, GulpCodec, GulpQuery, GulpDiff | ✅ | Pure Swift |
| GulpStore | ✅ | Needs `libsqlite3-dev` installed |
| GulpTLS, GulpHTTP, GulpProxy | ✅ | NIO + BoringSSL (bundled in swift-nio-ssl) |
| GulpSession, GulpRepeater, GulpFuzzer, GulpScanner, GulpCrawler (static mode), GulpOAST, GulpSequencer, GulpReport, GulpAI, GulpAutomation, GulpWorkspace, gulp-cli, gulp-vulnlab | ✅ | |
| GulpExtensions | ✅ (JSON-RPC only) | The JS host is compiled only when `canImport(JavaScriptCore)` |
| GulpBrowser, GulpScript, GulpUI, GulpFeatures | ⚠️ shell | Targets are defined and **compile on Linux as empty shells** (their AppKit/JavaScriptCore code is behind `#if canImport(...)`); the real functionality is macOS-only. So `swift build`/`swift test` cover the whole graph on Linux, but these modules do nothing there. |

This lets most of the engine be built and tested in Linux CI or cloud containers.

## 5. Runtime model

### 5.1 Processes

- **Gulp.app**: the main process. Each open project runs one `ProjectSession`.
- **Managed Chromium**: a child process launched by `GulpBrowser`, with its own profile, proxy and
  CDP port.
- **Out-of-process extensions**: child processes that talk JSON-RPC over stdio.
- **gulp-beacon** (optional): the user's own OAST server, deployed on a VPS (see F10).

### 5.2 ProjectSession (GulpWorkspace)

`ProjectSession` is an `actor` that owns everything for one open project:

```swift
public actor ProjectSession {
    public let id: UUID
    public let store: ProjectStore              // GulpStore
    public let settings: LayeredSettings        // user + project settings
    public let scope: ScopeService              // GulpCore
    public let events: EventBus                 // GulpCore
    public let http: HTTPEngine                 // GulpHTTP, with hooks registered
    public let proxy: ProxyService              // GulpProxy (0..n listeners)
    public let sessions: SessionService         // GulpSession
    public let scanner: ScannerService
    public let fuzzer: FuzzerService
    public let oast: OASTService
    public let extensions: ExtensionManager
    // …
    public static func open(at url: URL) async throws -> ProjectSession
    public func close() async
}
```

The app holds one `ProjectSession` per window (document). The CLI and the automation API use the
same type, which is why the headless and GUI modes behave the same.

### 5.3 Event bus

`EventBus` is a typed broadcast built on `AsyncStream`. Producers never block: each subscriber has
a bounded buffer, and if it overflows the subscriber gets a `.lagged(count)` marker and should
re-query the store.

```swift
public enum GulpEvent: Sendable {
    case exchangeRecorded(ExchangeID, source: ToolSource)
    case exchangeUpdated(ExchangeID)                     // response arrived, annotation changed…
    case interceptQueued(InterceptItemID)
    case wsMessage(WSMessageID)
    case issueFound(IssueID)
    case taskProgress(TaskID, TaskProgress)
    case oastInteraction(OASTInteractionID)
    case scopeChanged
    case settingsChanged(SettingsKey)
    case log(LogEntry)
}
```

The ID types are `Int64` row ids (`typealias TaskID = Int64`, likewise `ExchangeID`,
`IssueID`, `InterceptItemID`, `WSMessageID`, `OASTInteractionID`), all in `GulpCore`. `TaskProgress`
is Gulp's own value type (fraction done, counts, ETA — not Foundation's `Progress`). `SettingsKey`
identifies a settings group + key (it maps to the `SettingsGroup.key` string of doc 04 §6, carried
as `struct SettingsKey { let group: String; let key: String? }`). `LogEntry` is the event-log record
shown in the Event Log panel (§8).

### 5.4 Concurrency and threading

- One `MultiThreadedEventLoopGroup` per process (`System.coreCount` threads) for all networking.
- Orchestration uses Swift structured concurrency (task groups for scanning and fuzzing). Tasks have
  a priority, and cancellation is honored everywhere.
- **MainActor** is used only for the UI. View models are `@MainActor @Observable` and receive
  coalesced events: a `Debouncer` gathers events and applies them in one batch every ≤100 ms.
- Database writes go through one **write coalescer** in `GulpStore`. It batches inserts (flushes
  every 50 ms or 500 rows, whichever comes first) in a single transaction, so the proxy never waits
  on SQLite.
- Reads use the `DatabasePool` (WAL), so they run concurrently with writes.

### 5.5 Request flow: proxied request

```
Client ──TCP──▶ ProxyListener (NIO)
   │  CONNECT host:443 ? → reply 200 → sniff ClientHello (SNIHandler) → TLS policy:
   │      MITM: mint/lookup leaf cert (GulpTLS) → NIOSSLServerHandler (ALPN mirrors upstream)
   │      Pass-through: splice bytes (no decryption) for hosts on the TLS pass-through list
   ▼
HTTP decoder (raw-preserving H1 / H2 frames) → RawRequest + metadata
   ▼
Request pipeline:  match&replace(request) → InterceptGate (if enabled and rules match → await user) → extensions(onRequest)
   ▼
HTTPEngine.send (upstream proxy? DNS override? H1/H2 per ALPN) ──▶ Server
   ▼
Response pipeline: match&replace(response) → InterceptGate(response) → extensions(onResponse)
   ▼
Store.record(exchange) (async, coalesced) → EventBus.exchangeRecorded → UI / passive scanner
   ▼
Client ◀── raw response bytes
```

### 5.6 Request flow: tool-generated request (Repeater, Fuzzer, Scanner, Crawler, extension)

```
Tool builds RawRequest
   ▼
ScopeGuard.check (active tools) ── refuse/confirm
   ▼
HTTPEngine.send(request, target, options)
   ├─ RequestHooks (ordered): SessionRules (F15) → TransformTags (F12) → Extensions → ContentLengthFixer (if enabled)
   ├─ Connection: pool lookup or new (TCP → optional upstream proxy CONNECT → TLS with SNI → ALPN)
   └─ ResponseHooks: Extensions → SessionRules (cookie jar update)
   ▼
Logger records exchange (source = tool)   →  passive scanner (if enabled for tool)
```

## 6. Key shared abstractions (all in GulpCore unless stated)

| Type | Purpose |
|---|---|
| `ByteBuffer`-free `Bytes` (`[UInt8]` wrapper with slicing views) | Core message storage, independent of NIO, so that UI and store don't import NIO |
| `RawRequest`, `RawResponse` | Raw bytes plus lazily computed `ParsedHTTPMessage` (byte ranges of start line, headers, body) |
| `HTTPTarget` | `scheme`, `host`, `port`, `sni?`, `ipOverride?`, `httpVersionPreference` |
| `Exchange` | One request/response pair with metadata (see doc 04) |
| `InsertionPoint` | A named byte range in a request plus an encoding context (F08) |
| `ScopeService` / `ScopeGuard` | Scope rules and checks (F04) |
| `ToolSource` | `.proxy, .repeater, .fuzzer, .scanner, .crawler, .sequencer, .extension(id), .session, .browser, .automation, .ai` |
| `Highlight` | Color tag (red, orange, yellow, green, cyan, blue, purple, pink, gray) |
| `Annotation` | Comment, highlight, tags |
| `GulpError` | Error enum with user-facing message and recovery suggestion |

## 7. Security of Gulp itself

Gulp processes hostile input all day, so the tool itself is a target.

- **Render view**: response HTML is rendered in a `WKWebView` with JavaScript disabled
  (`WKWebpagePreferences.allowsContentJavaScript = false`) and a `WKContentRuleList` that blocks all
  network loads, so a page can't call home or run script inside Gulp. Optionally, network loads can
  be routed through the Gulp proxy.
- **Parsers** must be robust against malformed and huge input. Fuzz-test them (doc 06), cap sizes,
  and never crash on bad bytes.
- **Local servers** (proxy listener, REST API, MCP) bind to `127.0.0.1` by default. The REST and MCP
  servers require a bearer token. Binding to all interfaces needs explicit opt-in, and Gulp shows a
  warning when it is enabled.
- **CA private key**: stored in the macOS Keychain (`kSecClassKey`, this-device-only). It can be
  exported only through an explicit action.
- **Extensions** declare permissions in their manifest (F18). The user approves them at install time.

## 8. Error handling and logging conventions

- Network errors are **data**, not exceptions: an exchange can end in a `.failed(GulpNetworkError)`
  state, which tables show (for example "Connection refused").
- Use `Logger(label: "gulp.<module>")` and keep logs free of secrets. Settings → Diagnostics has a
  "verbose network logging" toggle.
- The app has an **Event Log** panel that shows `GulpEvent.log` entries (warnings and errors that
  users should see, such as "Upstream TLS handshake failed for example.com: certificate expired").

## 9. Performance budgets (enforced by tests in doc 06)

| Metric | Budget |
|---|---|
| App cold start to usable window (M-series Mac) | < 1.0 s |
| Proxy added latency (median, keep-alive, small responses) | < 5 ms |
| Proxy throughput | ≥ 2,000 req/s locally against VulnLab |
| History table scroll with 1M rows | 60 fps, no hitches > 50 ms |
| Open a 1M-exchange project | < 3 s to first paint |
| Message editor: open a 5 MB response | < 300 ms to first paint (highlighting may continue in the background) |
| Fuzzer throughput (HTTP/1 keep-alive, local) | ≥ 1,000 req/s; Turbo mode ≥ 5,000 req/s |
