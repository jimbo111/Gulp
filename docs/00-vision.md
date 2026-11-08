# 00 — Vision, goals and principles

## 1. One-paragraph pitch

Gulp is a fast, native macOS workbench for testing web applications and APIs. A tester points a
browser (or a phone, simulator or CLI tool) at Gulp's proxy. Gulp records and lets them modify every
request, maps the application, and provides manual tools (Repeater, Fuzzer, Decoder and JWT
Workbench, Comparer) and automated ones (Crawler, passive and active Scanner, out-of-band Beacon) to find
vulnerabilities. It feels like a Mac app: fast to start, keyboard driven, light and dark mode,
multi-window, at home on Apple Silicon. It also adds modern capabilities: an optional AI assistant,
an MCP server so AI agents can drive it, and built-in access-control and API tooling.

## 2. Target users

- **Penetration testers and bug bounty hunters**: manual-first testing with heavy Repeater and Fuzzer use.
- **AppSec engineers**: scans of staging environments, CI automation, reports.
- **Developers**: debugging HTTP traffic and checking a fix.

## 3. Goals and non-goals

### Goals

1. Feature parity with a professional web security suite for the core workflow: proxy → map →
   manual testing → automated scanning → reporting.
2. Fidelity: Gulp can send *any* byte sequence (malformed requests, duplicate headers, smuggling
   payloads, HTTP/2 edge cases).
3. Performance: the UI stays responsive with 1,000,000 history items in a project, and proxy overhead
   is below 5 ms per request at the median (see doc 06 §5).
4. Native macOS UX that follows the Human Interface Guidelines.
5. Extensibility: JS extensions in-process, any-language extensions out-of-process, plus a scripting
   console.
6. Automation: headless CLI, REST API and MCP server.

### Non-goals (for v1)

- Windows or Linux GUI. The core library builds on Linux (useful for CI and the Beacon server), but
  the app is macOS only.
- HTTP/3 (QUIC) interception. Browsers fall back to HTTP/2 when QUIC is blocked, and the Gulp
  Browser launches with `--disable-quic`.
- A team server or multi-user collaboration. This is a settled non-goal (doc 07 decision #6):
  Gulp is single-user, and sharing happens by exchanging `*.gulp` project files and reports.
- Mobile app binary analysis (Gulp proxies mobile traffic but doesn't decompile apps).
- Mac App Store distribution. The App Sandbox conflicts with launching browsers, changing system
  proxy settings and loading extensions, so Gulp ships signed and notarized outside the store.

## 4. Naming map (reference suite → Gulp)

Gulp uses its own names. The mapping helps you read the specs if you know the reference tool. Never
put the reference tool's product names in Gulp's UI.

| Reference concept | Gulp name | Spec |
|---|---|---|
| Proxy (Intercept, HTTP history, WebSockets history, Match and replace) | **Proxy** (same sub-tabs) | F01, F05 |
| Target (Site map, Scope) | **Target** | F04 |
| Repeater | **Repeater** | F06 |
| Intruder | **Fuzzer** | F07 |
| Scanner, BChecks | **Scanner**, **Check Recipes** (YAML) | F08 |
| Crawler | **Crawler** | F09 |
| Collaborator | **Beacon** (interactsh compatibility in v1; the self-hostable OAST server is post-1.0) | F10 |
| Sequencer | **Sequencer** (post-1.0, out of v1 since 2026-11-08) | F11 |
| Decoder, Hackvertor-style tags | **Decoder**, **Transform Tags** | F12 |
| Comparer | **Comparer** | F13 |
| Organizer | **Notebook** | F14 |
| Session handling rules, Macros, Cookie jar | **Sessions** (Rules, Macros, Cookie Jar, Identities) | F15 |
| Embedded browser, DOM Invader, Clickbandit | **Gulp Browser**, **DOM Probe** (the **Frame Kit** clickjacking recorder was cut on 2026-11-08) | F16 |
| Engagement tools | Folded into the tools they extend (2026-11-08): content discovery in the **Fuzzer**, **CSRF PoC** in Reports, **Copy as** in the Send-to menu, the task **scheduler** in Automation | F07, F19, F21, doc 05 (was F17) |
| Extensions, Montoya API, BApp Store | **Extensions**, **Gulp Extension API**, **Extension Gallery** (post-1.0) | F18 |
| Bambdas (Java filter snippets) | **GulpQL** (query language) + **Snippets** (JS) | F05, F18 |
| Logger | **Logger** | F05 |
| Reports | **Reports** | F19 |
| Project files, settings | **Projects** (`*.gulp`), **Settings** | F20 |
| REST API, headless | **gulp CLI**, **REST API**, **MCP server** | F21 |
| AI features | **Gulp Assistant** | F22 |
| (BApps: Autorize, JWT Editor, Param Miner, HTTP Request Smuggler, InQL, Turbo Intruder, Logger++) | **Authz Matrix**, **JWT Workbench**, **Param Discovery**, **Smuggling Probe**, **GraphQL Workbench**, **Fuzzer Turbo mode**, **Logger** (built in) | F23, F12, F07, F05 |

## 5. Product principles

1. **Never lose data.** Everything that goes through the proxy or any tool is persisted to the
   project immediately (write-ahead, crash-safe).
2. **Raw first, pretty second.** The raw bytes are canonical. Pretty, Hex, Inspector and Render are
   views of them.
3. **Every message can be sent anywhere.** Any request, in any table or editor, has the same context
   menu: Send to Repeater / Fuzzer / Comparer / Decoder / Scanner / Notebook, Copy as
   cURL, and so on.
4. **Keyboard first.** Every action has a shortcut or a command-palette entry (⌘K).
5. **Safe by default.** Scope enforcement, no automatic sending of traffic to third parties (AI and
   public OAST are opt-in), and the CA key is protected.
6. **Explain, don't just flag.** Every scanner issue includes evidence with highlighted byte ranges,
   reproduction steps and remediation guidance.

## 6. Ethics and safety features (required)

- First-launch dialog: "Only test systems you are authorized to test." The user must acknowledge it
  once; store the acknowledgment in user settings.
- **ScopeGuard**: active tools refuse out-of-scope targets unless the user confirms in a per-action
  dialog. Proxy pass-through of out-of-scope traffic is allowed (that's browsing), but nothing is
  *generated* against out-of-scope hosts automatically.
- Rate limiting and resource pools are available for every automated tool, with conservative defaults.
- The AI assistant and public OAST servers are off by default and show a data-egress notice when
  enabled.
