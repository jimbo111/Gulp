# 12 — Fresh per-feature comparison vs. current Burp Suite (run 2026-11-13)

> **Snapshot, not current status.** `docs/PROGRESS.md` is authoritative for what is built; it
> reflects the code as of 2026-11-13 (519 tests and 37 DoD scripts then).

This is a **fresh** per-feature compare/contrast done this turn against the **current** Burp Suite
feature set (Professional / DAST, releases 2025.2 → 2026.3 and the Burp AI line), not a refresh of the
earlier `09-burpsuite-comparison.md`. Burp facts below are from PortSwigger's 2025 release notes, the
"year of innovation" blog, and the 2026 feature write-ups retrieved this turn (sources at the end).
Gulp facts are grounded in the feature specs (`docs/features/F01–F33`), the engines, and the tests
that ran green this turn (519 unit tests; 36/37 DoD acceptance scripts — see `11-review-run.md`).

Verdict legend: **=** parity · **▲** Gulp ahead · **▼** Gulp behind · **↔** different trade-off.

## A. Core interception & protocols

| Capability | Burp (current) | Gulp | V |
|---|---|---|---|
| Intercepting proxy, HTTP/1+2, WebSocket | Full HTTP/1, HTTP/2, WebSocket; match-and-replace on WS messages | Full HTTP/1, HTTP/2 (incl. raw h2, h2c, trailers), WebSocket interception + repeater + fuzzer; match-and-replace on HTTP and WS | **=** |
| Raw-bytes fidelity | Repeater can desync-test; but many flows normalize via its HTTP model | **Hard rule: raw bytes are the truth** — never round-trips user-edited requests through a normalizing parser (`GulpHTTP`); single-packet/pipelining/desync are first-class | **▲** |
| TLS interception / CA | Per-host certs, CA export | Keychain-backed CA, SNI leaf minting, ALPN mirroring | **=** |
| HTTP/2 exotic request smuggling | Strong (request smuggler, HTTP/2 downgrade) | Smuggling probe **with self-poisoning confirmation** (ADV-032) that constructs and warns but never auto-sends | **=** |

## B. Repeater / manual tooling

| Capability | Burp (current) | Gulp | V |
|---|---|---|---|
| Repeater tabs, history | Mature; tab groups; **custom actions** (2025.3.2) powered by Bambdas to extract/analyze/auto-modify messages | Repeater service with persistence, WS repeater, paste-as-cURL/fetch/raw, Copy-as, group single-packet send | **↔** |
| AI payload exploration | **Shadow Repeater** — AI-generated payload variants probe new code paths | Gulp's Fuzzer + `beacon()`/transform tags give deterministic variant generation; AI-assisted variants are an assistant feature, not yet an auto-"shadow" loop | **▼** |
| Inline transforms / decoding | Inspector + Bambda custom actions | **Transform Tags** (DEC-020..023) evaluated inline with live preview; Smart Decode; full transform registry | **▲** |
| Comparer / diff | Word/byte comparer | Myers word/byte diff **with pre-diff transforms** (CMP-001..006) | **▲** |

## C. Scanner (DAST)

| Capability | Burp (current) | Gulp | V |
|---|---|---|---|
| Crawl + audit | Audit now runs **in parallel** with crawl (2025.3.2); large built-in check catalog | Crawl-and-audit pipeline; passive + active catalogs incl. P0/P1; OpenAPI + protobuf insertion points; `ScopeGuard` before every active send | **=** |
| Custom no-code checks | **BChecks** (plain-text) + **Montoya custom scan checks** (Java, 2025.9) | **Check Recipes** (JSON, SCN-060/061/064): path/content gates, header/body/status/regex matchers, OR groups, templated issue; always-on and tested | **=** |
| OAST / collaborator | Burp Collaborator (hosted) | `GulpOAST` interactsh client + **self-hostable Beacon** server; `beacon()` tag; OAST-over-WebSocket | **↔** (self-host ▲, hosted maturity ▼) |
| Evidence / dedup / SARIF | Issue definitions, dedup, export | Issue dedup upsert, evidence markers, status overrides, **SARIF + JSON export**, HTML + Markdown reports | **=** |
| False-positive discipline | Confidence tiers | Differential `/safe/`-twin oracle on every VulnLab fixture — **this turn's executed review caught and fixed a real recon false-positive the doc review missed** | **▲** |

## D. Specialized workbenches (Gulp's parity-plus surface)

| Area | Burp (current) | Gulp | V |
|---|---|---|---|
| WebSocket security | Proxy + match/replace; manual | **WebSocket Workbench (F26)**: CSWSH check, per-message authz probe (WSX-004), WS fuzzer over a live socket (WSX-002), sub-protocol decode (socket.io/graphql-ws/SignalR/STOMP), **scripted WS sequences** (WSX-008), OAST-over-WS | **▲** |
| JWT / auth | Via extensions (e.g. JWT Editor) | Built-in **JWT Workbench** (ADV-010..013); **request signing** DPoP / RFC 9421 / SigV4 (M12a); **Authz Matrix** (ADV-001..006) with safe twin | **▲** |
| Sequencer | Token randomness (classic) | Sequencer with NIST-style battery, per-position Shannon entropy, verdicts | **=** |
| gRPC / protobuf | Via Blazing/▲ extensions | First-class protobuf wire codec, `.proto` parser, gRPC/gRPC-Web/Connect framing, Repeater calls, Fuzzer protobuf positions (F33) | **▲** |
| JS recon | Via extensions | **JS Recon Studio (F27)**: source-map reconstruction, param mining, secret/endpoint recon, **asset diff across deploys** (JSR-009) | **▲** |
| SSRF/param discovery | Param miner (extension) | Built-in param discovery (ADV-020), server-side param pollution classifier (ADV-022) | **=** |

## E. Extensibility, automation, AI

| Capability | Burp (current) | Gulp | V |
|---|---|---|---|
| Extension API | **Montoya API**, BApp Store (huge ecosystem) | `GulpExtensions` manifest + in-process **JavaScriptCore host** (GulpScript); recipe library | **▼** (ecosystem/network effect) |
| MCP / agent control | Community **Burp-MCP** extensions | **First-party MCP stdio server** (AUT-020..023) with audit log + scope enforcement on every tool call | **▲** |
| AI assistant | Burp AI: Repeater prompts, **AI recorded logins**, Explore Issue, Shadow Repeater | Assistant over pure engines (redaction-first); AI-explained issues; no hosted-model lock-in | **↔** |
| Headless / CI | DAST, REST API, CI integrations | `gulp-cli` covers every tool headless; 37 executable DoD scripts; SARIF for code-scanning | **=** |

## F. Honest gaps (where Gulp is behind, and why)

1. **Shipping maturity of the macOS GUI.** Engines, CLI, and tests are green on Linux; the SwiftUI
   screens + JavaScriptCore host are written and type-check against real-engine API shims but have
   **not been compiled/run on macOS** in this environment (no Mac; the private repo's CI minutes are
   exhausted, so the `macos-15` job can't provision). This is the single blocker to calling the GUI
   "verified," and no code change here resolves it — it clears when CI minutes are added. (Tracked in
   `08-architecture-review.md` and `11-review-run.md`.)
2. **Extension ecosystem / network effect.** Burp's BApp Store and the installed base of Montoya
   extensions are a moat no single release closes. Gulp's answer is first-party breadth (the
   workbenches in §D) plus a scriptable JS host, not ecosystem parity.
3. **Shadow-Repeater-style autonomous AI variant loops.** Gulp has the deterministic fuzzer and an
   assistant, but not yet an auto-"watch what you do in Repeater and mutate" loop.

## G. Where Gulp genuinely outperforms (net)

- **Raw-byte fidelity as a hard architectural rule**, not a mode.
- **Built-in, tested workbenches** for WebSocket, JWT/auth-signing/authz-matrix, gRPC/protobuf, and
  JS-recon-with-deploy-diff that Burp leaves to extensions.
- **First-party MCP server** with scope enforcement and an audit log on every agent action.
- **A differential `/safe/`-twin test oracle** behind every scanner fixture — demonstrated this turn
  by catching and fixing a real recon false-positive that the document-only review had not.
- **Everything headless + executable DoDs**: 519 unit tests and 37 end-to-end acceptance scripts,
  36/37 green in this throttled sandbox (the 37th is only slow here, not broken).

## Sources (retrieved 2026-11-13)

- PortSwigger release notes 2025.2 / 2025.3.2 / 2025.4.2 / 2025.6.4 / 2025.7 / 2025.9.1
  (https://portswigger.net/burp/releases/professional-community-2025-2 and siblings)
- "What's new in Burp Suite Professional: a year of innovation"
  (https://portswigger.net/blog/whats-new-in-burp-suite-professional-a-year-of-innovation)
- Burp Suite 2026 feature write-ups (codeant.ai/blogs/burp-suite-features; appsecsanta.com/burp-suite)
- Wikipedia "Burp Suite" (version/date cross-check) (https://en.wikipedia.org/wiki/Burp_Suite)
