# F16 — Gulp Browser, DOM Probe, Frame Kit

> Milestone: M13 · Modules: `GulpBrowser` (macOS only), `GulpFeatures/Browser` · Depends on: F01, F02

## 1. Purpose

A pre-configured browser that routes through Gulp's proxy with the CA already trusted, so testers
start capturing traffic in one click without touching system settings. **DOM Probe** is an in-page
assistant that finds client-side (DOM-based) vulnerabilities. **Frame Kit** records a clickjacking
proof-of-concept.

## 2. Requirements

### 2.1 Gulp Browser

| ID | Pri | Requirement |
|---|---|---|
| BRW-001 | P0 | Discover an installed Chromium-family browser (Chrome, Chromium, Edge, Brave) or offer to download **Chrome for Testing** into the app support dir. Launch it as a child process with an isolated user-data-dir (a dedicated profile), pointed at a chosen Gulp listener. |
| BRW-002 | P0 | Trust the Gulp CA for that browser without modifying the system store: launch with `--ignore-certificate-errors-spki-list=<Gulp CA SPKI sha256 base64>` (and `--proxy-server=127.0.0.1:<port>`, `--proxy-bypass-list=<none>`). Fall back to a profile-local NSS store import if the flag is unavailable. |
| BRW-003 | P0 | Launch flags for a clean test session: new isolated profile, `--disable-quic` (so HTTP/3 falls back to interceptable H2), `--no-first-run`, `--no-default-browser-check`, disable background networking/components/translate/update pings so history isn't polluted. |
| BRW-004 | P0 | One-click "Open Browser" (⌘⇧O) from the toolbar and empty states; multiple browser windows allowed; closing Gulp cleans up launched browsers. |
| BRW-005 | P0 | Connect over the **Chrome DevTools Protocol** (a WebSocket to `--remote-debugging-port` on a random port) for automation used by the Crawler (F09), login recording (F15), DOM Probe and Frame Kit. *(P0 because the P0 DOM Probe (BRW-010/011) and browser-backed crawl depend on it.)* |
| BRW-006 | P1 | Keep the test profile between runs (optional) so logins persist, or always-fresh (default). Manage the downloaded Chrome for Testing version and updates. |
| BRW-007 | P2 | A built-in `WKWebView`-based lightweight browser as a fallback when no Chromium is available (limited: no CDP automation, trusts the CA via a per-view policy). Clearly labeled as limited. |

### 2.2 DOM Probe (client-side vuln finder)

| ID | Pri | Requirement |
|---|---|---|
| BRW-010 | P0 | Inject an instrumentation script into pages (via CDP `Page.addScriptToEvaluateOnNewDocument`) that hooks DOM **sources** (e.g. `location`, `document.referrer`, `postMessage`, `localStorage`, URL params) and **sinks** (`innerHTML`, `document.write`, `eval`, `setAttribute`, `location` assignment, jQuery sinks) and reports when tainted source data reaches a sink. |
| BRW-011 | P0 | A canary/taint technique: feed a unique marker through sources (hash, query, name, referrer, postMessage) and detect it arriving in a dangerous sink; report the source→sink flow with the value and stack where available. Raise a DOM-XSS issue (F08) with evidence. |
| BRW-012 | P1 | **postMessage** monitor: log cross-origin messages and flag handlers that use message data in sinks without origin checks. |
| BRW-013 | P1 | A controls overlay in the page (toggle, inject a test payload into the current source, show findings) and a panel in Gulp listing flows; "send URL to Repeater/Scanner". |
| BRW-014 | P1 | Prototype-pollution probe: detect gadgets by injecting `__proto__` params and observing polluted properties / known sink behavior. |
| BRW-015 | P2 | DOM-clobbering and WebSocket/URL-fragment-routing (SPA) source tracking. |

### 2.3 Frame Kit (clickjacking PoC)

| ID | Pri | Requirement |
|---|---|---|
| BRW-020 | P1 | Given a target URL, check framing protections (X-Frame-Options, CSP frame-ancestors) and, if frameable, record a click sequence on the framed page to build a clickjacking PoC (an HTML file that overlays the target in an iframe with a decoy). |
| BRW-021 | P1 | Export the PoC HTML and a short explanation; link it to a clickjacking issue (F08). |
| BRW-022 | P2 | Overlay-opacity controls and a recorded-clicks replay to demonstrate the attack. |

## 3. UI

- Toolbar "Open Browser" and a Browser panel: launched-browser status, profile mode, CA-trust
  status, and buttons for DOM Probe (on/off per browser) and Frame Kit. DOM Probe findings and
  postMessage logs appear in a panel and feed Issues. Frame Kit has a target field, a framing-check
  result, a record button and an export.

## 4. Implementation notes

- Compute the CA SPKI pin: sha256 of the CA's `SubjectPublicKeyInfo`, base64 — exactly the value
  Chrome expects for `--ignore-certificate-errors-spki-list`. This trusts *only* the Gulp CA for
  that profile, not all certs, which is safer than `--ignore-certificate-errors`.
- Process management: launch with a captured stdout/stderr, a known remote-debugging port, and the
  isolated profile; detect exit; never leave orphans (track PIDs, terminate on project/app close).
- CDP client: a small WebSocket JSON client (through Gulp's own stack, direct to localhost); manage
  targets/sessions; used by Crawler and here. Keep it in `GulpBrowser`.
- DOM Probe script is a self-contained JS bundle shipped in resources; it posts findings to a
  CDP binding (`Runtime.addBinding`) that `GulpBrowser` receives.
- This module is macOS-only (`#if os(macOS)`), but the issue it raises uses the shared F08 model.

## 5. Edge cases

- No Chromium installed and download declined → offer the WKWebView fallback (no automation) and
  explain the limits.
- Sites that detect automation/headful CDP → document; the browser is headful by default for manual
  use, headless only for crawling.
- CSP blocking injected overlays (DOM Probe/Frame Kit) → report that protection as the finding
  (it's doing its job) rather than failing silently.
- QUIC/HTTP3 forced by a site → `--disable-quic` makes it fall back; note any site that refuses.

## 6. Acceptance tests

1. One click launches Chromium proxied through Gulp with **no** certificate warning on
   `https://localhost:8443`; traffic appears in history; closing Gulp kills the browser.
2. DOM Probe on VulnLab `/spa` (reads `location.hash` into `innerHTML`) reports a source→sink flow
   and raises a DOM-XSS issue with the marker; `/safe/spa` reports nothing.
3. Frame Kit reports `/frameable` as frameable and `/safe/frameable` as protected; it exports a PoC
   HTML for the frameable page.
4. The Crawler (F09 browser mode) uses the same CDP client to render and discover SPA routes.
