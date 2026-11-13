# 09 — Gulp vs Burp Suite (2026-11-13)

A feature-by-feature comparison of Gulp against the current Burp Suite (Community and Professional,
2025-era), and where Gulp already wins, is at parity, or still has a gap — and the plan to
*outperform*, not just match. The comparison is deliberately honest: Burp is a mature product with a
large extension ecosystem, and this document calls out where Gulp is behind so the gaps are closed on
purpose rather than overlooked.

Legend: ✅ parity or better · 🟡 partial · ⬜ gap/not built · ⭐ Gulp advantage.

## 1. Core proxy & HTTP

| Capability | Burp | Gulp | Notes |
|---|---|---|---|
| Intercepting proxy (HTTP/1.1, HTTP/2) | ✅ | ✅ | Gulp proxies h2 both ways with ALPN mirroring. |
| TLS interception / per-host CA | ✅ | ✅ | Gulp mints leaves with SNI; CA key in Keychain. |
| WebSockets intercept/repeat | ✅ | ✅ | |
| HTTP/2-exclusive edits (raw h2) | ✅ | ✅ | |
| **Byte-exact requests (no normalization)** | 🟡 | ⭐ | Burp's engine re-normalizes some requests; Gulp *never* round-trips through a parser — "raw bytes are the truth" is an enforced invariant (0 `URLSession` in engines). This matters for smuggling/desync work. |
| Upstream proxies, SOCKS, match & replace | ✅ | ✅ | |
| HTTP/3 (QUIC) client | 🟡 | ⬜ | Burp has experimental HTTP/3; Gulp has it as post-1.0 (HTTP-037). **Gap.** |

## 2. Repeater / Intruder-class fuzzing

| Capability | Burp | Gulp | Notes |
|---|---|---|---|
| Repeater, tabs, history | ✅ | ✅ | |
| Intruder (sniper/battering-ram/pitchfork/cluster-bomb) | ✅ | ✅ | Gulp's Fuzzer has the four attack types + payload processing. |
| **Intruder rate-limited in Community** | — | ⭐ | Burp throttles Intruder hard in Community; Gulp has no artificial throttle — the shared limiter is a *safety* cap the user controls, not a paywall. |
| Single-packet attack (HTTP/2 race) | ✅ | ✅ | Gulp does single-packet group send (HTTP-030…034). |
| Grep-match / extract / reflection analysis | ✅ | ✅ | |
| **Protobuf/gRPC field fuzzing** | 🟡 | ⭐ | Burp needs an extension; Gulp fuzzes protobuf fields natively (re-encodes envelope + length). |

## 3. Scanner (active + passive)

| Capability | Burp Pro | Gulp | Notes |
|---|---|---|---|
| Passive checks | ✅ | ✅ | ~33 passive checks. |
| Active checks (XSS/SQLi/cmdi/SSTI/XXE/SSRF/traversal/redirect/CRLF) | ✅ | ✅ | All P0 families, with dose-response timing and OAST. |
| OAST (Collaborator / interactsh) | ✅ | ✅ | Gulp speaks interactsh and ships a self-hostable Beacon. ⭐ self-hostable + interactsh-compatible. |
| Crawl-and-audit | ✅ | ✅ | Static crawl → audit distinct requests. |
| Scan imported OpenAPI | ✅ | ✅ | One request per operation. |
| Re-test an issue / verdict history | ✅ | 🟡 | Gulp re-tests (still-present/fixed); no stored verdict history yet. |
| Confidence/severity, dedup, SARIF export | ✅ | ✅ | ⭐ SARIF out of the box (Burp needs an extension). |
| **Scanner methodology is open & testable** | ⬜ | ⭐ | Burp's checks are closed; Gulp's are documented (F08 §3.4) and proven against VulnLab with safe twins in CI — a reproducible precision/recall claim per check. |
| P1 check catalog (prototype pollution, mass assignment, NoSQL/LDAP/XPath, upload, JWT, CORS, host-header) | ✅ | ✅ | Prototype pollution (SCN-070), mass assignment (SCN-072), NoSQL/`$where`, XPath (via `string-length()`, so it is distinguished from SQLi on real targets), LDAP (wildcard), **unrestricted file upload (SCN-073)**, JWT (alg:none/weak-secret), CORS and host-header injection are all **built and tested against VulnLab safe twins** (2026-11-13). Only CSPT (SCN-071) is deferred (browser-gated). |

## 4. Access control, sessions, auth

| Capability | Burp Pro | Gulp | Notes |
|---|---|---|---|
| Session handling rules + macros | ✅ | ✅ | |
| Cookie jar, identities | ✅ | ✅ | |
| **Authorization matrix / Autorize-style** | 🟡 (extension) | ⭐ | Autorize is a third-party extension in Burp; Gulp has the Authz Matrix built in (replay-as-identity, verdicts, auto-issues). |
| **Request signing: DPoP, HTTP Message Signatures, AWS SigV4** | 🟡 (extensions) | ⭐ | Burp needs separate extensions (and SigV4 is Pro-only via an add-on); Gulp has all three as first-class session actions that run last and sign the sent bytes, verified against independent implementations. |
| Recorded browser login / passkeys | ✅ | ⬜ | **Gap** — needs the CDP browser (M13a, macOS). |
| Client certs / platform auth per identity | ✅ | 🟡 | mTLS supported at the engine; per-identity selection is a carry-over. |

## 5. Decoders, encoders, utilities

| Capability | Burp | Gulp | Notes |
|---|---|---|---|
| Decoder / smart decode | ✅ | ✅ | |
| Inspector / transform tags | ✅ | ✅ | Gulp's Transform Tags are inline, reversible, previewable. |
| Comparer (word/byte diff) | ✅ | ✅ | |
| **JWT workbench (alg:none, RS→HS, kid, weak secret, jku/x5u)** | 🟡 (extension) | ⭐ | JWT Editor is an extension in Burp; Gulp has it built in with VulnLab coverage. |
| **gRPC / protobuf decode without a schema** | 🟡 (extension) | ⭐ | Native schema-less protobuf + reflection + `.proto` import. |
| **GraphQL introspection + schema render + authz checks** | 🟡 (extension) | ⭐ | GraphQL is an extension in Burp; Gulp has introspection, a schema model, variable insertion points and field-authz checks built in. |

## 6. Target, logging, query

| Capability | Burp | Gulp | Notes |
|---|---|---|---|
| Site map, scope, target analysis | ✅ | ✅ | |
| **Query language over history (GulpQL)** | 🟡 (Bambdas) | ⭐ | Burp added Bambdas (Java snippets); Gulp has a real query language (GulpQL) with FTS, saved filters, and push-down to SQL — usable by non-programmers and reused in intercept/M&R rules. |
| Logger / capture | ✅ | ✅ | |
| Notebook / coverage index | 🟡 | ⭐ | Gulp's Notebook + coverage index is richer than Burp's "Organizer". |
| **Sequencer (token randomness)** | ✅ | ✅⭐ | Built (2026-11-13): NIST SP 800-22 + FIPS battery with an open, reference-tested method (Burp's is a black box); CSPRNG rates Excellent, a counter Extremely poor, proven by `Scripts/sequencer-dod.sh`. The Swift-Charts UI is a macOS carry-over. |
| Import HAR/Postman/other-proxy history | ✅ | ✅ | |

## 7. Extensibility, reporting, automation

| Capability | Burp | Gulp | Notes |
|---|---|---|---|
| Extension API (in-process) | ✅ (BApp store, Java/Python) | 🟡 | Gulp's in-process JS extensions + out-of-process JSON-RPC are specced (F18) but not built (M15). **Gap vs Burp's huge ecosystem.** |
| Check Recipes / custom checks (no-code) | 🟡 (Bambdas) | ✅ | ⭐ Declarative JSON/YAML recipes (passive) join the scan — no Java, unlike Burp Bambdas/BChecks. Active recipes + editor remain. |
| Reporting (HTML/PDF/Markdown) | ✅ | ✅ | HTML + bug-bounty Markdown built (`gulp-cli report`); ⭐ SARIF too; PDF export remains. |
| **MCP server (drive the tool from an AI agent)** | ⬜ | ⭐ | Gulp exposes an MCP server (read history, send requests, audited); Burp has no first-party agent interface. |
| CLI / headless | 🟡 (Pro REST API) | ⭐ | Gulp is CLI-first (`gulp-cli`), every feature scriptable; Burp's headless is a limited REST API. |
| AI assistance | 🟡 (Burp AI, Pro) | ⬜ | Specced (F22), not built (M18). |

## 8. Where Gulp already outperforms Burp

1. **Byte-exact HTTP, enforced.** No parser normalization anywhere in the send path — the right
   foundation for request smuggling, desync and header-injection research, and a property Burp only
   partly guarantees.
2. **Built-in what Burp makes you install:** Authz Matrix (vs Autorize), JWT workbench (vs JWT
   Editor), GraphQL (vs the GraphQL extension), gRPC/protobuf (vs the protobuf extensions), request
   signing incl. SigV4/DPoP/RFC 9421 — all first-party, all tested.
3. **A real query language (GulpQL)** over history, not Java snippets, reused across the product.
4. **Open, reproducible scanner methodology** proven against a vulnerable lab with safe twins in CI —
   a precision/recall claim you can run, not a black box.
5. **Agent-native + CLI-first:** an MCP server and a complete headless CLI make Gulp automatable and
   drivable by an AI agent in ways Burp is not.
6. **Self-hostable OAST** that is also interactsh-compatible — not tied to a vendor Collaborator.
8. **Always-on vulnerable-JS-library detection** with a bundled advisory dataset (jQuery, lodash,
   Bootstrap, Moment, Handlebars, AngularJS, DOMPurify) — no network calls at scan time; Burp needs
   its Pro scanner / an extension.

7. **Not paywalled:** no Community-tier throttle on Intruder/Scanner; the limiter is a user-controlled
   safety cap.

## 9. Gaps to close to decisively beat Burp (prioritised)

| # | Gap | Milestone | Why it matters |
|---|---|---|---|
| 1 | **Secret scanner + JS recon** (find secrets/endpoints in responses & JS) | M19 (F27) | High-signal, always-on; a daily bug-bounty win. **Built next (§10).** |
| 2 | P1 active checks | M11c | **Prototype pollution, mass assignment, NoSQL/LDAP/XPath, file-upload bypass, JWT-in-scan, CORS, host-header all shipped (2026-11-13);** only CSPT (browser-gated) remains. |
| 3 | Extension ecosystem (JS API) + active Check Recipes | M15 | **Passive Check Recipes shipped (2026-11-13);** the JS extension API + active recipes remain. |
| 4 | Formatted reporting (HTML/PDF, bug-bounty Markdown) | M16 | **HTML + Markdown shipped (2026-11-13); PDF + UI remain.** |
| 5 | Recorded browser login + DOM/DOM-XSS probe | M13a | JS-heavy apps and client-side bugs. |
| 6 | HTTP/3 client | post-1.0 | Niche but a visible checkbox. |
| 7 | AI triage/assist | M18 | Burp AI exists; Gulp's agent surface is a stronger base. |

## 10. First outperformance increment (this session): Secret & JS recon

Gap #1 is the highest signal-per-effort and fully testable on Linux, so it is built now as a passive,
always-on capability (F27): every in-scope response (and every linked JavaScript file) is scanned for
high-entropy secrets and credentials with a curated ruleset (AWS keys, Google API keys, GitHub/GitLab
tokens, Slack tokens, JWTs, private keys, Stripe keys, generic high-entropy assignments), and for
JavaScript endpoints/paths (fetch/axios/XHR URLs, template literals) that expand the attack surface.
Findings become issues (`recon.secret`, `recon.endpoint`). This is something Burp only does via
extensions (and with weaker entropy handling). See the M-recon DoD and `GulpScanner/Recon*`.
