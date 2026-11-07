# F10 — Beacon (OAST / out-of-band application security testing)

> Milestone: M11 · Modules: `GulpOAST`, `Beacon/` (separate package), `GulpFeatures/Beacon` ·
> Depends on: F02, F03

## 1. Purpose

Many serious vulnerabilities are **blind**: the payload works, but the response doesn't show it
(e.g. a server fetches an attacker URL, or a shell command runs, with no visible output). **OAST**
detects these by giving each payload a unique hostname/URL on a server the tester controls. When the
target interacts with it (DNS lookup, HTTP request, SMTP), that interaction is recorded and
correlated back to the payload. Gulp calls this server **Beacon**.

> **Concept.** If `http://<token>.beacon.example.com/` is injected into a vulnerable SSRF parameter,
> the target server resolves and fetches it. Beacon sees a DNS query and an HTTP request for
> `<token>`, so even with no response change, Gulp knows the injection worked and can tie it to the
> exact request and insertion point.

## 2. Requirements

### 2.1 Client (in Gulp)

| ID | Pri | Requirement |
|---|---|---|
| BCN-001 | P0 | Generate correlation payloads: a unique token per request (random, collision-resistant) plus the Beacon domain, yielding a hostname `<token>.<beacon-domain>` and URLs (http/https) and an email local-part. Used by Scanner (SCN-033), Fuzzer (FUZ-025), Repeater tags (`«beacon()»`, F12), and extensions. |
| BCN-002 | P0 | Poll (or stream) the configured Beacon server for interactions; match them to tokens; store in `oast_payloads`/`oast_interactions` with the protocol, remote address, timestamp and raw data. Emit `oastInteraction`. |
| BCN-003 | P0 | A Beacon feed UI (tool + Dashboard panel): interactions with protocol, time, source IP, the correlated tool/exchange/insertion point, and the raw request/DNS data. Click to jump to the originating exchange/issue. |
| BCN-004 | P0 | Configuration: Beacon server URL + auth secret (in the Keychain), polling interval, and a "generate a self-hosted Beacon" helper that outputs deploy instructions/secret. **OAST is off by default (doc 07 decision #4)**: a fresh install preconfigures no Beacon URL and no public server, and OAST stays inactive until the user either configures their own Beacon or opts in to a public interactsh server (BCN-005). |
| BCN-005 | P0 | **interactsh compatibility**: support the open interactsh client protocol so users can use public or self-hosted interactsh servers with no Gulp server deployment (RSA keypair registration, AES-GCM-encrypted poll payloads, correlation-id scheme). Clearly label public servers as third-party egress (opt-in). |
| BCN-006 | P1 | Health indicator in the status bar (Beacon reachable / last interaction / token count); a "test Beacon" button that injects a token into a Gulp-initiated request to itself to verify the whole loop. |
| BCN-007 | P1 | Per-interaction "promote to issue" if it isn't already tied to one; and manual token generation for use in Repeater. |
| BCN-008 | P2 | Capture the full HTTP request/body and DNS query type; support wildcard subdomains for data exfil encoding (`<data>.<token>.<domain>`). |

### 2.2 Server (`gulp-beacon`, Linux/Docker)

| ID | Pri | Requirement |
|---|---|---|
| BCN-020 | P0 | A deployable server that owns a domain/subdomain (the user sets NS records to point the subdomain at it). Listens for **DNS** (authoritative for the zone) and **HTTP/HTTPS** interactions; optionally **SMTP**. Records each with the full details and the queried hostname (to extract the token). |
| BCN-021 | P0 | A polling API for the client (authenticated with the shared secret) returning new interactions since a cursor; data encrypted in transit (TLS) and, in interactsh-compat mode, with the client's key. |
| BCN-022 | P0 | Automatic TLS for the HTTP listener (ACME/Let's Encrypt or user-provided cert) so https payloads work. |
| BCN-023 | P1 | Retention/cleanup (interactions expire after N days), rate limiting, and abuse protection (it's internet-facing). Bind and log safely; no interaction data leaves the box except to authenticated pollers. |
| BCN-024 | P1 | Dev mode (`make beacon`, which runs `gulp-beacon --dev`): runs locally on high ports with a self-signed cert and an in-memory store, used by integration tests. VulnLab's SSRF/cmd/XXE endpoints point at it. |
| BCN-025 | P2 | A Docker image and a one-command deploy script; a minimal admin page (behind auth) showing recent interactions. |

## 3. UI

Beacon tool: config section (server, secret, polling, interactsh toggle, health/test) and the
interactions table with a detail pane. The Dashboard shows a compact live feed. The status bar shows
Beacon health.

## 4. Implementation notes

- Tokens: 20+ bytes of randomness, base32/hex, lowercased to be DNS-safe; keep a map token→context
  (tool, exchange id, insertion point, issue id) in `oast_payloads`.
- Client polling: a single background task per project polls at the configured interval and
  dispatches matches; in interactsh mode, implement the register/poll/deregister flow and AES-GCM
  decryption exactly to interoperate.
- **Token-model reconciliation (native Beacon vs interactsh).** BCN-001's per-request fully-unique
  `<token>.<domain>` is the *native* Beacon scheme. interactsh instead uses a fixed per-session
  **correlation-id prefix** plus a random per-payload suffix, i.e. `<random><correlationId>.<domain>`,
  and its poll API returns interactions keyed by that correlation-id. So the two modes share one
  interface but build/parse hostnames differently: in interactsh mode, generate payloads as
  `<unique-suffix><correlation-id>.<domain>`, store the suffix→(tool, exchange, insertion point) map
  locally, and on poll match the returned interaction's full subdomain back to the request by its
  suffix. Keep this mapping in `oast_payloads.correlation_id` so correlation works identically for
  the UI regardless of mode. Getting this wrong silently mis-attributes or drops interactsh hits.
- **Privileged ports**: the DNS listener must bind UDP/TCP **53** and HTTPS **443**, both privileged
  (<1024). Don't run the whole server as root: grant the binary `CAP_NET_BIND_SERVICE`
  (`setcap`, or systemd `AmbientCapabilities=`), or start as root and drop privileges after binding,
  or map the ports with the Docker image (BCN-025). The deploy docs and Dockerfile must cover this,
  since "DNS interactions never arrive" is the most likely misconfiguration.
- The Beacon server uses Hummingbird for HTTP and a small DNS server (a Swift DNS library or a
  hand-rolled UDP/TCP responder) that answers A/AAAA/CNAME/TXT for the zone and logs the queried
  name and source. Keep the server dependency set small so it builds and runs on a cheap VPS.
- Grace period: the Scanner must wait a configurable window after sending OAST payloads before
  declaring a scan complete, because interactions arrive asynchronously.

## 5. Edge cases

- Caching DNS resolvers collapse repeated lookups → still enough to confirm; dedup by token+protocol
  within a window.
- Targets with no outbound DNS/HTTP → OAST simply yields nothing (not a failure).
- Public interactsh servers may be blocklisted by targets or rate-limited → document and prefer
  self-hosted Beacon for serious work.
- Clock skew between client and server → correlate by token, not by time.

## 6. Acceptance tests

1. Dev Beacon running; a Gulp request containing a token to VulnLab `/fetch?url=http://<token>...`
   produces an HTTP interaction correlated to that exchange within the grace period.
2. The command-injection check's OAST payload yields a DNS interaction tied to the right insertion
   point and raises the issue.
3. interactsh-compat mode against a local interactsh server records an interaction (register/poll/
   decrypt loop verified).
4. "Test Beacon" confirms the full loop and updates the health indicator.
