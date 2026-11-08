# F15 — Sessions, authentication and macros

> Milestones: M12a (sessions, macros, request signing), M13a (recorded and passkey logins), M22
> (scripted WS sequences WSX-008, post-1.0) · Modules: `GulpSession`, `GulpFeatures/Sessions` ·
> Depends on: F03, F04, F16

## 1. Purpose

Automated tools (Crawler, Scanner, Fuzzer) must stay authenticated and handle anti-automation tokens
(CSRF tokens, dynamic nonces). **Session handling rules** adjust outgoing requests and react to
responses; **macros** replay sequences (like a login) to obtain fresh tokens/cookies; the **cookie
jar** holds cookies shared across tools; **identities** represent different users (for access-control
testing).

## 2. Requirements

### 2.1 Cookie jar and identities

| ID | Pri | Requirement |
|---|---|---|
| SES-001 | P0 | A per-project **cookie jar**: cookies observed from proxy/tool traffic are stored (domain, path, name, value, flags, expiry) and can be sent automatically by tools per rules. View/edit/delete entries. |
| SES-002 | P0 | **Identities**: named sets of credentials/cookies/headers/tokens representing a user (e.g. "admin", "user-A", "unauthenticated"). An identity scopes its own cookie-jar partition. Used by Authz Matrix (F23) and by scans "as a user". |
| SES-003 | P1 | Import/export the cookie jar; "set these cookies from this response" quick action; clear jar. |

### 2.2 Session handling rules

| ID | Pri | Requirement |
|---|---|---|
| SES-010 | P0 | Ordered **rules**, each with a **scope** (tools it applies to, URL/host conditions via GulpQL) and an ordered list of **actions**. Rules run as a `RequestHook` (and some as a `ResponseHook`) in the F03 pipeline. |
| SES-011 | P0 | Actions: **use cookies from the jar**; **set/add/remove a header or param**; **run a macro** (SES-020) and use its result (e.g. copy a token from the macro's response into this request); **check session validity** and, if invalid, run a macro then retry; **prompt the user** (interactive) when automation can't proceed. |
| SES-012 | P0 | **Session-validity check**: a configurable signal (status, redirect to login, body contains/absent a marker, cookie present) that determines whether the current session is still valid; drives re-authentication. |
| SES-013 | P1 | **Token/nonce following**: capture a value (CSRF token, nonce, view-state) from a prior response or a macro and substitute it into subsequent requests (by param/header name or regex), with "always fetch fresh" option. |
| SES-014 | P1 | Rule tester: run a rule against a sample request and show the transformed request and any macro traffic, for debugging. |
| SES-015 | P1 | Per-rule logging to the Logger so it's clear what the session layer did to each request (and why a retry happened). |
| SES-016 | P1 | **Request signing — DPoP** (RFC 9449) as a session action: for each request, mint a fresh DPoP proof JWT (`htm`, `htu`, `iat`, `jti`, `ath` for the access token, the server `nonce` when one is demanded via `DPoP-Nonce`) signed with the identity's key, and set the `DPoP` header; retry once on a `use_dpop_nonce` error. *(Added by the 2026-11-08 feature review, A3; M12a.)* |
| SES-017 | P1 | **Request signing — HTTP Message Signatures** (RFC 9421) as a session action: sign the configured covered components (`@method`, `@target-uri`, `@authority`, `content-digest`, chosen headers) with the identity's key/algorithm, adding `Signature-Input`/`Signature` (and `Content-Digest` when covered). *(Added by the 2026-11-08 feature review, A3; M12a.)* |
| SES-018 | P1 | **Request signing — AWS SigV4** as a session action: sign with access key/secret (+ session token), region and service, for API Gateway and other AWS-fronted APIs (`Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`). Signing actions (SES-016…018) are configured as session actions but run as the engine's **last** request hook — after Transform Tags, match & replace, extensions and the Content-Length fixer (doc 01 §5.6, F03 §4) — so the signature covers the bytes actually sent; keys live in the Keychain. *(Added by the 2026-11-08 feature review, A3; M12a.)* |

### 2.3 Macros

| ID | Pri | Requirement |
|---|---|---|
| SES-020 | P0 | A **macro** = an ordered list of requests (recorded from history or built manually) replayed in sequence to establish/refresh session state. Each step can capture values from its response (cookie, regex, Inspector pick) into variables usable by later steps and by rules. |
| SES-021 | P0 | Parameter handling per step: automatically carry forward cookies; configurable "update this param from a previous response" (e.g. CSRF token chaining); and use identity credentials via variables. |
| SES-022 | P1 | Build a macro from selected history items; edit each step's request; test-run the macro and view the resulting cookies/variables. |
| SES-023 | P1 | Macros run with the engine (scope-gated for active contexts) and are reused by Crawler/Scanner re-auth; a macro can itself be the login flow for an identity. |
| WSX-008 | P2 | Scripted WebSocket message sequences (send A, await a frame matching X, then send B) for stateful protocols, as a macro step type over one `openWebSocket` connection. *(Moved from F26, 2026-11-08; later: M22 — post-1.0.)* |

### 2.4 Login recording and client certs

| ID | Pri | Requirement |
|---|---|---|
| SES-030 | P1 | **Recorded login** via the Gulp Browser (F16): the user logs in once in the managed browser; Gulp records the navigations/requests and builds a replayable login (a macro or a browser-replay) usable by automated tools. Credentials stored in the Keychain. *(later: M13a — needs F16's CDP automation, which lands in M13a; the rest of Sessions is M12a.)* |
| SES-031 | P2 | Browser-based re-auth: when a macro replay can't reproduce a JS-heavy login, re-run the recorded browser login headlessly to refresh cookies. |
| SES-032 | P1 | **Passkey logins**: recorded logins (SES-030) and browser re-auth work for WebAuthn/passkey sign-in by using the Gulp Browser's virtual authenticator (F16 BRW-016) — the identity stores the virtual credential, so the recorded login replays without a hardware key. *(Added by the 2026-11-08 feature review, A4; M13a.)* |
| SES-040 | P1 | Upstream **client certificates** (mTLS) per host (F02 TLS-011), selectable per identity. |
| SES-041 | P2 | Platform auth (Basic/Digest/NTLM) per host/identity (F03 HTTP-012). |

## 3. UI

Sessions tool (and Settings → Sessions) sub-tabs: **Rules** (ordered list + editor with
scope/actions + tester), **Macros** (list + step editor + test), **Cookie jar** (table),
**Identities** (list + credentials/headers/cookies + login method). The Logger annotates requests
touched by session rules.

## 4. Implementation notes

- `SessionService` exposes `RequestHook`/`ResponseHook` implementations registered with the engine;
  rule evaluation is ordered and short-circuits per the rule's scope. Keep it fast — it runs on
  every tool request.
- Validity check + macro-retry: on a response the ResponseHook deems "session invalid", mark the
  session stale; the next request (or an immediate retry) triggers the macro, then re-sends. Guard
  against infinite re-auth loops (max attempts, backoff).
- Variables live in the per-project `VariableStore` (shared with Transform Tags, F12), partitioned
  by identity where relevant.
- Recorded login: capture the browser's requests through the proxy during a marked recording window;
  offer to turn them into a macro (strip static assets, keep the auth-relevant posts/redirects).
- Request signing (SES-016…018): one `RequestSigner` hook, registered last in the engine pipeline,
  dispatching to the configured scheme. Signing reads the final bytes, so it must re-sign on every
  send and retry (never cache a signature). DPoP: per-identity key pair (ES256 by default), a fresh
  `jti` per proof, `ath` = base64url(SHA-256(access token)), and the latest `DPoP-Nonce` remembered
  per origin. RFC 9421: build the signature base from the covered components exactly as the RFC
  orders them. SigV4: canonical request → string to sign → derived signing key; when the body is
  streamed or unknown, use `UNSIGNED-PAYLOAD` only if the user allows it. The JOSE/crypto primitives
  are the F12 `GulpCodec` ones (shared with the JWT Workbench).
- Passkeys (SES-032): the recorded login stores the identity's virtual-authenticator credential
  (F16 BRW-016) in the Keychain alongside other credentials and re-adds it to the authenticator
  before replaying.

## 5. Edge cases

- CSRF tokens that rotate every request → "always fetch fresh" + capture-then-use within the same
  logical action; document ordering.
- Re-auth storms under concurrency (many tasks hit an expired session at once) → single-flight the
  macro (one re-auth, others await it).
- Logout links triggered by the crawler → excluded by Crawler policy and/or a rule that detects and
  re-auths.
- SameSite/secure cookies and cross-subdomain scope → respect cookie attributes in the jar.

## 6. Acceptance tests

1. With a login macro and a validity check configured, a long Fuzzer run against VulnLab's
   authenticated area stays logged in; forcing session expiry (VulnLab config) triggers exactly one
   re-auth under concurrency, and requests succeed afterward.
2. A session rule following the CSRF token lets automated POSTs to `/login`-style endpoints succeed
   where they'd otherwise 403.
3. Two identities (user-A, user-B) each keep separate cookies; a request sent "as user-B" carries
   user-B's session.
4. A browser-recorded login replays to obtain a valid session cookie.
5. Request signing (SES-016…018): Repeater sends to VulnLab's `/signed/dpop`, `/signed/http-sig` and
   `/signed/sigv4` succeed with the matching session action enabled and fail (401) without it; editing
   the body in Repeater is still accepted, because signing runs after every other hook.
6. Passkeys (SES-032): a login to VulnLab `/webauthn/login` is recorded with the virtual authenticator
   and replayed to obtain a valid session.
