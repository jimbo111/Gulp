# F25 — SSO Workbench (OAuth 2.0 / OIDC / SAML flow testing)

> Milestone: M21 · Modules: `GulpFeatures/SSO` + helpers in `GulpScanner`/`GulpSession` ·
> Depends on: F03, F05, F08, F12 (JWT/codec primitives — sign/verify, base64, inflate), F15, F16,
> the JWT Workbench's attack helpers (F12 §2.3, moved from F23 on 2026-11-08), the shared limiter (F03 §3.4)

## 1. Purpose

Modern apps delegate authentication to OAuth2/OIDC/SAML, and the serious bugs live in the **flow**,
not in an isolated token. The SSO Workbench reconstructs the whole authorization dance from captured
traffic (authorize → callback → token → userinfo, or SAML AuthnRequest → IdP → assertion POST),
visualizes it, and runs flow-specific attacks. It complements the JWT Workbench (F12 §2.3, which manipulates
a single token and knows nothing about the surrounding grant) and F15 (which keeps you logged in but
doesn't attack the protocol).

> **Concept.** OAuth/OIDC bugs are usually missing or weak protections *between* messages — a
> `redirect_uri` the server over-accepts, a missing/replayable `state`, PKCE that can be downgraded,
> a SAML assertion whose signature isn't properly checked. You can only see these by modeling the
> flow end to end.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| SSO-001 | P0 | Reconstruct an OAuth2/OIDC flow from project traffic (or a selected exchange set): detect grant type (auth-code, auth-code+PKCE, implicit, client-credentials, device, hybrid) and extract `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge(_method)`, `response_type`/`response_mode`, and the token/authorize/userinfo endpoints into a structured flow model. |
| SSO-002 | P0 | Detect and parse SAML messages (AuthnRequest/Response/assertions; base64+inflate for redirect binding, raw for POST binding) and render decoded XML with the **signature scope highlighted** (what is signed vs not). |
| SSO-003 | P0 | `redirect_uri` validation tests (append/prefix/subdomain/path-traversal/`@`-confusion/open-redirect chaining, all within scope) reporting which variants the authorization server accepts; raise an issue (F08) with evidence. |
| SSO-004 | P0 | Test `state` and PKCE protections: flag missing/static/reflected-only `state`, and PKCE absent or downgradeable to `plain`; classify CSRF / authorization-code-injection exposure. |
| SSO-005 | P0 | SAML assertion attacks on demand (signature removal, XML Signature Wrapping variants, assertion / `audience` / `recipient` / `NotOnOrAfter` tampering, replay), reporting acceptance/rejection per variant. Replays are scope-gated and never auto-run. |
| SSO-006 | P1 | Detect implicit/hybrid token leakage vectors (token in URL fragment reachable via `Referer`, `window.history`, or logged redirects) and flag them. |
| SSO-007 | P1 | Fetch and inspect OIDC/OAuth metadata (`/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, JWKS) and SAML metadata, cross-checking advertised vs enforced behavior (e.g. advertised PKCE-required but not enforced). |
| SSO-008 | P1 | Identity swapping via F15 identities to test authorization-code/assertion injection across users and IdP/SP confusion. |
| SSO-009 | P1 | Emit flow-aware Check Recipes / insertion points so the Scanner (F08) can re-test these flows in an automated audit. |
| SSO-010 | P2 | Device-code and CIBA flows; OAuth-for-SPA `nonce`/DPoP observations. |

## 3. UI

An SSO tool: a **flow diagram** (authorize → callback → token → userinfo, or the SAML exchange) with
each message clickable to its exchange; a parameters panel (extracted grant fields, with validity
badges); an **attacks** panel (redirect_uri matrix, state/PKCE checks, SAML assertion mutations) with
per-variant accept/reject results; and a metadata inspector. Findings feed Issues (F08).

## 4. Implementation notes

- Flow reconstruction is a state machine over the exchange set, matched by endpoint shapes and
  parameter names; it tolerates missing steps (reconstruct what's present).
- SAML: base64-decode (+ raw-inflate for redirect binding) via F12 codecs; parse XML and compute the
  signed-node set (reference URIs) to drive the signature-scope highlight and XSW mutations.
- Token manipulation reuses the JWT sign/verify/alg-confusion ops that live in **F12/GulpCodec**
  (surfaced by the JWT Workbench, F12 §2.3); this tool adds the flow context around them.
- Browser-drive JS-heavy logins via F16 to capture the full flow when it isn't all in history.
- All active sends (SAML replays, redirect_uri probes) go through ScopeGuard and the shared limiter
  (F03 §3.4, GOV-002/003).

## 5. Edge cases

- Flows split across multiple hosts/subdomains (IdP ≠ SP) — scope must include both or the user
  confirms per-action.
- Rotating `state`/`nonce` per request — capture-then-use within one logical attempt.
- Encrypted SAML assertions / JWE — decode only when a key is supplied; otherwise report "encrypted,
  not analyzed".
- Non-standard/proprietary SSO — reconstruct best-effort and label unknown parameters.

## 6. Acceptance tests

1. Against a VulnLab OIDC app, the workbench reconstructs the auth-code flow and flags a
   `redirect_uri` that accepts a `/callback/../evil` path; the safe twin rejects all variants.
2. A planted implicit-flow app leaks the access token via `Referer` and is flagged; the code-flow
   twin is not.
3. A VulnLab SAML SP accepts a signature-stripped assertion and an XSW variant; both are reported
   with the exact mutated XML, and the hardened SP rejects them.
4. PKCE downgrade (`S256`→`plain`) is accepted by the vulnerable AS and rejected by the safe one.
