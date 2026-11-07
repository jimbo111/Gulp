# F23 — Advanced testing tools

> Milestone: M19 · Modules: `GulpFeatures/Advanced` + helpers in engines (`GulpScanner`,
> `GulpHTTP`, `GulpSession`) · Depends on: F03, F06, F07, F08, F10, F12 (codec/JWT ops), F13 (diff/similarity for Authz verdicts), F15

These are focused power-tools, each equivalent to a popular extension of the reference ecosystem.
Build them as first-class tools sharing the common engines/components.

## 1. Authz Matrix (access-control testing)

> **Concept.** Many apps enforce authorization inconsistently. The matrix replays the same requests
> as different **identities** (F15) — e.g. admin, low-priv user, unauthenticated — and compares
> responses to reveal where a low-priv user can reach high-priv functionality (IDOR/broken access
> control).

| ID | Pri | Requirement |
|---|---|---|
| ADV-001 | P0 | Pick a set of requests (from history/site map/selection) and a set of identities; replay each request as each identity (swapping its auth cookies/headers/tokens via F15), honoring scope. |
| ADV-002 | P0 | A matrix view: rows = requests, columns = identities; each cell shows status/length and an **enforcement verdict** (Enforced / **Bypassed** / Same-as-authorized / Needs review) computed by comparing each identity's response to the authorized baseline and to the unauthenticated response. |
| ADV-003 | P0 | Automatic analysis heuristics: a low-priv/unauth response that matches the privileged response (status+similar body) ⇒ likely bypass; a difference ⇒ likely enforced; configurable similarity threshold; raise access-control issues (F08) for bypasses with evidence. |
| ADV-004 | P1 | "Live" mode: as you browse as the high-priv user, each request is auto-replayed as the other identities in the background and flagged (Autorize-style). |
| ADV-005 | P1 | Handle CSRF tokens/nonces per identity (use session rules/macros) so replays are valid; exclude logout/destructive requests. |
| ADV-006 | P2 | IDOR helper: detect object-id parameters and try adjacent/other-user ids (within scope) to find missing ownership checks. |

## 2. JWT Workbench

| ID | Pri | Requirement |
|---|---|---|
| ADV-010 | P0 | Decode JWTs (header/payload/signature) from any message; edit claims; re-sign with a provided key (HS256/384/512, RS/PS, ES) and insert back into the request. |
| ADV-011 | P0 | Attack helpers: `alg:none`, algorithm confusion (RS256→HS256 using the public key as the HMAC secret), weak-HMAC-secret brute force (wordlist), `kid`/`jku`/`x5u` injection probes, expired/`nbf` manipulation. Each clearly labeled; scope-gated when sent. |
| ADV-012 | P1 | Key management: paste/import keys (PEM/JWK), generate keys, and a JWKS fetch/inspect helper. Verify signatures against a key/JWKS. |
| ADV-013 | P1 | Integrate with Repeater/Fuzzer (a JWT Transform Tag / payload processor) so manipulated tokens flow into attacks. |

## 3. Param Discovery (hidden parameters)

| ID | Pri | Requirement |
|---|---|---|
| ADV-020 | P0 | Brute-force hidden parameters (query/body/headers/cookies) using wordlists, detecting which are processed by observing response changes (length/status/reflection/behavior) against a baseline with canary values. |
| ADV-021 | P1 | Mine candidate param names from the app itself (seen params, words in JS/HTML) to augment wordlists; dedup. |
| ADV-022 | P1 | Detect server-side parameter pollution / array/dup handling quirks; report processed params as findings/observations and offer "send to Fuzzer/Scanner". |

## 4. Smuggling Probe (HTTP request smuggling / desync)

| ID | Pri | Requirement |
|---|---|---|
| ADV-030 | P0 | Detect request-smuggling vectors (CL.TE, TE.CL, TE.TE variants, and HTTP/2 downgrade desync) using safe timing-based differential probes, following a careful methodology that avoids corrupting other users' traffic by default. |
| ADV-031 | P0 | Leverage the engine's raw/low-level control (F03): craft requests with conflicting/obfuscated length framing and HTTP/2→1 downgrade shapes; measure timing/response differentials to classify the vector. |
| ADV-032 | P1 | Guided confirmation/exploitation workbench (construct a follow-up that proves desync) with strong warnings and scope gating; never run destructive confirmations automatically. |
| ADV-033 | P1 | Report findings with the exact probes and reasoning; integrate with the Scanner as an opt-in active check family. |

## 5. GraphQL Workbench

| ID | Pri | Requirement |
|---|---|---|
| ADV-040 | P0 | Detect GraphQL endpoints; run **introspection** (and detect when it's disabled); render the schema (types/queries/mutations) in a browser. |
| ADV-041 | P0 | Build/send queries with a schema-aware editor; import operations from traffic; pretty-print and variables support. |
| ADV-042 | P1 | Security checks: introspection exposed, field/suggestion leakage, batching/alias-based abuse (DoS/brute force), missing depth/complexity limits, and authz testing per field (pairs with Authz Matrix). Raise issues (F08). |
| ADV-043 | P1 | Generate insertion points from GraphQL variables/args for the Scanner; a GraphQL-aware matcher helper for Check Recipes. |

## 6. API import & schema-driven testing

| ID | Pri | Requirement |
|---|---|---|
| ADV-050 | P0 | Import **OpenAPI/Swagger** (2.0/3.x) and build requests for every operation (paths, methods, params, example/required bodies, auth), adding them to the site map and offering a scan of the whole API. |
| ADV-051 | P1 | Import **Postman** collections and **HAR**; map to requests/site map. |
| ADV-052 | P1 | Schema-aware insertion points and value generation (types/enums/formats) so scans send plausible, well-typed inputs. |
| ADV-053 | P2 | gRPC-Web / protobuf decode helpers (best-effort) for API traffic. |

## 7. Secret scanner

| ID | Pri | Requirement |
|---|---|---|
| ADV-060 | P0 | Scan responses (and JS files) for secrets (API keys, tokens, private keys, cloud credentials) via an updatable regex/entropy ruleset; raise info/low issues with the matched (redacted) evidence and location. Runs passively and on demand over the project. |
| ADV-061 | P1 | Entropy-based detection for high-entropy strings; allowlist/denylist; dedup; link to the report with redaction (F19 RPT-010). |

## 8. Implementation notes

- Each tool is a feature module reusing: identities/sessions (F15) for Authz Matrix; the codec/JWT
  ops (F12) for JWT; the Fuzzer engine (F07) for Param Discovery; the raw engine (F03) for Smuggling;
  the scanner model (F08) for all issues; the diff/similarity (F13) for Authz verdicts.
- Smuggling and other potentially disruptive probes are **safe-by-default**, scope-gated, and never
  auto-run destructive confirmations; they carry prominent warnings and require explicit action.
- OpenAPI/GraphQL importers produce normal `RawRequest`s + insertion points so the existing Scanner
  handles them — no separate scan engine.

## 9. Acceptance tests

1. Authz Matrix: replaying VulnLab `/api/orders/{id}` and `/admin` as user-A/user-B/unauth flags the
   IDOR and the admin bypass; `/safe/*` twins show "Enforced".
2. JWT Workbench: forge an `alg:none` token and an RS→HS confusion token for VulnLab's `/api/me` and
   confirm acceptance/rejection correctly; brute-force a weak HMAC secret from a wordlist.
3. Param Discovery finds a hidden parameter planted in a VulnLab endpoint via response-diff.
4. Smuggling Probe classifies VulnLab's CL.TE emulation listener (:8090) as vulnerable via timing
   differentials; a correctly-behaving endpoint is classified safe.
5. GraphQL Workbench introspects `/graphql`, renders the schema, and flags the field-level authz bug.
6. Importing `/openapi.json` creates requests for every `/api/*` operation and a scan covers them.
7. The secret scanner finds a planted API key in a VulnLab JS file and reports it redacted.
