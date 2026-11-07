# F28 — Web Cache Poisoning & Deception Scanner

> Milestone: M24 · Modules: `GulpFeatures/CacheProbe` + helpers in `GulpScanner`/`GulpHTTP` ·
> Depends on: F03, F05, F08, F10, F23 (header wordlists)

## 1. Purpose

F23's Smuggling Probe covers request desync; caching is a separate top-tier bug class it doesn't
touch. This tool identifies caching behavior and cache keys, discovers **unkeyed inputs** (headers
like `X-Forwarded-Host`/`X-Forwarded-Scheme`, duplicate params, `Accept` quirks) whose reflected
effect is cached and served to other users (**cache poisoning**), and tests **cache deception**
(path-confusion such as `/account/foo.css` being cached while returning private content). It is
**victim-safe by default**: it probes with per-run unique keys so it never serves a poisoned
response to a real user, mirroring the OAST safety posture.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| WCP-001 | P0 | Detect cacheability and infer cache status/age from `Age`, `X-Cache`, `CF-Cache-Status`, `Cache-Control`, `Vary`, ETag and response-time deltas, per URL. |
| WCP-002 | P0 | Probe candidate **unkeyed inputs** (a maintained header/param list) by injecting a unique canary, then issue a clean follow-up request to confirm the canary was cached and served *without* the input — proving a poisoning vector — using per-run unique keys so no real user is served a poisoned page. |
| WCP-003 | P0 | Test **cache deception** via path/extension confusion (`/profile`, `/profile.css`, `/profile/..%2f`, encoded suffixes) and report when authenticated/private content becomes publicly cacheable. |
| WCP-004 | P0 | Raise issues (F08) with the exact poisoning request, the confirming cached response, the inferred cache key, and blast-radius notes; all sends scope-gated and Governor-limited (F29). |
| WCP-005 | P1 | Integrate with OAST (F10) for header-based SSRF/interaction that is cache-amplified; reuse the header wordlist from Param Discovery (F23). |
| WCP-006 | P1 | Detect cache-key normalization quirks (case, port, trailing dot, duplicate headers) that enable keyed-but-equivalent poisoning. |
| WCP-007 | P1 | Ship as an opt-in active check family in the Scanner (F08) and as Check-Recipe primitives (cacheability matchers). |
| WCP-008 | P2 | A guided multi-request confirmation workbench (poison → observe → auto-expire) with strong warnings; never auto-run on shared production caches without explicit confirmation. |

## 3. UI

A Cache tool: a target list with cacheability/age/key inference; an unkeyed-input probe runner with
a canary/confirm result per input; a deception tester (path/extension variants); and findings feeding
Issues. Strong, explicit warnings on the confirmation workbench.

## 4. Implementation notes

- Cacheability inference reads the response headers plus timing (a cached hit is typically much
  faster and carries `Age`/cache-status headers).
- The victim-safe confirmation is the crux: always probe with a **unique** key per run so the cached
  entry you create can only be observed by your own confirming request; never poison a key a real
  user would hit. Document this prominently.
- Reuse the F23 header/param wordlists; reuse the diff machinery (F13) to detect reflected effects.
- OAST (F10) catches blind/SSRF-style amplified interactions.

## 5. Edge cases

- Short cache TTLs — the confirm request must race the TTL; retry with timing awareness.
- CDNs that key on cookies/`Vary` — factor `Vary` into the cache-key model.
- Shared/production caches — the default mode never poisons a real key; the exploitation workbench
  (WCP-008) requires explicit confirmation and warns about blast radius.
- Don't confuse mere reflection with a *cached* reflection — the clean follow-up is what proves it.

## 6. Acceptance tests

1. VulnLab reflects `X-Forwarded-Host` into a cached response; the tool confirms poisoning via a
   clean follow-up and reports the key; the non-caching twin is clean.
2. A `/account` endpoint cached as `/account.css` leaks private content and is flagged as cache
   deception; the hardened twin returns `Cache-Control: private` and is clean.
3. A header-based SSRF reflected into cache produces an OAST interaction correlated to the probe.
4. Run as the opt-in scanner family, it finds these with no false positives on safe twins.
