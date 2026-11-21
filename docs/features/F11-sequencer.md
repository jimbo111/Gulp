# F11 — Sequencer

> Milestone: Post-1.0 backlog (out of v1 since the 2026-11-08 feature review; built anyway on 2026-11-13) · Modules:
> `GulpSequencer`, `GulpFeatures/Sequencer` · Depends on: F03

**Out of v1 (2026-11-08 feature review, product decision #7).** Token-randomness analysis rarely
finds bugs against modern frameworks and JWT-based sessions, and it cost a whole milestone (the
retired M14). The spec is kept intact; see the roadmap's Post-1.0 backlog.

**Status (2026-11-20).** Built on 2026-11-13, reversing the deprioritization (doc 07, 2026-11-13):
`GulpSequencer` (token capture, a NIST SP 800-22-style battery, FIPS poker, per-position χ²,
effective-entropy verdict), `gulp-cli sequencer`, `SequencerView`, and `Scripts/sequencer-dod.sh`
(VulnLab `/token/weak` rates poor, `/token/strong` excellent). Not built: Swift Charts output and
runs saved to the `sequencer_runs` table (which exists in schema v1 and is still unused).

## 1. Purpose

The Sequencer analyzes the **randomness** of security-sensitive tokens (session cookies, CSRF
tokens, password-reset tokens, API keys). Weak tokens can be predicted, letting an attacker hijack
sessions or forge requests. Gulp collects many tokens and runs statistical tests to estimate their
effective entropy.

> **Concept: entropy and why it matters.** If a session token has only, say, 20 bits of real
> randomness, an attacker can guess valid tokens in ~1 million tries. Good tokens have 100+ bits of
> unpredictable randomness. The tests here (borrowed from NIST-style randomness testing, e.g.
> FIPS 140-2 / SP 800-22 families) estimate how much of each bit is actually unpredictable.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| SEQ-001 | P0 | **Live capture**: take a base request that returns a token; identify the token location (a cookie by name, a regex/delimiter capture in the body/headers, or an Inspector pick). Repeatedly send the request to collect tokens, showing count and rate. |
| SEQ-002 | P0 | **Manual load**: paste or load a list of previously collected tokens for analysis (no sending). |
| SEQ-003 | P0 | Capture at least a few thousand tokens efficiently (concurrent sends via the engine, honoring throttle/scope); dedupe accidental duplicates and warn if the token doesn't change. |
| SEQ-004 | P0 | **Analysis** at two levels: character-level and bit-level. Convert tokens to bit sequences (per the detected charset/encoding: hex, base64, base64url, decimal, raw) and run the test battery. |
| SEQ-005 | P0 | Test battery (report per-test and an overall estimate of effective entropy in bits, with confidence): character-level — count, transitions, (optionally) chi-square per position; bit-level — FIPS monobit, poker, runs, long-runs; SP 800-22-style — frequency, block frequency, runs, longest-run, serial, approximate entropy, cumulative sums, spectral (where practical). Each test yields a pass/fail at a significance level and a contribution to the entropy estimate. |
| SEQ-006 | P0 | Results UI: an overall quality verdict (Excellent/Good/Reasonable/Poor/Extremely poor) with the estimated bits of entropy, a summary table of tests, and per-position/per-bit charts (Swift Charts) showing where randomness is weak. |
| SEQ-007 | P1 | Handle encoding and padding: strip constant prefixes/suffixes automatically (many tokens have fixed framing), analyze only the varying region, and report what was stripped. |
| SEQ-008 | P1 | Pause/resume/stop capture; save a run (tokens + results) in the project and reopen it; export results. |
| SEQ-009 | P1 | Significance level setting and "reliable results need N samples" guidance; warn when too few samples make results untrustworthy. |
| SEQ-010 | P2 | Compare two runs (e.g. before/after a fix); flag tokens that are time- or counter-derived (monotonic/structured) explicitly. |

## 3. UI

Sequencer sub-tabs: **Capture** (base request, token-location picker, live count, start/stop),
**Manual load**, **Analysis** (verdict, entropy estimate, tests table, charts), and run history.

## 4. Implementation notes

- Token extraction reuses the grep-extract machinery (F07) and the cookie parser.
- Keep raw tokens in a blob; derive bit sequences on demand per the chosen interpretation (let the
  user override the detected encoding).
- Implement the tests in pure Swift in `GulpSequencer` (Linux-testable). Use well-known reference
  vectors to unit-test each test (a known-random stream passes; a known-biased stream fails).
- The "effective entropy" headline is an estimate: combine per-position/per-bit results
  conservatively (take the weakest consistent signal). Document the method in the results ("how this
  is calculated") so users understand it's an estimate, not a guarantee.
- Capture must not alter server state unexpectedly: warn when the request looks state-changing
  (POST) and when the token doesn't vary between responses.

## 5. Edge cases

- Tokens of varying length → analyze the common region; report length variance (itself a smell).
- Structured tokens (JWTs, `base64(json).sig`) → detect and advise analyzing the signature/random
  part, not the header; link to the JWT Workbench (F23).
- Very low variation (constant token) → immediate "no randomness" verdict without the full battery.
- Rate-limited capture → honor throttle; show realistic ETA.

## 6. Acceptance tests

1. VulnLab `/token/weak` (counter/time-derived) is rated Poor/Extremely poor with a low entropy
   estimate; the per-position chart shows the structured bytes.
2. VulnLab `/token/strong` (CSPRNG) is rated Excellent with an estimate near its true bit length.
3. Each statistical test passes on a known-good random vector and fails on a crafted biased vector
   (unit tests with reference data).
4. A run saves and reopens with identical results.
