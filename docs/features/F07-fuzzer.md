# F07 — Fuzzer (Intruder-equivalent)

> Milestone: M8 · Modules: `GulpFuzzer`, `GulpFeatures/Fuzzer` · Depends on: F03, F04, F10, F12

## 1. Purpose

The Fuzzer automates sending many variations of a request by substituting **payloads** into marked
**positions**, then helps the tester spot interesting results (by status, length, time, or matched
content). It is used for brute force, parameter testing, enumeration, and injection testing.

## 2. Requirements

### 2.1 Positions and attack types

| ID | Pri | Requirement |
|---|---|---|
| FUZ-001 | P0 | Mark payload positions in a request by wrapping bytes in `§…§` (U+00A7). Auto-mark common spots (every param value, each header value) with a one-click "auto" that the user can prune. Clear-all and add-from-selection actions. |
| FUZ-002 | P0 | Attack types: **Sniper** (one position at a time, others baseline), **Battering Ram** (same payload in all positions), **Pitchfork** (parallel payload sets, iterate in lockstep), **Cluster Bomb** (Cartesian product of all positions' sets). |
| FUZ-003 | P0 | Base request is fully editable; target and HTTP version as in Repeater. Payloads are inserted as raw bytes at the marked ranges (no re-parsing of the surrounding message). |
| FUZ-004 | P0 | Start/pause/resume/cancel; a live results table streaming as responses arrive. Request count and ETA shown. |

### 2.2 Payloads

| ID | Pri | Requirement |
|---|---|---|
| FUZ-010 | P0 | Payload sources per position set: a simple list (typed or pasted), a file/wordlist, numbers (from/to/step, with padding and hex/dec), dates, a character set brute-forcer (charset × length), null payloads (N empty), and "same as base". |
| FUZ-011 | P0 | Bundled wordlists (copied to the user wordlists dir on first run): common parameters, directories/files, usernames, passwords, fuzzing/injection strings (XSS, SQLi, traversal, SSTI, command metacharacters), user agents. Clearly labeled; the user can add their own. |
| FUZ-012 | P0 | Payload **processing** pipeline (ordered, per set): prefix/suffix, match/replace (regex), case rules, encode (URL, URL-all, HTML, Base64, hex, etc.), hash (md5/sha1/sha256…), skip-if (regex), reverse, substring. Live preview of the first N processed payloads. |
| FUZ-013 | P1 | Payload-processing **Transform Tags** (F12) and a Snippet processor (F18) for arbitrary transforms. |
| FUZ-014 | P1 | "Recursive grep" payloads: feed a value grep-extracted from the previous response as the next payload (for sequential enumeration / CSRF-token following). |
| FUZ-015 | P2 | Payload set from a GulpQL/column of existing history (e.g. all seen param values). |

### 2.3 Processing results

| ID | Pri | Requirement |
|---|---|---|
| FUZ-020 | P0 | Results table columns: #, payload(s), status, response length, response time, error, plus **grep-match** boolean columns and **grep-extract** value columns. Sort and filter (GulpQL via HIS-027). Select a row → see the full request/response. |
| FUZ-021 | P0 | **Grep-match**: a list of strings/regex; each becomes a column flagging responses that contain it. Presets for error strings (SQL errors, stack traces) and success/fail markers. |
| FUZ-022 | P0 | **Grep-extract**: capture text between delimiters or by regex group into a column (e.g. extract a token, a row count, a reflected value). |
| FUZ-023 | P0 | **Baseline & anomalies**: mark a baseline response; highlight rows whose length/status/time deviate; a quick "length histogram" to spot outliers. |
| FUZ-024 | P1 | Reflection column: whether the payload is reflected in the response (and encoded/raw), useful for XSS triage. |
| FUZ-025 | P1 | OAST column: when a payload includes a Beacon token (F10), flag rows that caused an out-of-band interaction (blind injection detection). *(later: M11 — needs Beacon, which lands in M11; the rest of the Fuzzer is M8.)* |
| FUZ-026 | P1 | Save an attack and its results in the project; reopen later; export results (CSV/HTML). |
| FUZ-027 | P2 | Charts: length and time scatter plots (Swift Charts) to eyeball clusters. |

### 2.4 Engine, throttling and Turbo

| ID | Pri | Requirement |
|---|---|---|
| FUZ-030 | P0 | Concurrency control: configurable parallel connections (default 10), requests/second cap, and inter-request delay (fixed or random range). Honor the global throttle (F03 HTTP-013) and ScopeGuard. |
| FUZ-031 | P0 | Retry-on-failure policy and a "stop on" condition (e.g. stop when a grep match is found, or after N errors). |
| FUZ-032 | P1 | **Turbo mode**: a high-throughput engine using HTTP/1 pipelining and HTTP/2 multiplexing to reach thousands of req/s, with a scriptable request generator (a Snippet that yields requests), inspired by Turbo Intruder. Gate it behind an explicit toggle and a clear warning. |
| FUZ-033 | P1 | Resource pool shared with other tools so a running scan + fuzz don't overwhelm the target. |
| FUZ-034 | P2 | Adaptive throttling: back off automatically on 429/503 or rising latency. |

## 3. UI

Fuzzer sub-tabs per attack: **Positions** (base request with `§` markers, attack-type picker),
**Payloads** (per-position set config + processing + preview + count), **Settings** (concurrency,
delays, grep, redirects, retries, stop conditions), **Results** (live table + editor + charts).

Multiple attacks run as separate tabs; the Dashboard lists them as tasks.

## 4. Implementation notes

- A `PayloadStream` protocol yields `[Bytes]` (one per position) lazily, so huge/cartesian spaces
  don't materialize. Total count is computed for the progress bar (or "∞/streamed" for scripted).
- Generate each concrete request by splicing payloads into the base request's marked ranges; then
  apply hooks (content-length fixer runs last if enabled). Record exchanges with source `.fuzzer`.
- Results are written to `fuzzer_results` as they arrive (coalesced); the table is virtualized and
  reads from the store so an attack of millions of rows stays responsive.
- Grep runs on the decompressed, size-capped response view; compile regexes once.
- Turbo mode: a dedicated connection manager using `HTTPEngine` pipelining/multiplexing APIs
  (HTTP-011, HTTP-023); the request generator Snippet runs in the JS runtime with a bridge that
  enqueues requests and receives responses via callbacks.

## 5. Edge cases

- `§` appearing naturally in the request: offer an escape (`§§`) or let the user pick a different
  marker char in settings.
- Payload counts that overflow (cluster bomb of three 10k lists = 10^12): warn and require
  confirmation; stream, never preallocate.
- Encoding interactions: document that position bytes are inserted raw; encoding is a processing
  step, so inserting into an already-URL-encoded context needs the URL-encode processor.
- A position inside a chunked body or multipart: payload changes the length; the content-length/
  multipart-boundary fixer must handle it (or warn).

## 6. Acceptance tests

1. Sniper over a username list against `/login` flags the valid username by a different response
   length/status; the grep column marks the error string on the rest.
2. Cluster bomb (user × password, 50×50) runs at the configured concurrency and respects the rps cap
   (measured), and finds the valid pair.
3. Grep-extract pulls the CSRF token from each `/login` GET; recursive-grep uses it in the paired
   POST.
4. *(M11, not M8)* A blind-injection payload set carrying Beacon tokens flags the row that triggered
   an out-of-band DNS/HTTP interaction (OAST column) — this exercises FUZ-025, which is deferred to
   M11 with Beacon, so it is not part of the M8 Definition of Done.
5. Turbo mode reaches the throughput budget (doc 01 §9) against VulnLab and can be cleanly cancelled.
