# F29 — Governor (global resource control + panic stop)

> Milestone: core in M11 (first active tools), full panel in M16 · Modules: `GulpHTTP` (shared
> limiter), `GulpWorkspace`, `GulpFeatures/Governor` · Depends on: F03, F04, F07, F08, F09, F10, F20

## 1. Purpose

One place that bounds everything Gulp *generates*: global and per-host concurrency and request-rate
caps, resource watchpoints, scheduled quiet hours, and a one-key **panic stop** that halts every
active tool at once. Today rate limiting and resource pools exist per tool (doc 00 §6) with no global
ceiling, no per-host budget shared across tools, and no emergency brake. This is both a safety
feature ("safe by default") and a performance control, and it's the single choke point active tools
already pass through for ScopeGuard.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| GOV-001 | P0 | **Panic stop** (⌃. and a toolbar + menu-bar-extra item): immediately pause all active, network-generating tasks across the project (Scanner, Crawler, Fuzzer, Beacon injection, Sequencer capture, Drift runs, scheduled tasks); show what was stopped and offer "resume all". |
| GOV-002 | P0 | **Global caps**: max total concurrent outbound connections and max requests/sec across *all* tools, enforced by a shared token-bucket + semaphore in `GulpHTTP` that every active tool draws from. |
| GOV-003 | P0 | **Per-host budgets**: concurrency and req/s limits keyed by host, shared across tools, so Scanner + Fuzzer hitting one host can't collectively overrun it; conservative defaults, overridable per host. |
| GOV-004 | P1 | **Resource watchpoints**: pause active tasks and warn when project size, free disk, or app memory cross thresholds; tie into PRJ-010 retention. |
| GOV-005 | P1 | **Quiet hours / windows**: a schedule during which active tools auto-pause (e.g. no automated traffic during business hours on prod), integrating with the scheduler (F17 ETL-006). |
| GOV-006 | P1 | **Live throughput panel** (status bar + Dashboard): current req/s, in-flight, per-host leaders, and which cap is the current bottleneck. |
| GOV-007 | P1 | **Adaptive backoff**: automatically reduce rate when a host returns a burst of 429/503/timeouts, with a visible "throttled" badge and a manual override (supersedes the per-tool FUZ-034/SCN hints with one shared mechanism). |
| GOV-008 | P2 | **Dry-run / preview** for any active tool: estimate total requests and time under current caps before launching. |
| GOV-009 | P2 | Caps are **layered settings** (PRJ-020): a project inherits a cautious user default and can tighten per engagement. |

## 3. UI

Settings → a "Network" / "Governor" area for the caps, per-host overrides, quiet hours and
watchpoints (layered). A persistent status-bar throughput readout and a menu-bar-extra panic button;
the Dashboard shows the live throughput panel and which cap is binding.

## 4. Implementation notes

- The limiter lives in `GulpHTTP` as a shared `ResourcePool` (token bucket for rate, semaphore for
  concurrency, keyed global + per-host). Every active tool already calls `ScopeGuard.require` before
  sending (F04 TGT-023) — the Governor sits at the **same gate**, so wiring is cheap: `acquire()`
  before send, `release()` after.
- Panic stop flips a shared `paused` flag the pool checks and cancels in-flight permits; tasks
  observe cancellation (F03 HTTP-009) and move to Paused, resumable.
- Backoff watches response status/latency per host and shrinks that host's bucket, restoring it as
  health recovers.
- `TaskProgress`/throughput feed the Dashboard via the EventBus (`taskProgress`).

## 5. Edge cases

- Panic stop must not corrupt in-progress project writes — it pauses *sending*, not the store
  coalescer; queued writes still flush.
- A per-host cap of 0 effectively blocklists a host for active tools (useful, document it).
- Quiet hours firing mid-scan → pause, resume automatically when the window ends (or on manual
  override).
- The limiter must add negligible overhead on the hot path (lock-free/striped counters).

## 6. Acceptance tests

1. A Fuzzer configured for 2,000 req/s plus a concurrent crawl never exceed a 1,000 req/s global cap
   in aggregate (measured).
2. Two tools targeting one host share a 50-concurrency budget (combined in-flight ≤ 50).
3. ⌃. during a scan+fuzz leaves zero in-flight requests within one limiter tick and all tasks Paused;
   "resume all" restarts them.
4. A VulnLab endpoint returning 503 bursts drives the measured send rate down and flips the throttled
   badge, then recovers.
