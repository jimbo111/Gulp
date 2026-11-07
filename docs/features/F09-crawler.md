# F09 — Crawler

> Milestones: M11 (static), M13 (browser-backed) · Modules: `GulpCrawler`, `GulpBrowser` (optional),
> `GulpFeatures/Scanner` · Depends on: F03, F04, F15, F16

## 1. Purpose

The Crawler discovers an application's content and functionality automatically: it follows links,
submits forms, and (in browser mode) drives a real browser to reach JavaScript-rendered content. Its
output fills the site map and feeds the active Scanner ("crawl and audit").

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| CRL-001 | P0 | Seeded crawl from one or more URLs (or "everything in scope"); strictly honors scope and ScopeGuard. |
| CRL-002 | P0 | Static link extraction from responses: `a[href]`, `link`, `script[src]`, `img[src]`, `form[action]`, `iframe`, `Location`, `url(...)` in CSS, `<base>`, meta refresh, and URL-looking strings in JSON/JS (heuristic, low priority queue). |
| CRL-003 | P0 | A crawl **frontier**: a queue with dedup by normalized URL, depth limit, page budget, and per-host concurrency. Normalization handles default ports, trailing slashes, fragment removal, and (configurable) ignoring volatile query params. |
| CRL-004 | P0 | Form handling: discover forms, fill inputs with safe plausible values (configurable field→value heuristics), and submit GET forms by default; POST forms only in "submit forms" mode with a confirmation and a "never submit matching" exclude list (e.g. logout, delete). |
| CRL-005 | P0 | Robots/sitemap: read `/robots.txt` and `/sitemap.xml` for additional URLs (as hints; obeying `Disallow` is a setting, default off for authorized testing but clearly labeled). |
| CRL-006 | P0 | Session awareness: run session rules/macros (F15) so the crawl stays logged in; detect logout (by a configurable signal) and re-authenticate. *(Build the re-auth hook point in M11; the session-rule/macro wiring is completed in M12 when F15 lands. The M11 crawler runs unauthenticated.)* |
| CRL-007 | P1 | Duplicate-content detection: collapse near-identical pages (hash of structure) to avoid crawling pagination/calendars forever; a "crawl similar pages up to N" cap. |
| CRL-008 | P1 | Coverage controls: max depth, max pages, max per-directory, max duration, and request throttling (shared pool). |
| CRL-009 | P1 | Parameter discovery during crawl: record every param name/value seen to inform the site map's analysis (F04 TGT-008) and the Scanner. |
| CRL-010 | P1 | Crawl report: pages discovered, forms found, parameters, errors, and auth events. |

### Browser-backed mode (M13)

| ID | Pri | Requirement |
|---|---|---|
| CRL-030 | P0 | Drive the managed Chromium (F16) over CDP to render pages, so SPA/JS content and client-side links are discovered. All browser traffic goes through the Gulp proxy, so it's logged and in the site map. |
| CRL-031 | P0 | Interaction: wait for network idle, extract links from the rendered DOM, click same-origin in-scope links, and (in form mode) fill and submit forms via the DOM. |
| CRL-032 | P1 | A pool of browser tabs/contexts for parallelism; recycle contexts to bound memory. |
| CRL-033 | P1 | Trigger events that reveal content (hover menus, "load more"), bounded by a per-page action budget. |
| CRL-034 | P1 | Capture client-side navigation (history API) and XHR/fetch endpoints as site-map entries. |
| CRL-035 | P2 | Optional screenshot per page stored with the node (for the report and visual review). |
| CRL-036 | P2 | Record a login once in the browser (F15 SES-030) and reuse it as the crawl's auth. |

## 3. UI

- Launched from Target ("Crawl from here"), the Dashboard ("New crawl"), or combined as "Crawl and
  audit" (crawl feeds the Scanner). A config sheet (seeds, scope reminder, mode static/browser, form
  policy, limits, session). Progress in the Dashboard: pages/sec, queue size, discovered counts, a
  live tree preview, and a log.

## 4. Implementation notes

- The static extractor reuses the passive link extractor (shared with F04 inferred URLs). Parse HTML
  with a tolerant parser (don't require well-formed markup); extract CSS/JS URLs with scoped regexes.
- Frontier is an actor with a priority queue (links high, heuristic URL-strings low). Persist it so a
  crawl can pause/resume across app restarts (store seeds + visited set hash; re-derive if needed).
- Browser mode: one CDP client (F16) manages targets (tabs); navigate, `Page.loadEventFired` +
  network-idle heuristic, `Runtime.evaluate` to collect links and to fill forms; enforce scope on
  every navigation (cancel out-of-scope loads).
- "Crawl and audit" hands each discovered in-scope request to the Scanner's insertion-point engine
  (F08). The **audit dedup key** is `(method, normalized-path-template, param-name-set)` — path
  templates collapse numeric/UUID segments to `{id}` (as TGT-006) and the key ignores parameter
  *values* — so each distinct parameter is audited once regardless of value, and infinite
  value-spaces (pagination, search) don't explode the insertion-point set. This is deliberately
  different from the crawl frontier's URL dedup (CRL-003), which keeps distinct values to discover
  content.

## 5. Edge cases

- Infinite spaces (calendars, faceted search): depth/budget + duplicate-structure detection.
- Dangerous links (logout, delete, state changes): a default exclude list and "don't submit
  destructive forms" heuristic (method + keywords); always honor scope excludes.
- Auth loops (every page redirects to login): detect and surface "session not established" rather
  than hammering.
- Rate-limited/fragile targets: throttle; back off on 429/503.

## 6. Acceptance tests

1. Static crawl of VulnLab discovers the linked pages and the guestbook form; the site map fills;
   out-of-scope links are not fetched.
2. "Crawl and audit" (Thorough) finds every P0 vulnerability (doc 06 §3) and nothing on `/safe/*`.
3. Browser-mode crawl of `/app/` (SPA) discovers client-rendered routes and the XHR endpoints that
   static mode misses.
4. With a login macro configured, a crawl of the authenticated area stays logged in (re-auth on
   detected logout) and reaches `/account`.
