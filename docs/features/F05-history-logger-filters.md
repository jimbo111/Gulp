# F05 — History, Logger, GulpQL filters and search

> Milestones: M2 (history), M9 (GulpQL, Logger, search) · Modules: `GulpQuery`, `GulpStore`,
> `GulpFeatures/{Proxy,Logger}` · Depends on: F01, F04

## 1. Purpose

Everything that passes through any tool is logged. The **HTTP History** (Proxy) shows proxy traffic;
the **Logger** shows traffic from *every* tool in one place. **GulpQL** is a small, fast query
language used for filters, intercept rules, match-replace conditions and search. Global search uses
SQLite FTS for substring matching across millions of messages.

## 2. Requirements

### 2.1 History and Logger tables

| ID | Pri | Requirement |
|---|---|---|
| HIS-001 | P0 | HTTP History table (UI-001) with columns: #, Host, Method, URL/Path, Params, Status, Length, MIME, Title, TLS, Time, Source, Comment, Highlight. Column chooser, resize, reorder, sort; preferences persist. |
| HIS-002 | P0 | Paged, virtualized rendering from the store (never load all rows). Live-append new rows (coalesced ≤100 ms); an "auto-scroll to newest" toggle. |
| HIS-003 | P0 | Row selection shows request/response in the MessageEditor (UI-010) with layout control (UI-050). |
| HIS-004 | P0 | Multi-select with bulk actions: highlight, comment, add to scope, send to tools, delete, save, copy URLs. |
| HIS-005 | P0 | Highlight colors (9) and inline comment editing (UI-041). |
| HIS-006 | P0 | Quick-filter chips (UI-002): in scope, hide images/CSS/JS/fonts, status classes, has params, commented/highlighted, MIME, method. |
| HIS-040 | P1 | **Logger**: one table of every exchange across all tools (source column prominent), independent of project history display settings; its own GulpQL filter and columns. |
| HIS-041 | P1 | Logger "capture" toggle and a per-source include set (e.g. log Proxy + Repeater only). |
| HIS-042 | P1 | Connection view: group by TCP/TLS/H2 connection, show reuse, ALPN, and per-connection events (F03 HTTP-026). |
| HIS-043 | P1 | Custom columns via a Snippet (F18) or a GulpQL expression (e.g. a column `resp.header("x-cache")`). |
| HIS-044 | P1 | Export selected or filtered rows as HAR, CSV, or `.gulp`-items; import HAR into history. |
| HIS-045 | P2 | Live column of a regex capture (e.g. extract a request id) with match highlighting. |

### 2.2 GulpQL

| ID | Pri | Requirement |
|---|---|---|
| HIS-020 | P0 | A boolean expression language over a message/exchange. Grammar in §4. Operators: `and or not`, parentheses, comparisons `== != < <= > >=`, `~` (regex matches), `!~`, `in` (set/range), `contains`, `startswith`, `endswith`. Case-insensitive string compares by default; `=~` is case-sensitive regex, `~` case-insensitive. |
| HIS-021 | P0 | Fields: `req.method req.host req.port req.scheme req.path req.query req.url req.ext req.length req.body req.line` ; `req.header("name")` (last value), `req.headers("name")` (list), `req.cookie("name")`, `req.param("name")`, `req.params` ; `resp.status resp.length resp.mime resp.title resp.body resp.time` , `resp.header(...)`, `resp.cookie(...)`, `resp.sets_cookie` ; `source`, `in_scope`, `highlight`, `comment`, `tag`, `has_response`, `edited`, `notes`. |
| HIS-022 | P0 | Helper predicates: `req.has_param`, `reflected("x")` (a request param value appears in the response), `time_between(a,b)`, `matches_scope`. |
| HIS-023 | P0 | Evaluate in memory against an `Exchange`. Pure, Sendable, no side effects. |
| HIS-024 | P0 | **SQL push-down**: translate the parts of an expression that map to indexed columns (`status`, `host`, `method`, `in_scope`, `source`, `length`, `highlight`, ranges) into a SQL `WHERE` clause, so filtering 1M rows uses indexes; evaluate the remainder (body regex, header lookups) in memory over the reduced set. |
| HIS-025 | P1 | Autocomplete and inline syntax coloring in the FilterBar; error underlining with a message. |
| HIS-026 | P1 | Saved filters (named) and a recents list; filters are shareable (export/import). |
| HIS-027 | P1 | The same expression type powers intercept rules (PRX-015), match-replace conditions (PRX-025), Logger filters, scanner insertion-point conditions, and Fuzzer result filters. |
| HIS-028 | P2 | `Snippet` escape hatch: `snippet("name")` calls a JS predicate (F18) for cases GulpQL can't express. |

### 2.3 Search

| ID | Pri | Requirement |
|---|---|---|
| HIS-050 | P0 | Global search (⌘⇧F) across requests and responses using the FTS5 trigram index; results grouped by tool with match previews; click to open. Queries under 3 characters (below the trigram minimum) fall back to a bounded scan (HIS-052) with a "narrow your search" hint. |
| HIS-051 | P0 | Search scope selector: current table, whole project, in-scope only; and a field selector (request/response/both, headers/body). |
| HIS-052 | P1 | Regex search mode (slower; runs over the candidate set returned by a trigram prefilter where possible, else a scan with progress and cancel). |
| HIS-053 | P1 | "Find references" to a value (token, filename) across the project. |
| HIS-054 | P2 | Search within WebSocket messages and the Notebook. |

## 3. UI

- History and Logger: FilterBar on top, table, editors below. A result count and an active-filter
  summary chip. A "⌘⇧F" global search opens a sheet with grouped results.
- GulpQL field: monospace, autocomplete popover, red underline on parse errors with a tooltip.

## 4. GulpQL grammar (EBNF, implement in `GulpQuery`)

```
expr      := orExpr
orExpr    := andExpr ("or" andExpr)*
andExpr   := notExpr ("and" notExpr)*
notExpr   := "not" notExpr | primary
primary   := "(" expr ")" | comparison | predicate
comparison:= field op value
op        := "==" | "!=" | "<" | "<=" | ">" | ">=" | "~" | "!~" | "=~"
           | "contains" | "startswith" | "endswith" | "in"
field     := ident ("." ident)? ( "(" string ")" )?     // e.g. req.header("x")
value     := string | number | regex | list | range | bool | ident
list      := "[" value ("," value)* "]"
range     := number ".." number
```

Implementation: a hand-written lexer and a Pratt/recursive-descent parser → a `GulpQLExpression`
AST (Sendable, Codable). Two evaluators: `evaluate(_:Exchange) -> Bool` and
`sqlLowering() -> (sql: String?, bindings: [SQLBinding], residual: GulpQLExpression?)`, where
`SQLBinding` is a small neutral enum (`.text/.int/.double/.blob/.null`) owned by `GulpQuery`.
`GulpQuery` must **not** import GRDB (or any storage type) — `GulpStore` maps `SQLBinding` to its
own driver values. This keeps the query language a pure, Linux-testable lower-layer module.

## 5. Edge cases

- A field that needs the response (`resp.*`) on a request-only row → unknown → the row is excluded
  from positive matches and included under `not`/`has_response == false` logic consistently
  (define: missing fields compare as "no match"; `has_response` gates it).
- Very large bodies: body regex runs only on the decompressed, size-capped view (first 2 MB) with a
  flag that it was truncated.
- Invalid user regex: parse error surfaced in the FilterBar, evaluation returns everything (fail
  open) only in the UI filter, never in ScopeGuard.

## 6. Acceptance tests

1. `resp.status >= 500 and req.host ~ "api"` returns the right rows; the SQL push-down means it
   doesn't scan bodies (assert via a query-plan check that an index is used).
2. `reflected("q")` flags the VulnLab `/xss/html?q=` row.
3. Global search for a planted unique token finds it in both a request and a response in <200 ms on
   a 100k-row project.
4. The same expression string drives a Logger filter and an intercept rule identically.
