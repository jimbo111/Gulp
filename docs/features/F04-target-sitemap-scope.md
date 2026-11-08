# F04 — Target: site map and scope

> Milestones: M6a (site map, scope), M6b (import entry point TGT-009), M9 (coverage index), M16b
> (coverage view) · Modules: `GulpCore` (ScopeService), `GulpStore`, `GulpFeatures/Target` ·
> Depends on: F05

## 1. Purpose

The **Target** tool organizes everything Gulp has seen about the applications under test into a tree
(the **site map**) and lets the tester define **scope** — which hosts and paths the engagement
covers. Scope drives what active tools are allowed to touch and what the UI shows by default.

## 2. Requirements

### 2.1 Site map

| ID | Pri | Requirement |
|---|---|---|
| TGT-001 | P0 | Build a tree from all exchanges: host → path segments → leaf (endpoint). Nodes aggregate the requests seen for them. Built incrementally as traffic arrives (listen to `exchangeRecorded`), and rebuildable from the store. |
| TGT-002 | P0 | Selecting a node shows its endpoints in a table (method, path, status, length, MIME, params, time) and the selected exchange in the MessageEditor. |
| TGT-003 | P0 | Distinguish **visited** (a real request was seen) from **inferred** (a URL only referenced in a response but never requested) nodes, shown with a dimmed style. |
| TGT-004 | P0 | Context menu on nodes/rows: add/remove scope, Send to… (F01 UI-040), "Actively scan this branch", "Crawl from here", "Delete branch", Copy URLs, Expand/collapse. |
| TGT-005 | P1 | Show/hide filters: only in-scope, hide not-found (404), hide out-of-scope, MIME filters, a search box (matches host/path). |
| TGT-006 | P1 | Group parameterized paths: collapse numeric or UUID path segments into a `{id}` node (toggle), so `/users/1`, `/users/2` fold into `/users/{id}`. |
| TGT-007 | P1 | Per-node annotations (comment, highlight) and per-host notes. |
| TGT-008 | P1 | "Analyze target" panel for a host: counts of dynamic URLs, parameters seen (name → where used), interesting observations (params that look like filenames, redirects, tokens). |
| TGT-009 | P2 | Import/merge URLs from a file, a sitemap.xml, an OpenAPI/Swagger spec, or a HAR into the site map. *(The Target entry point of the shared import/export service, F20 PRJ-012; OpenAPI request building is F23 ADV-050. Ships with PRJ-012 in M6b.)* |
| TGT-010 | P2 | Compare two site maps (for example before/after a crawl) and highlight new content. |

### 2.2 Scope

| ID | Pri | Requirement |
|---|---|---|
| TGT-020 | P0 | Scope = an ordered list of include and exclude rules. Evaluation is **last-match-wins**: walk the enabled rules top to bottom; the last rule that matches the target decides (include ⇒ in scope, exclude ⇒ out). If **no** rule matches, the target is **out of scope** (an empty rule set means nothing is in scope). The UI shows the deciding rule when you test a URL. Each rule: enabled, protocol (http/https/any), host (regex or "exact"), port (exact/range/any), path (regex). |
| TGT-021 | P0 | Simple mode: add a host or URL prefix with one action ("Add to scope") that generates a sensible rule (host-exact + path-prefix). Advanced mode exposes the regex rules table. |
| TGT-022 | P0 | `ScopeService.isInScope(target:path:)` is pure and fast (precompiled regexes); it's used by the UI, the store's `in_scope` cache, and ScopeGuard. On scope change, recompute `in_scope` for affected rows in the background and emit `scopeChanged`. |
| TGT-023 | P0 | **ScopeGuard**: active tools (Scanner active audit, Crawler, Fuzzer, Beacon injection, active parts of advanced tools) call `ScopeGuard.require(target)` before sending. Out of scope → throw `.outOfScope` unless the call carries an explicit per-action override (the UI asks "Target is out of scope. Send anyway?"). A **manual single send** (e.g. Repeater) is not auto-blocked but prompts for confirmation on an out-of-scope target before sending — the same "Send anyway?" dialog, which supplies the override; a per-setting "don't ask again for this host/project" downgrades it to a non-blocking warning badge. Tools with no network egress (Decoder, Comparer) are unaffected. |
| TGT-024 | P1 | "Use scope for the proxy" option: the proxy drops/omits out-of-scope items from history and live tasks (PRX-045). |
| TGT-025 | P1 | Export/import scope as JSON; show the effective scope as a readable summary ("In scope: https://*.example.com on 443; Excluded: /logout"). |
| TGT-026 | P2 | Scope presets per project and a quick scope switcher in the toolbar. |

### 2.3 Coverage (moved from F31 Journal, 2026-11-08)

| ID | Pri | Requirement |
|---|---|---|
| JRN-001 | P0 | **Coverage index**: per endpoint (from the site map), record which tools have exercised it and last-tested time, derived from the `ToolSource` on exchanges. At its M9 landing the available sources are Repeater/Fuzzer/Notebook; the Scanner (active/passive) columns populate once F08 ships (M10a/M11b). The index is source-agnostic, so it extends automatically as tools come online. *(Moved from F31; M9.)* |
| JRN-002 | P0 | **Coverage view**: the Target tree (UI-060) annotated with coverage badges, plus filters "show untested in-scope endpoints" and "show params never fuzzed". *(Moved from F31; M16b.)* |

## 3. UI

Target sub-tabs: **Site map** and **Scope**.
- Site map: an outline view (UI-060) on the left, the endpoint table + editor on the right, and the
  filter bar on top.
- Scope: a simple list (chips of in-scope hosts, an "Add" field) with an "Advanced" disclosure that
  shows the include/exclude rules tables and a live "test a URL against scope" field.

## 4. Implementation notes

- Site-map tree is kept in memory as a trie of nodes; persist annotations and the inferred/visited
  bit, not the whole tree (rebuild the structure from `exchanges` on open — it's fast with the host
  and path indexes).
- Inferred URLs come from passive link extraction (shared with the Crawler, F09): parse `href`,
  `src`, `action`, `Location`, JSON URL-looking strings; add inferred nodes without requesting them.
- Precompile scope regexes once; guard against catastrophic backtracking by validating
  user-supplied regexes (reject or warn on nested quantifiers; apply a match timeout).
- The coverage index (JRN-001) is an aggregation over `exchanges.source` + endpoint identity (the
  audit dedup key from F09 works here too); it is derived and rebuildable from the store, so it needs
  no table. Compute it incrementally; categorize by tool so a single passive view doesn't count as an
  active test ("touched" is not "tested").

## 5. Edge cases

- Ports: an include for `example.com` with "any port" vs. an explicit `:443`. Default "Add to scope"
  uses any port unless the URL had a non-default port.
- IDN/case: match on the normalized lowercase host.
- A huge site map (100k nodes): virtualize the outline view; lazy-load children.

## 6. Acceptance tests

1. Browsing two hosts builds two top-level nodes; a referenced-but-not-visited URL appears dimmed.
2. "Add to scope" on `https://example.com/app` makes `/app/x` in scope and `/other` logic correct
   per rule order; `http://example.com` out if protocol is https-only.
3. A Repeater send to an out-of-scope host triggers the confirmation dialog; confirming sends it;
   an active scan of an out-of-scope node is blocked without override.
4. Changing scope recomputes `in_scope` for 100k rows in the background without freezing the UI.
5. Coverage (moved from F31): sending an endpoint to Repeater then actively scanning it marks both
   tools covered with correct timestamps in the coverage index; the "untested in-scope" filter lists
   only endpoints with no recorded tool activity.
