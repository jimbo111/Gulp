# F27 — JS Recon Studio (source-map recovery & API inventory)

> Milestone: M23 (the recon core only needs F04/F05, so it can be built earlier if desired) · Modules: `GulpFeatures/JSRecon`
> (asset storage in `GulpStore`; source-map/endpoint parsing is pure Swift and may live in `GulpCodec`/`GulpCore`; the JS
> beautifier is either a pure-Swift formatter or, if it uses JavaScriptCore, `GulpScript` — **not** `GulpCore`, which is
> pure-Swift and Linux-building, doc 01 §3 rule 3) · Depends on: F04, F05, F08, F09, F23

## 1. Purpose

Front-end bundles are the richest recon source in modern SPAs. Today Gulp only regex-scans JS for
secrets (F23 ADV-060) and lists scripts/comments (F17 ETL-004). JS Recon Studio aggregates every JS
asset seen for the in-scope hosts, beautifies/unminifies it, recovers original source trees from
`.map` files, and mines them for an **API/endpoint inventory** (fetch/XHR/axios URLs, route tables,
GraphQL operations), parameter names, feature flags, cloud/storage URLs, and library versions — then
feeds those endpoints into the site map, Crawler, Scanner and Param Discovery. It turns "dead" client
code into live attack surface.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| JSR-001 | P0 | Collect all JS (and CSS) assets observed for selected in-scope hosts, dedup by content hash, show size/host/first-seen; pull fresh copies via the engine on request (scope-gated). |
| JSR-002 | P0 | Beautify/unminify JS for readable viewing and search, with syntax highlighting (reuse the `MessageEditor`, doc 05 UI-010, from `GulpUI`). |
| JSR-003 | P0 | Recover original sources from source maps: detect `//# sourceMappingURL` and inline/base64 maps, fetch referenced `.map` files, and reconstruct the original file tree from `sourcesContent` as a browsable virtual folder. |
| JSR-004 | P0 | Extract an endpoint/API inventory from JS/maps — URL string literals, `fetch`/XHR/axios/`$.ajax` targets, route-table paths, GraphQL operation strings — normalized against the target origin, deduped. |
| JSR-005 | P0 | Send discovered endpoints into the site map (F04) and offer "crawl/scan/Param-Discover these" (F08/F09/F23), honoring scope. |
| JSR-006 | P1 | Mine candidate parameter names, feature flags and config keys from JS and hand them to Param Discovery (F23 ADV-021). |
| JSR-007 | P1 | Fingerprint JS libraries/framework versions and cross-link to the Scanner's vulnerable-JS dataset (F08). |
| JSR-008 | P1 | Flag interesting literals (cloud storage URLs, internal hostnames, API bases, source-map exposure itself) as info observations; link secrets to the F23 secret scanner rather than re-implementing it. |
| JSR-009 | P2 | Diff an asset across captures to surface newly-added endpoints/routes between app versions (retest/engagement value; pairs with F30). |

## 3. UI

A JS Recon tool: an asset list (host, size, first-seen, "has source map" badge); a viewer with
beautified source and the reconstructed source tree; an **inventory** panel (endpoints, params,
libraries, literals) with per-row "send to site map / crawl / scan / Param Discovery"; and a diff
view across captures.

## 4. Implementation notes

- Beautify with a pure-Swift JS formatter where possible (keeps it Linux-buildable); if a
  JavaScriptCore-based beautifier is used it lives in `GulpScript` (macOS-only), never in `GulpCore`.
  Source-map reconstruction parses the Source Map v3 JSON (`sources` + `sourcesContent`) into a
  virtual tree — no eval, pure data, so it can live in a cross-platform module.
- Endpoint extraction combines AST-ish scans (string literals passed to known fetch/XHR/axios calls)
  with scoped regexes; normalize relative URLs against the asset's origin; dedup against the site map.
- This is pure parsing/orchestration — no attack sends except the scope-gated asset re-fetch and the
  downstream crawl/scan it hands off.
- Store assets as blobs (dedup by sha256, doc 04); the inventory is derived and rebuildable.

## 5. Edge cases

- Huge bundles (10+ MB) — stream/paginate the viewer; cap beautify work and continue in background.
- Obfuscated/webpack-runtime code — endpoint extraction is best-effort; report confidence.
- Source maps referenced but 404/withheld — report "map referenced but unavailable".
- Source-map exposure in production is itself a finding (info/low), not just a convenience.

## 6. Acceptance tests

1. VulnLab serves a minified bundle with an exposed `.map`; the tool reconstructs the original `src/`
   tree and lists files.
2. The endpoint miner extracts planted `/api/internal/*` routes not reachable by crawling and adds
   them to the site map; "scan these" finds the planted bug on one.
3. Library fingerprinting flags a bundled known-vulnerable library version.
4. The asset diff surfaces a new endpoint added between two VulnLab captures.
