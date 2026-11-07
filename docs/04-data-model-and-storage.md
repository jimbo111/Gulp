# 04 — Data model and storage

## 1. Principles

1. **Raw bytes are canonical.** Request and response bytes are stored exactly as sent and received
   on the wire (for HTTP/2: the HTTP/1-style text representation in §3, plus the original frames
   when "keep frames" is on).
2. **Parsing is lazy and range-based.** A parsed message is a set of byte ranges into the raw
   buffer. Editing one part (for example a header value) splices bytes, so the formatting of
   everything else is preserved.
3. **Derived data is rebuildable.** The site map, FTS index and statistics can be rebuilt from the
   `exchanges` table (`Project → Rebuild indexes`).

## 2. Core Swift types (GulpCore)

```swift
// Bytes wraps [UInt8] with copy-on-write storage and cheap slices. Minimum API GulpCore relies on:
public struct Bytes: Sendable, Hashable, RandomAccessCollection {
    public typealias Element = UInt8
    public typealias SubSequence = Bytes
    public init(_ bytes: [UInt8])
    public init(_ string: String)                 // UTF-8
    public var startIndex: Int { get }; public var endIndex: Int { get }
    public subscript(position: Int) -> UInt8 { get }
    public subscript(bounds: Range<Int>) -> Bytes { get }
    public func string(lossy: Bool = true) -> String   // UTF-8 view for display
    public mutating func replaceSubrange(_ r: Range<Int>, with new: Bytes)
}

public struct RawRequest: Sendable, Hashable {
    public var bytes: Bytes { get }               // the canonical bytes (see init/edit below)
    public var parsed: ParsedRequest { get }      // parsed once at init and memoized (see note)
    public init(_ bytes: Bytes)                   // parses eagerly; `parsed` is stored, not recomputed
    /// Serializing is the identity: `RawRequest(b).serialize() == b` (doc 06 §2 round-trip test).
    public func serialize() -> Bytes
    /// Splice new bytes over a parsed byte range (e.g. a header value), returning a re-parsed value;
    /// only those bytes change, everything else is preserved (doc 06 §2 edit test).
    public func replacing(_ range: Range<Int>, with new: Bytes) -> RawRequest
}
// Memoization note: `parsed` is computed in `init` and stored, so there is no "mutate then
// invalidate" problem — these are value types and any edit (`replacing`) returns a NEW value whose
// `parsed` is recomputed from the spliced bytes. `bytes` is get-only for the same reason.

public struct ParsedRequest: Sendable {
    public var method: Range<Int>                 // byte ranges into RawRequest.bytes
    public var target: Range<Int>                 // request-target (origin/absolute/authority/asterisk form)
    public var version: Range<Int>
    public var headers: [HeaderField]             // in order, duplicates allowed
    public var headerBlockEnd: Int                // index after CRLFCRLF (or LFLF, tolerated)
    public var body: Range<Int>
    public var lineEnding: LineEnding             // .crlf / .lf / .mixed (preserved)
    public var warnings: [ParseWarning]           // e.g. obsolete line folding, bare LF, invalid chars
}

public struct HeaderField: Sendable { public var name: Range<Int>; public var value: Range<Int>; public var line: Range<Int> }

public struct ParsedResponse: Sendable {          // mirror of ParsedRequest for the status line
    public var version: Range<Int>                // e.g. "HTTP/1.1"
    public var statusCode: Int                    // parsed integer, e.g. 200
    public var reasonPhrase: Range<Int>
    public var headers: [HeaderField]             // in order, duplicates allowed
    public var headerBlockEnd: Int                // index after CRLFCRLF (or LFLF, tolerated)
    public var body: Range<Int>                   // the body as framed (raw; chunked stays chunked)
    public var dechunkedBody: Bytes?              // de-chunked view when Transfer-Encoding: chunked
    public var transferEncodingChunked: Bool
    public var contentLength: Int?
    public var bodyFraming: BodyFraming           // .contentLength / .chunked / .closeDelimited / .none
    public var interimResponses: [ParsedResponse] // recorded 1xx responses that preceded this one (HTTP-002)
    public var lineEnding: LineEnding
    public var warnings: [ParseWarning]
    public var incomplete: Bool                   // true if the connection closed before the declared body finished
}

public struct RawResponse: Sendable, Hashable {
    public var bytes: Bytes { get }
    public var parsed: ParsedResponse { get }
    public init(_ bytes: Bytes)                   // parses eagerly; `parsed` memoized as in RawRequest
    public func serialize() -> Bytes              // identity
    public func replacing(_ range: Range<Int>, with new: Bytes) -> RawResponse
}

public struct HTTPTarget: Sendable, Hashable, Codable {
    public var scheme: Scheme            // .http / .https
    public var host: String              // as used for Host/SNI by default
    public var port: Int
    public var sniOverride: String?
    public var ipOverride: String?       // connect to this IP instead of resolving host
}

public typealias ExchangeID = Int64

public struct Exchange: Sendable, Identifiable {
    public var id: ExchangeID
    public var source: ToolSource
    public var target: HTTPTarget
    public var httpVersion: HTTPVersion            // .http1_0, .http1_1, .http2
    public var request: RawRequest
    public var response: RawResponse?              // nil while pending or failed
    public var state: ExchangeState                // .pending, .complete, .failed(GulpNetworkError), .dropped, .intercepted
    public var timing: Timing                      // see Timing below (all phases of HTTP-010)
    public var clientAddress: String?              // for proxy traffic
    public var connectionID: UInt64                // groups requests on the same connection
    public var tls: TLSInfo?                       // negotiated version, cipher, ALPN, server cert chain fingerprint
    public var edited: EditInfo?                   // original request/response if modified by intercept or match&replace
    public var annotation: Annotation              // comment, highlight, tags
    public var derived: DerivedFields              // host, path, query, mime, status, lengths, title, param count, cookies set…
}

// ---- Supporting value types (all in GulpCore) ----
public enum Scheme: String, Sendable, Codable { case http, https }
public enum HTTPVersion: String, Sendable, Codable { case http1_0 = "HTTP/1.0", http1_1 = "HTTP/1.1", http2 = "HTTP/2" }
public enum LineEnding: Sendable { case crlf, lf, mixed }
public enum BodyFraming: Sendable { case contentLength, chunked, closeDelimited, none }
public enum ParseWarning: Sendable, Equatable {
    case bareLF, obsoleteLineFolding, missingFinalCRLF, invalidCharInName, duplicateContentLength,
         conflictingFraming, oversizedHeaders, nonUTF8
}

public struct Timing: Sendable, Codable {         // milliseconds per phase; all of HTTP-010
    public var start: Date
    public var dnsMs, connectMs, tlsMs, requestWriteMs, ttfbMs, downloadMs, totalMs: Double?
}  // tlsMs/connectMs are nil for reused or plaintext connections; requestWriteMs + downloadMs added per HTTP-010.

public struct TLSInfo: Sendable, Codable {        // Exchange.tls
    public var version: String                    // e.g. "TLSv1.3"
    public var cipherSuite: String
    public var alpn: String?                       // "h2" / "http/1.1"
    public var serverChainSHA256: [String]         // fingerprints, leaf first
    public var validation: TLSValidation           // .ok / .failed(reason) / .notChecked
}
public enum TLSValidation: Sendable, Codable, Equatable { case ok, notChecked, failed(String) }

public struct EditInfo: Sendable {                // Exchange.edited (set when intercept/match&replace changed bytes)
    public var originalRequest: RawRequest?
    public var originalResponse: RawResponse?
    public var editedBy: ToolSource                // who changed it
}

public struct DerivedFields: Sendable, Codable {  // denormalized columns mirrored into `exchanges` (doc §4)
    public var host: String; public var port: Int; public var scheme: Scheme
    public var method: String?; public var path: String?; public var query: String?; public var ext: String?
    public var status: Int?; public var responseLength: Int?; public var mime: String?; public var title: String?
    public var paramCount: Int; public var hasCookies: Bool; public var setsCookies: Bool
}

public struct Annotation: Sendable, Codable {     // Exchange.annotation
    public var comment: String?; public var highlight: Highlight?; public var tags: [String]
}

// ToolSource encodes to the TEXT column `exchanges.source` as a stable string: the simple cases are
// their names ("proxy","repeater",…); `.extension(id)` encodes as "extension:<id>".
public enum ToolSource: Sendable, Codable, Hashable {
    case proxy, repeater, fuzzer, scanner, crawler, sequencer, session, browser, automation, ai
    case extension(id: String)
    public var rawValue: String { get }            // the TEXT encoding above
    public init?(rawValue: String)
}

// Error model. GulpNetworkError is the typed failure stored in ExchangeState.failed and serialized
// into `exchanges.error`; GulpError is the user-facing app error (message + recovery suggestion).
public enum GulpNetworkError: Sendable, Codable, Equatable {
    case cancelled, connectTimeout, tlsHandshakeTimeout, firstByteTimeout, idleTimeout, totalTimeout
    case connectionRefused, connectionReset, dnsFailure(String), tlsFailure(String)
    case tooLarge(limit: Int), incompleteResponse, upstreamProxyError(String), other(String)
    public var code: String { get }                // the `exchanges.error` TEXT token, e.g. "connect_timeout"
}
public struct GulpError: Error, Sendable {         // thrown to the UI/CLI, never stored in an exchange
    public var message: String                     // user-facing
    public var recoverySuggestion: String?
    public var underlying: GulpNetworkError?
}
```

> **Concept: why byte ranges instead of a dictionary of headers?** A dictionary loses order,
> duplicates, case, whitespace and malformed lines, and those details are exactly what you test
> (for example duplicate `Content-Length` for request smuggling). Ranges keep the parse "view" while
> the bytes stay intact.

### Parser tolerance rules (HTTP/1)

- Accept both CRLF and bare LF; record which was used.
- Accept obsolete line folding (whitespace-prefixed continuation lines); flag a warning.
- Never reject a message in the editor. If parsing fails, show the raw text with a warning banner,
  and the user can still send it.
- Body framing for *display* uses the headers; *sending* never re-frames unless "Update
  Content-Length" or "Normalize framing" is on.

## 3. HTTP/2 representation

HTTP/2 messages are shown and edited as HTTP/1-style text:

```
GET /path?q=1 HTTP/2
Host: example.com            ← maps to :authority
User-Agent: …
```

- Pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) are derived from the request line and
  `Host`. They can be edited individually in the Inspector ("HTTP/2 pseudo-headers" section) to
  create values that can't be expressed in HTTP/1 (for example a `:path` containing a space, or a
  header value containing CRLF).
- When the Inspector holds values like that, the message is marked **non-representable**: the
  editor shows a banner, and the engine sends from the structured form (`H2RequestSpec`) instead of
  re-parsing the text.

```swift
// A header field for H2 raw mode. Named struct, NOT a tuple: Swift cannot synthesize Codable
// for tuples or arrays of tuples, so the fields below must be a Codable element type.
public struct H2Field: Sendable, Codable, Hashable {
    public var name: Bytes      // bytes so illegal-in-H1 names (uppercase, etc.) are representable
    public var value: Bytes
}

public struct H2RequestSpec: Sendable, Codable {
    public var pseudoHeaders: [H2Field]   // ordered; e.g. :method :scheme :authority :path
    public var headers: [H2Field]         // ordered, case preserved (lowercased on wire unless "raw case")
    public var body: Bytes
    public var dataFrameSplit: [Int]?     // optional: split body into DATA frames of these sizes
}
```

## 4. SQLite schema (GulpStore, schema version 1)

A project is **one SQLite file** with the extension `.gulp`, opened in WAL mode
(`PRAGMA journal_mode=WAL; synchronous=NORMAL; foreign_keys=ON`).

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);       -- schema_version, project_uuid, created_at, app_version

CREATE TABLE blobs (                                                  -- message bodies and raw bytes
  id INTEGER PRIMARY KEY,
  sha256 BLOB NOT NULL UNIQUE,                                        -- dedup identical blobs
  size INTEGER NOT NULL,
  compression INTEGER NOT NULL DEFAULT 0,                             -- 0 none, 1 zlib (used when size > 4 KB and it saves ≥ 10 %)
  data BLOB NOT NULL
);

CREATE TABLE exchanges (
  id INTEGER PRIMARY KEY,                                             -- ExchangeID, monotonic = proxy history "#"
  source TEXT NOT NULL,                                               -- ToolSource raw value
  created_at REAL NOT NULL,                                           -- unix seconds
  scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
  ip TEXT, sni TEXT,
  http_version TEXT NOT NULL,
  method TEXT, path TEXT, query TEXT,                                 -- derived, for indexing/filtering
  request_blob INTEGER NOT NULL REFERENCES blobs(id),
  response_blob INTEGER REFERENCES blobs(id),
  original_request_blob INTEGER REFERENCES blobs(id),                 -- set if edited
  original_response_blob INTEGER REFERENCES blobs(id),
  status INTEGER, response_length INTEGER, mime TEXT, title TEXT,
  state TEXT NOT NULL, error TEXT,
  timing_json TEXT, tls_json TEXT,
  connection_id INTEGER, client_address TEXT,
  in_scope INTEGER NOT NULL DEFAULT 0,                                -- cached; recomputed on scope change
  highlight TEXT, comment TEXT,
  param_count INTEGER, has_cookies INTEGER, sets_cookies INTEGER,
  extension TEXT                                                      -- file extension of the path, for filters
);
CREATE INDEX ix_ex_source_id ON exchanges(source, id);
CREATE INDEX ix_ex_host ON exchanges(host, port, scheme);
CREATE INDEX ix_ex_status ON exchanges(status);
CREATE INDEX ix_ex_scope ON exchanges(in_scope, id);

CREATE TABLE exchange_tags (exchange_id INTEGER REFERENCES exchanges(id) ON DELETE CASCADE, tag TEXT, PRIMARY KEY(exchange_id, tag));

CREATE TABLE ws_connections (id INTEGER PRIMARY KEY, upgrade_exchange_id INTEGER REFERENCES exchanges(id), url TEXT, opened_at REAL, closed_at REAL, close_code INTEGER);
CREATE TABLE ws_messages (
  id INTEGER PRIMARY KEY, connection_id INTEGER REFERENCES ws_connections(id) ON DELETE CASCADE,
  direction INTEGER NOT NULL,              -- 0 client→server, 1 server→client
  opcode INTEGER NOT NULL, created_at REAL NOT NULL,
  payload_blob INTEGER REFERENCES blobs(id), original_payload_blob INTEGER REFERENCES blobs(id),
  length INTEGER, highlight TEXT, comment TEXT,
  frames_json TEXT                         -- per-message frame boundaries (offsets, fin bits, rsv/compression) for PRX-031
);

CREATE VIRTUAL TABLE fts_exchanges USING fts5(request_text, response_text, content='', contentless_delete=1, tokenize='trigram');
-- contentless with delete support (SQLite >= 3.43); rowid = exchanges.id, supplied on insert.
-- Bodies truncated to the first 256 KB per message for indexing. On older SQLite, drop
-- contentless_delete and rebuild the index instead of deleting rows (see the FTS note below).

CREATE TABLE scope_rules (id INTEGER PRIMARY KEY, kind TEXT CHECK(kind IN ('include','exclude')), enabled INTEGER, protocol TEXT, host_regex TEXT, port TEXT, path_regex TEXT, ordinal INTEGER);

CREATE TABLE issues (
  id INTEGER PRIMARY KEY, type_id TEXT NOT NULL, name TEXT NOT NULL,
  severity TEXT NOT NULL, confidence TEXT NOT NULL,
  host TEXT NOT NULL, path TEXT NOT NULL, insertion_point TEXT,
  dedup_key TEXT NOT NULL UNIQUE,
  detail_md TEXT, background_md TEXT, remediation_md TEXT, references_md TEXT,   -- references_md backs SCN-001's "references"
  status TEXT NOT NULL DEFAULT 'open',      -- open | false_positive | accepted_risk | fixed (SCN-001 uses these exact tokens)
  source_task_id INTEGER, created_at REAL, updated_at REAL
);
CREATE TABLE issue_evidence (id INTEGER PRIMARY KEY, issue_id INTEGER REFERENCES issues(id) ON DELETE CASCADE, exchange_id INTEGER REFERENCES exchanges(id), request_markers_json TEXT, response_markers_json TEXT, oast_interaction_id INTEGER, note TEXT);

CREATE TABLE tasks (id INTEGER PRIMARY KEY, kind TEXT, name TEXT, config_json TEXT, state TEXT, progress_json TEXT, created_at REAL, finished_at REAL);
CREATE TABLE task_log (id INTEGER PRIMARY KEY, task_id INTEGER REFERENCES tasks(id) ON DELETE CASCADE, at REAL, level TEXT, message TEXT);

CREATE TABLE repeater_tabs (id INTEGER PRIMARY KEY, title TEXT, group_id INTEGER, ordinal INTEGER, target_json TEXT, options_json TEXT, draft_blob INTEGER REFERENCES blobs(id));
CREATE TABLE repeater_groups (id INTEGER PRIMARY KEY, name TEXT, color TEXT, send_mode TEXT);
CREATE TABLE repeater_history (id INTEGER PRIMARY KEY, tab_id INTEGER REFERENCES repeater_tabs(id) ON DELETE CASCADE, exchange_id INTEGER REFERENCES exchanges(id), ordinal INTEGER);

CREATE TABLE fuzzer_attacks (id INTEGER PRIMARY KEY, name TEXT, config_json TEXT, base_request_blob INTEGER, state TEXT, created_at REAL);
CREATE TABLE fuzzer_results (attack_id INTEGER REFERENCES fuzzer_attacks(id) ON DELETE CASCADE, seq INTEGER, payloads_json TEXT, exchange_id INTEGER, status INTEGER, length INTEGER, time_ms INTEGER, grep_json TEXT, PRIMARY KEY(attack_id, seq));

CREATE TABLE oast_payloads (id INTEGER PRIMARY KEY, correlation_id TEXT UNIQUE, created_at REAL, context_json TEXT);   -- which tool, exchange and insertion point used it
CREATE TABLE oast_interactions (id INTEGER PRIMARY KEY, payload_id INTEGER REFERENCES oast_payloads(id), protocol TEXT, remote_address TEXT, at REAL, raw_blob INTEGER, summary TEXT);

CREATE TABLE notebook_items (
  id INTEGER PRIMARY KEY, kind TEXT,                                 -- kind: 'exchange' | 'note'
  exchange_id INTEGER REFERENCES exchanges(id) ON DELETE SET NULL,   -- optional back-ref to the live exchange
  request_blob INTEGER REFERENCES blobs(id),                         -- snapshot (NB-001), independent of history edits/deletion
  response_blob INTEGER REFERENCES blobs(id),
  target_json TEXT,                                                  -- scheme/host/port so the snapshot can be re-sent
  title TEXT, status TEXT, body_md TEXT, tags TEXT, highlight TEXT,  -- tags = JSON array (NB-003)
  issue_id INTEGER REFERENCES issues(id) ON DELETE SET NULL,         -- NB-005 link
  created_at REAL, updated_at REAL, ordinal INTEGER
);

CREATE TABLE cookie_jar (domain TEXT, path TEXT, name TEXT, value TEXT, expires REAL, secure INTEGER, http_only INTEGER, same_site TEXT, identity_id INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(domain, path, name, identity_id));
-- identity_id is NOT NULL (0 = "no identity") because SQLite treats NULLs in a PRIMARY KEY as
-- distinct, which would let duplicate no-identity cookies accumulate instead of being replaced.
CREATE TABLE identities (id INTEGER PRIMARY KEY, name TEXT, color TEXT, config_json TEXT);       -- Authz Matrix, sessions
CREATE TABLE macros (id INTEGER PRIMARY KEY, name TEXT, steps_json TEXT);
CREATE TABLE session_rules (id INTEGER PRIMARY KEY, name TEXT, enabled INTEGER, ordinal INTEGER, config_json TEXT);

CREATE TABLE sequencer_runs (id INTEGER PRIMARY KEY, name TEXT, config_json TEXT, tokens_blob INTEGER, results_json TEXT, created_at REAL);

CREATE TABLE settings (scope TEXT, key TEXT, value_json TEXT, PRIMARY KEY(scope, key));      -- project-level settings
CREATE TABLE extension_state (extension_id TEXT, key TEXT, value BLOB, PRIMARY KEY(extension_id, key));
```

### Post-1.0 expansion tables (Phase F, migration v2+)

These back the Phase F features (F30 Drift & Retest, F31 Journal). They ship as **two** later additive
migrations, not in schema v1, so each lands with its feature under the "never edit a shipped
migration" rule: `v2_journal` at M9/M16 (the `journal_*` tables) and `v3_drift` at M25 (the `drift_*`,
`issue_proofs`, `retest_runs` tables). Defined here together so the schema stays centralized.

```sql
-- F30 Drift & Retest -------------------------------------------------------
CREATE TABLE drift_baselines (id INTEGER PRIMARY KEY, name TEXT, created_at REAL, scope_json TEXT);
CREATE TABLE drift_endpoints (                                 -- immutable per-endpoint snapshot (DRF-001)
  id INTEGER PRIMARY KEY, baseline_id INTEGER REFERENCES drift_baselines(id) ON DELETE CASCADE,
  target_json TEXT, request_blob INTEGER REFERENCES blobs(id), response_blob INTEGER REFERENCES blobs(id),
  facts_json TEXT, mask_json TEXT                              -- extracted facts + per-endpoint noise masks (DRF-006)
);
CREATE TABLE drift_runs (id INTEGER PRIMARY KEY, baseline_id INTEGER REFERENCES drift_baselines(id) ON DELETE CASCADE, run_at REAL);
CREATE TABLE drift_results (                                   -- one row per endpoint per run (DRF-004)
  id INTEGER PRIMARY KEY,
  run_id INTEGER REFERENCES drift_runs(id) ON DELETE CASCADE,
  endpoint_id INTEGER REFERENCES drift_endpoints(id),          -- NULL for a `new` endpoint (no baseline row yet)
  target_json TEXT,                                            -- identity of the endpoint even when endpoint_id is NULL (`new`)
  status TEXT,                                                 -- unchanged | changed | new | removed | error
  sample_request_blob INTEGER REFERENCES blobs(id), sample_response_blob INTEGER REFERENCES blobs(id),
  diff_json TEXT
);  -- a surrogate id + target_json so `new` endpoints (DRF-004) are first-class, not an implicit NULL-PK row.
CREATE TABLE issue_proofs (                                    -- replayable proof per issue (DRF-003)
  id INTEGER PRIMARY KEY, issue_id INTEGER REFERENCES issues(id) ON DELETE CASCADE,
  target_json TEXT, request_blob INTEGER REFERENCES blobs(id),
  steps_json TEXT,                                             -- ordered extra requests for multi-step proofs (smuggling/race/chains); request_blob is the primary one
  identity_id INTEGER REFERENCES identities(id),               -- replay under a specific identity (DRF-008); NULL = scope-matched session rules
  matcher_json TEXT, created_at REAL
);
CREATE TABLE retest_runs (                                     -- per-issue retest history (DRF-005)
  id INTEGER PRIMARY KEY, issue_id INTEGER REFERENCES issues(id) ON DELETE CASCADE, run_at REAL,
  verdict TEXT,                                                -- fixed | still_vulnerable | changed | needs_review
  evidence_exchange_id INTEGER REFERENCES exchanges(id), note TEXT
);  -- the verdict axis is retest-run history; issues.status is updated from it, not replaced by it.

-- F31 Journal (coverage index is derived/rebuildable; only these need persistence) ---------------
CREATE TABLE journal_checklists (                              -- per-endpoint methodology goals (JRN-006)
  id INTEGER PRIMARY KEY, host TEXT, endpoint_key TEXT, category TEXT, done INTEGER NOT NULL DEFAULT 0, note TEXT
);
CREATE TABLE journal_markers (id INTEGER PRIMARY KEY, at REAL, label TEXT, note TEXT);  -- timeline pins (JRN-008)
```

### Notes

- **Migrations**: use GRDB's `DatabaseMigrator`, one registered migration per schema change, named
  `vN_description`. Never edit a migration that has shipped.
- **Blob dedup**: identical responses (static assets) are stored once. A periodic vacuum task
  (`Project → Compact`) removes unreferenced blobs. Its reference walk must enumerate **every**
  blob-referencing column, not a hardcoded v1 list — including the Phase F ones
  (`drift_endpoints.request_blob`/`response_blob`, `drift_results.sample_request_blob`/
  `sample_response_blob`, `issue_proofs.request_blob`) — or it would vacuum the immutable snapshots
  F30 promises. Derive the column list from the schema (or keep it beside the migration that adds
  each blob column).
- **Write coalescer**: `StoreWriter` actor gathers `PendingWrite`s and flushes them in one
  transaction every 50 ms or 500 items. A crash loses at most the last 50 ms of traffic; for proxy
  traffic that is acceptable, and the Settings "Durable mode" flushes on every write.
- **FTS**: the trigram tokenizer gives substring search (`LIKE '%abc%'` semantics) in milliseconds,
  but it only matches queries of **3+ characters** — 1–2 char queries can't use the index and fall
  back to a bounded `LIKE`/scan with progress (F05 HIS-052). Index only text-like MIME types.
  Indexing runs on a background queue after the insert. Bodies are indexed to the first 256 KB (this
  is deliberately smaller than the 2 MB cap used for in-memory body regex in F05 — the index favors
  breadth over completeness; full-fidelity matching uses the regex/scan path). The table uses
  `contentless_delete=1` (SQLite ≥ 3.43) so rows can be deleted when exchanges are deleted — both the
  macOS 14 system SQLite and the Linux CI image (`swift:6.0-noble`) satisfy that, so it is the
  baseline, not a special case. Only if a build ever targets an older SQLite, drop the option and
  rebuild the index after deletes.
- **Temporary projects** use a file in `~/Library/Caches/Gulp/temp-<uuid>.gulp`, which is deleted on
  close unless the user saves it.

## 5. User-level storage (outside projects)

| What | Where |
|---|---|
| User settings | `~/Library/Application Support/Gulp/user-settings.json` (Codable, versioned) |
| CA certificate and key | Keychain (label `Gulp CA`); a cert copy in `~/Library/Application Support/Gulp/ca/gulp-ca.pem` |
| Leaf certificate cache | In memory (LRU, 2,000 entries); optional on-disk cache in `…/Gulp/certs/` |
| Installed extensions | `~/Library/Application Support/Gulp/extensions/<id>/` |
| Wordlists | `~/Library/Application Support/Gulp/wordlists/` (bundled lists are copied here on first run) |
| Check Recipes | `~/Library/Application Support/Gulp/recipes/` |
| Managed browser | `~/Library/Application Support/Gulp/browser/` (Chrome for Testing) and `…/browser-profile/` |
| API keys (AI, Beacon) | Keychain |
| Logs | `~/Library/Logs/Gulp/` |

## 6. Settings model

```swift
public protocol SettingsGroup: Codable, Sendable { static var key: String { get }; static var defaultValue: Self { get } }
// Examples: ProxySettings, TLSSettings, HTTPEngineSettings, ScannerDefaults, UISettings, AISettings…

public final class LayeredSettings: Sendable {
    // Lookup order: project override → user setting → default
    public func get<G: SettingsGroup>(_: G.Type) -> G
    public func set<G: SettingsGroup>(_ value: G, scope: SettingsScope)   // .user or .project
}
```

Settings can be exported and imported as JSON (`Settings → Export…`). Every settings group carries
a `version`, with a decoding fallback to defaults for unknown or missing keys.
