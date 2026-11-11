# F03 — HTTP engine

> Milestones: M1 (HTTP/1), M3 (HTTP/2), M5 (raw H2, race-condition modes), M11a (shared limiter,
> §3.4) · Module: `GulpHTTP` ·
> Depends on: GulpCore, GulpTLS

## 1. Purpose

Every request any tool sends (Proxy upstream, Repeater, Fuzzer, Scanner, Crawler, extensions, the
automation API) goes through one engine. The engine sends **exactly** the bytes it is given, handles
connections efficiently, and supports advanced timing attacks.

## 2. Public API

```swift
public struct SendOptions: Sendable {
    public var httpVersion: HTTPVersionPreference = .auto        // .auto (ALPN), .http1_1, .http2, .http2PriorKnowledge(h2c)
    public var connection: ConnectionPolicy = .reuse              // .reuse, .new, .newAndClose
    public var followRedirects: RedirectPolicy = .never           // .never, .onSite, .inScope, .always (+ maxHops, + process cookies)
    public var updateContentLength = false
    public var normalizeLineEndings = false
    public var timeouts = Timeouts()   // all phases of HTTP-005 (see type below)
    public var maxResponseBytes = 50 * 1024 * 1024
    public var decompressForHooks = true
    public var tlsProfile: TLSProfile? = nil
    public var upstreamProxy: UpstreamProxyOverride = .useRules
    public var applyHooks: HookSet = .all                          // which RequestHooks run (sessions, tags, extensions…)
    public var recordAs: ToolSource
}

public protocol HTTPEngine: Sendable {
    func send(_ request: RawRequest, to target: HTTPTarget, options: SendOptions) async -> ExchangeResult
    func send(_ request: H2RequestSpec, to target: HTTPTarget, options: SendOptions) async -> ExchangeResult
    func sendGroup(_ items: [GroupItem], mode: GroupSendMode, options: SendOptions) async -> [ExchangeResult]
    func openWebSocket(_ upgrade: RawRequest, to target: HTTPTarget, options: SendOptions) async throws -> WebSocketSession
}

public enum GroupSendMode: Sendable { case sequentialSingleConnection, sequentialSeparateConnections, parallel, singlePacket }
```

Supporting types for the API above:

```swift
public struct Timeouts: Sendable {                 // every phase named by HTTP-005
    public var connect: Duration = .seconds(10)
    public var tlsHandshake: Duration = .seconds(10)
    public var firstByte: Duration = .seconds(30)
    public var idleBetweenBytes: Duration = .seconds(30)
    public var total: Duration = .seconds(120)
}
public struct ExchangeResult: Sendable {
    public var exchange: Exchange                  // the final record (recorded per options.recordAs)
    public var redirectChain: [Exchange]           // empty unless followRedirects produced hops
    public var error: GulpNetworkError?            // nil on success; also reflected in exchange.state
}
public struct GroupItem: Sendable {                // one request in a group send (F03 §3.3)
    public var request: RawRequest
    public var target: HTTPTarget
}
```

`WebSocketSession` is the live-socket handle returned by `openWebSocket`; its full surface (send/
receive frames, close, reconnect) is specified in F01 §2.4 / F06 REP-012 — for M1 the `openWebSocket` method
and `WebSocketSession` type are declared but not implemented (WebSockets are M4b), so in M1 calling
`openWebSocket` throws `GulpError(message: "WebSockets are implemented in M4", underlying: nil)` (the
message predates the M4a/M4b split; WebSockets are M4b).
Because `openWebSocket` lives on the engine, the WebSocket frame codec (RFC 6455 framing +
permessage-deflate) is implemented **in `GulpHTTP`** when WebSockets land at M4b — not in a
higher-layer module. `GulpProxy`, the WS Repeater (F06 REP-012), the post-1.0 WS Fuzzer (F07 §2.6)
and any other consumer use that one codec; nothing lower than `GulpHTTP` needs it, so there is no
upward import (doc 01 §3).

`ExchangeResult` contains the final `Exchange` (recorded or not, depending on options), the redirect
chain if one was followed, and timing.

## 3. Requirements

### 3.1 HTTP/1.x

| ID | Pri | Requirement |
|---|---|---|
| HTTP-001 | P0 | Write raw request bytes to TCP or TLS as given. No header injection, no reordering, no case changes. |
| HTTP-002 | P0 | Response framing per RFC 9112: status 1xx (skip interim responses but record them), HEAD, 204, 304 → no body; `Transfer-Encoding: chunked` (keep the raw chunked bytes; provide a de-chunked view); `Content-Length`; otherwise read until close. Handle trailers. |
| HTTP-003 | P0 | Connection pool keyed by (scheme, host, port, SNI, IP override, TLS profile, upstream proxy, client cert). Idle timeout 30 s, max 6 connections per key by default (configurable per tool; governed active-tool sends lift it and are bounded by the GOV-003 per-host budget instead, 2026-11-11). Validate a pooled connection is still open before reuse; retry once on a stale connection *only* if no bytes of the response were read and the method is idempotent (or the user opted in). |
| HTTP-004 | P0 | DNS resolution with an override table (Settings → Network → Hostname resolution: host → IP) and a per-target `ipOverride`. Support IPv4/IPv6 (happy eyeballs is acceptable but not required). |
| HTTP-005 | P0 | Timeouts: connect, TLS handshake, first byte, total, idle-between-bytes. Every timeout produces a typed error recorded in the exchange. |
| HTTP-006 | P0 | Upstream proxies: HTTP CONNECT (with basic auth), plain HTTP proxy (absolute-form rewrite, only when the request is plain HTTP), SOCKS5 (NIOSOCKS client). Rules from PRX-041. |
| HTTP-007 | P0 | Decompression helpers (gzip/deflate via zlib, brotli, zstd) for hooks and views; the raw response is always kept compressed as received. |
| HTTP-008 | P0 | "Update Content-Length" option: recompute it from the body if the header exists (add it if missing and the method normally carries a body). Never touch it when off. |
| HTTP-009 | P0 | Cancellation: cancelling the Swift task closes the channel and records `.failed(.cancelled)`. |
| HTTP-010 | P0 | Timing breakdown: DNS, connect, TLS, request write, time to first byte, download, total. |
| HTTP-011 | P1 | HTTP/1 pipelining API for Turbo mode (F07): write N requests on one connection back to back and read N responses in order. |
| HTTP-012 | P1 | Platform authentication (Basic, Digest, NTLMv2) per host as a hook: auto-responds to `401` challenges (NTLM needs connection affinity). |
| HTTP-013 | P1 | Throttling: a global and per-host requests-per-second cap shared by every tool (token bucket), so the user can protect fragile targets. Extended in M11a with concurrency budgets and adaptive backoff (§3.4). |

### 3.2 HTTP/2

| ID | Pri | Requirement |
|---|---|---|
| HTTP-020 | P0 | ALPN negotiation (`h2`, `http/1.1`) and HTTP/2 prior knowledge (h2c) support. |
| HTTP-021 | P0 | Convert an HTTP/1-style editor message to HTTP/2 (doc 04 §3): request line → pseudo-headers, `Host` → `:authority`, drop connection-specific headers (`Connection`, `Keep-Alive`, `Upgrade`, `Proxy-Connection`, `Transfer-Encoding: chunked` unless the user explicitly keeps it — which is an attack, see ADV smuggling), normalize `TE` (in h2 its only legal value is `trailers`; drop otherwise), lowercase names unless "raw case". |
| HTTP-022 | P0 | Responses from HTTP/2 are stored in the HTTP/1-style text form `HTTP/2 200` + headers + body (DATA frames concatenated), and the frame list is kept when "keep frames" is on. |
| HTTP-023 | P0 | One HTTP/2 connection per pool key, multiplexing streams (respect `SETTINGS_MAX_CONCURRENT_STREAMS`). |
| HTTP-024 | P0 | Handle `GOAWAY`, `RST_STREAM`, flow control (window updates for large downloads), server push (refuse via SETTINGS_ENABLE_PUSH=0). |
| HTTP-027 | P0 | HTTP/2 **trailers** (a HEADERS frame after DATA): keep them in the stored response (appended after the body in the HTTP/1-style form, as chunked trailers would be) and forward them through the proxy. gRPC carries `grpc-status`/`grpc-message` there, so dropping trailers breaks every proxied gRPC call. (Added by the 2026-11-07 feature review.) |
| HTTP-025 | P1 | Header names/values that are illegal in HTTP/1 (CR, LF, colon in names, uppercase) can be sent when the `H2RequestSpec` asks for them. The stock `NIOHTTP2Handler`/inline multiplexer enforce RFC 9113 header rules via the connection state machine and expose **no** public toggle to disable that in released versions, so raw mode drives the **low-level `HTTP2FrameEncoder` + HPACK encoder** directly (emit raw `HEADERS`/`DATA` frames, bypassing the normalizing state machine). Verify against the pinned `swift-nio-http2` version; do **not** assume a `headerValidation`/`contentLengthValidation` option on the normal handler. This path is what makes raw-H2 smuggling tests (ADV) and extended CONNECT (PRX-030) possible, since stock validation would reject `:protocol` and illegal headers. |
| HTTP-026 | P1 | Show HTTP/2 connection-level events (SETTINGS, GOAWAY codes) in the Logger's connection detail. |

### 3.3 Group sends and race conditions

| ID | Pri | Requirement |
|---|---|---|
| HTTP-030 | P0 | `sequentialSingleConnection`: send the items in order on one connection (keep-alive), each after the previous response. |
| HTTP-031 | P0 | `sequentialSeparateConnections`: in order, a new connection each. |
| HTTP-032 | P0 | `parallel`: all at once with independent connections (or streams). |
| HTTP-033 | P0 | `singlePacket` over HTTP/2: open one connection; for each request, send HEADERS plus all DATA except the final frame (keep at least 1 byte of body back; for GET requests send HEADERS without END_STREAM and hold an empty DATA frame with END_STREAM); wait ~100 ms (configurable warm-up, optionally with a PING to warm the connection); then write all withheld final frames into the channel and **flush once** so they leave in as few packets as possible (ideally one). Set `TCP_NODELAY`; over TLS the frames are coalesced into one `write` so they share a TLS record where size allows. This is best-effort — the OS may still split — so keep the combined final bytes small (aim under ~1,400 bytes, under one MSS) and surface the measured send spread (HTTP-035) rather than assuming a single segment. |
| HTTP-034 | P0 | `singlePacket` fallback for HTTP/1 (**last-byte sync**): open N connections, send each request except its last byte, wait, then send the last bytes on all connections as close together as possible (send them from one event loop iteration). |
| HTTP-035 | P1 | Group timing report: per-request send timestamp and response start, and the spread (max − min) of the final-byte writes. |
| HTTP-036 | P1 | Set `TCP_NODELAY` on (Nagle off) for all connections, and an option to set it off for experiments. |

> **Concept: the single-packet attack.** Race-condition bugs need requests that reach the server at
> nearly the same instant. Network jitter normally spreads parallel requests over milliseconds.
> Putting the *completing* bytes of 20–30 requests into one TCP packet removes that jitter, because
> the server receives them all at once and processes them concurrently. HTTP/2 makes it practical,
> since many requests share one connection. For HTTP/1, "last-byte sync" across several connections
> gets close.

### 3.4 Shared limiter and adaptive backoff (moved from F29 Governor, 2026-11-08)

The Governor (F29) was merged: its limiter is HTTP-013 extended here, and its panic stop and
throughput panel are workspace features (F20 §2.4). Every active tool draws from this **one**
`GulpHTTP` limiter — there is no second, parallel one. *(M11a, when the first active tools ship.)*

| ID | Pri | Requirement |
|---|---|---|
| GOV-002 | P0 | **Global caps**: max total concurrent outbound connections and max requests/sec across *all* tools. This **is** the HTTP-013 shared token bucket, extended with a global concurrency semaphore; every active tool draws from it. *(Moved from F29; M11a.)* |
| GOV-003 | P0 | **Per-host budgets**: per-host req/s (from HTTP-013) **plus** a per-host concurrency limit, shared across tools so Scanner + Fuzzer hitting one host can't collectively overrun it; conservative defaults, overridable per host. A per-host cap of 0 blocks a host for active tools (document it). *(Moved from F29; M11a.)* |
| GOV-007 | P1 | **Adaptive backoff**: automatically reduce a host's rate when it returns a burst of 429/503/timeouts, with a visible "throttled" badge and a manual override; restore the rate as the host recovers. Supersedes the per-tool hints (FUZ-034, the Scanner's WAF back-off) with one shared mechanism. *(Moved from F29; M11a.)* |

### 3.5 HTTP/3 (post-1.0)

| ID | Pri | Requirement |
|---|---|---|
| HTTP-037 | P2 | **HTTP/3 upstream client** for Repeater sends (QUIC, `h3` ALPN) and an "`Alt-Svc: h3` advertised" flag on history rows, so testers notice HTTP/3-only behavior. HTTP/3 **interception** stays a non-goal (doc 00 §3): the Gulp Browser disables QUIC. *(Added by the 2026-11-08 feature review, A9; post-1.0 — see the roadmap's Post-1.0 backlog.)* |

## 4. Implementation notes

- Channel pipeline for an HTTP/1 client connection: `[TLS?] → RawResponseFramer → EngineConnectionHandler`.
  Write the request with `channel.writeAndFlush(ByteBuffer(bytes: request))` (no NIOHTTP1 encoder).
- **HEAD framing is an engine-layer decision, not a parser one.** `GulpCore`'s stateless
  `HTTP1.parseResponse` frames a response from the response bytes alone and so can only recognize the
  self-evident bodyless cases (1xx, 204, 304). A HEAD response carries body-framing headers
  (`Content-Length`/`Transfer-Encoding`) describing the body the GET *would* have had, but there is
  no body — only the engine, which knows the request method, may override the framing to "no body"
  and must **not** wait for `Content-Length` bytes. The `RawResponseFramer` is told the method when it
  is created; it treats a HEAD response as framed-complete at the header block.
- Use `NIOAsyncChannel` to bridge to async/await, or write the handlers directly with promises
  where performance matters (Turbo mode).
- HTTP/2: `NIOHTTP2Handler(mode: .client)` with the inline stream multiplexer
  (`configureAsyncHTTP2Pipeline` or `configureHTTP2Pipeline`). Send `HTTP2Frame.FramePayload.headers`
  and `.data` on stream channels yourself (don't use `HTTP2FramePayloadToHTTP1ClientCodec`, because
  it normalizes). For raw mode (HTTP-025) drop to `HTTP2FrameEncoder`/HPACK so illegal headers,
  `:protocol` (extended CONNECT, PRX-030) and smuggling shapes aren't rejected by the state machine.
- Single-packet coalescing (HTTP-033): `write()` the withheld final frame to each stream child
  channel **without flushing**, then call `flush()` on the **parent** connection channel exactly
  once — per-child flushes defeat coalescing. If the server's `SETTINGS_MAX_CONCURRENT_STREAMS`
  (HTTP-024) is below the group size, not all streams can be in flight at once and the single-packet
  effect degrades: detect this, warn, and fall back to the HTTP/1 last-byte-sync mode (HTTP-034).
- Hooks pipeline (`RequestHook` protocol): `func willSend(_ req: inout OutgoingRequest, context: HookContext) async throws`.
  Order: session rules (F15) → transform tags (F12) → match & replace (tool flag) → extensions
  (F18) → content-length fixer → request signing (F15 SES-016…018, when a signing action applies —
  last, so the signature covers the exact bytes sent). `ResponseHook`: extensions → session cookie
  jar update.
- Record every send through `ExchangeRecorder` with `source = options.recordAs`.
- Shared limiter (§3.4): a `ResourcePool` in `GulpHTTP` — a token bucket for rate and a semaphore for
  concurrency, keyed global + per-host. Active tools already call `ScopeGuard.require` before sending
  (F04 TGT-023); the limiter sits at the **same gate** (`acquire()` before send, `release()` after).
  The workspace panic stop (F20 GOV-001) flips a shared `paused` flag the pool checks and cancels
  in-flight permits; tasks observe cancellation (HTTP-009) and move to Paused. Backoff (GOV-007)
  watches status/latency per host and shrinks that host's bucket. The hot path must add negligible
  overhead (lock-free or striped counters).

## 5. Edge cases

- A server that closes right after sending the headers without a body when one is declared → record
  a partial response with an "incomplete" flag.
- A request with no CRLFCRLF terminator: send it as is (the user may want this), and show a warning
  in the editor (not here).
- A response bigger than `maxResponseBytes`: truncate the stored body, set a flag, and close the
  connection (don't reuse it).
- HTTP/2 server sends a `RST_STREAM(REFUSED_STREAM)` → retry once on a new connection if it is safe.

## 6. Acceptance tests

1. Byte-exact: send a request with mixed-case duplicate headers and bare LF to VulnLab's raw
   `/echo-raw` listener → the server receives identical bytes.
2. Chunked, gzip, 1xx, HEAD and 304 fixtures frame correctly (no hangs; a 5-second test timeout).
3. Pool: 100 sequential sends to the same host use 1 connection (check the connection ids).
4. HTTP/2: 50 parallel streams on one connection; `GOAWAY` mid-flight → the unfinished streams are
   retried or reported.
5. Group send: `sendGroup` in each `GroupSendMode` returns one result per item, in order, with per-item timing recorded.
6. Shared limiter (moved from F29): a Fuzzer configured for 2,000 req/s plus a concurrent crawl never
   exceed a 1,000 req/s global cap in aggregate (measured), and two tools targeting one host share a
   50-concurrency budget (combined in-flight ≤ 50).
7. Backoff (moved from F29): a VulnLab endpoint returning 503 bursts (`/status/503`) drives the
   measured send rate down and flips the throttled badge, then recovers.
