# F01 — Proxy

> Milestones: M2 (plain HTTP), M3 (TLS), M4 (intercept, match & replace, WebSockets) ·
> Modules: `GulpProxy`, `GulpFeatures/Proxy` · Depends on: F02, F03, F05, F20

## 1. Purpose

The proxy is the heart of Gulp. Clients (the Gulp Browser, the system browser, mobile devices,
simulators, CLI tools) send traffic through it. Gulp records everything, can pause messages for
editing (intercept), rewrite them automatically (match & replace), and feeds the other tools.

## 2. Requirements

### 2.1 Listeners and basic forwarding

| ID | Pri | Requirement |
|---|---|---|
| PRX-001 | P0 | One or more listeners, each with bind address (default `127.0.0.1`), port (default `8080`), enabled flag. Start/stop live. Show bind errors (port in use) in the UI. |
| PRX-002 | P0 | HTTP/1.x forward proxying of absolute-form requests (`GET http://host/path HTTP/1.1`): convert to origin-form for the upstream request, preserving every other byte. |
| PRX-003 | P0 | Client keep-alive and upstream connection reuse via the HTTP engine pool (F03). |
| PRX-004 | P0 | Record every exchange (`source = .proxy`) with timing, client address and connection id; emit `exchangeRecorded`. |
| PRX-005 | P0 | `CONNECT host:port` handling: reply `HTTP/1.1 200 Connection established`, then decide between MITM and pass-through (PRX-007). |
| PRX-006 | P0 | MITM TLS: sniff the ClientHello for SNI (fall back to the CONNECT host), get a leaf certificate from GulpTLS, terminate TLS, then parse HTTP inside. |
| PRX-007 | P0 | TLS pass-through list (host/port regex): splice bytes without decrypting (useful for pinned apps or out-of-scope hosts). Record a "tunnel" entry (host, bytes in/out) in the Logger. |
| PRX-008 | P0 | ALPN mirroring: before finishing the client handshake, open (or reuse) an upstream TLS connection offering the client's ALPN list; offer the client only the protocol the server chose (`h2` or `http/1.1`). Settings toggle: "Force HTTP/1.1 to client" and "Force HTTP/1.1 to server". |
| PRX-009 | P0 | HTTP/2 between client and proxy (`swift-nio-http2` server side). Each stream becomes one exchange. |
| PRX-040 | P1 | **Invisible proxy mode** per listener: accept non-proxy-aware clients (origin-form requests). Use the `Host` header (HTTP) or SNI (TLS) to pick the target. Optional "redirect to host:port" per listener. |
| PRX-041 | P1 | **Upstream proxy rules**: ordered list of (host pattern → HTTP/HTTPS or SOCKS5 upstream proxy, optional auth). Applies to every tool via F03. |
| PRX-042 | P1 | **SOCKS5 listener** mode (no auth or user/pass), so clients that only speak SOCKS can be proxied. |
| PRX-043 | P1 | Per-listener certificate options: per-host CA-signed (default), self-signed per host, a specific certificate (PKCS#12 import), or a "named host" certificate. |
| PRX-044 | P1 | Strip/neutralize options (response side): remove `Strict-Transport-Security`, remove `Content-Security-Policy`, remove `Secure` from cookies, unhide hidden form fields (and highlight them), enable disabled fields, remove JS form validation (`novalidate`), convert HTTPS links to HTTP (off by default). |
| PRX-045 | P1 | "Don't send items to Proxy history or live tasks if out of scope" toggle. |
| PRX-046 | P1 | Built-in landing page at `http://gulp/` (when browsing through the proxy) with CA download (`/cert.pem`, `/cert.der`) and a status page. |
| PRX-047 | P2 | Request/response size limits and timeouts per listener; graceful overload handling (503 from proxy with a clear body). |
| PRX-048 | P2 | Listen on a Unix domain socket (for local tools that support it). |

### 2.2 Intercept

| ID | Pri | Requirement |
|---|---|---|
| PRX-010 | P0 | Global intercept toggle (toolbar + ⌘⇧I). When on, matching requests are held in an **intercept queue**. |
| PRX-011 | P0 | Intercept UI: queue list (method, URL, time waiting) and the selected message in an editable MessageEditor with Inspector. Actions: Forward (⌥⌘F), Drop (⌥⌘X), Forward all, Drop all, Send to…, "Intercept response to this request". |
| PRX-012 | P0 | Edited messages are forwarded with the edited bytes; the original is kept (`original_request_blob`) and the row shows an "edited" marker. |
| PRX-013 | P0 | Intercept rules (request): ordered conditions joined by AND/OR. Fields: domain, IP, protocol, method, URL, file extension, request contains params, header, body, in scope. Matching: matches/doesn't match regex. Default rules: skip images/CSS/fonts/JS (`^(gif\|jpg\|png\|css\|js\|ico\|svg\|woff2?)$`), only in-scope. |
| PRX-014 | P0 | Intercept responses (separate toggle and rule set: status, MIME, header, body, "request was intercepted"). |
| PRX-015 | P1 | Rules can also be written as a GulpQL expression (F05) instead of the rule builder. |
| PRX-016 | P1 | Timeout policy: optionally auto-forward intercepted items after N seconds. The queue shows countdowns. |
| PRX-017 | P1 | Intercepting a stream on an HTTP/2 connection does not block other streams on that connection. |
| PRX-018 | P1 | "Update Content-Length" on forward (default on for intercept edits, configurable). |
| PRX-019 | P2 | Breakpoints-style quick rules from a history row: "Intercept requests like this" (prefills a rule from host + path). |

### 2.3 Match & Replace

| ID | Pri | Requirement |
|---|---|---|
| PRX-020 | P0 | Ordered rules, each with: enabled, type (Request header, Request body, Request first line, Request param name/value, Response header, Response body, Response first line, WS message to server/client), match (literal or regex; empty match with header type = add header), replace (supports regex groups `$1`), comment. |
| PRX-021 | P0 | Rules apply to proxy traffic. A per-rule "also apply to tools" flag (Repeater, Fuzzer, Scanner…) hooks them into the F03 pipeline. |
| PRX-022 | P0 | Built-in presets (disabled by default): emulate iOS/Android UA, remove `If-Modified-Since`/`If-None-Match` (avoid 304s), remove `Accept-Encoding` (get plaintext), add `X-Forwarded-For: 127.0.0.1`, hide HSTS. |
| PRX-023 | P1 | Rule scope: only in-scope / host pattern. |
| PRX-024 | P1 | "Test rule" pane: paste a message and preview the rewritten result with a diff. |
| PRX-025 | P1 | Rules can be GulpQL-conditioned (`when: req.host ~ "api"`). |

### 2.4 WebSockets

| ID | Pri | Requirement |
|---|---|---|
| PRX-030 | P0 | Detect upgrades (`Upgrade: websocket`, `101`) and switch the connection to frame-level proxying (RFC 6455), including HTTP/2 extended CONNECT (RFC 8441) when supported by both sides. |
| PRX-031 | P0 | Record each message (text/binary/close/ping/pong) with direction and timestamp in `ws_messages`. Reassemble fragmented messages for display; keep frame boundaries in metadata. |
| PRX-032 | P0 | WebSockets history view: connection list + message table + editor; filter by direction/opcode/text. |
| PRX-033 | P1 | Intercept WebSocket messages (separate toggle and rules); edit and forward/drop. |
| PRX-034 | P1 | Decompress `permessage-deflate` for display and editing; re-compress on forward (or negotiate it away via a match-replace preset removing `Sec-WebSocket-Extensions`). |
| PRX-035 | P1 | Send a WS message to Repeater: Repeater opens a WS session (F06 REP-012) on a new connection with the same upgrade request. |
| PRX-036 | P2 | Socket.IO / STOMP / GraphQL-WS / JSON-RPC message pretty-printing. |

## 3. UI

`Proxy` tool sub-tabs: **Intercept** · **HTTP History** · **WebSockets History** · **Match & Replace** · **Listeners** (listeners + TLS pass-through + upstream rules + strip options; Settings → Proxy contains the same panes).

- Intercept: the left list is the queue (it can be collapsed), the right side is the editor and
  Inspector. The top bar has Forward, Drop, Intercept on/off, Open browser, and an "Action ▾" menu
  (Send to…, do-intercept response, add rule from this item).
- The HTTP History split is the table on top and the request/response editors below (layout
  switchable, UI-050).

## 4. Implementation notes

### 4.1 NIO pipeline per client connection

```
[ServerBootstrap child channel]
  ProxyProtocolSniffer          // first bytes: "CONNECT" | absolute-form | origin-form (invisible) | SOCKS5 (0x05) | TLS ClientHello (0x16, invisible TLS)
    → HTTP/1 path:   RawHTTP1RequestDecoder (our own, raw-preserving) → ProxyRequestHandler
    → CONNECT path:  ConnectHandler → (MITM) SNIHandler → TLSPolicyHandler → NIOSSLServerHandler(ctx with minted cert, ALPN)
                         → ALPN result: http/1.1 → RawHTTP1RequestDecoder … | h2 → NIOHTTP2Handler + StreamMultiplexer → H2StreamToExchangeHandler
                     (pass-through) → GlueHandler (byte splice to an upstream channel)
    → SOCKS path:    SOCKS5ServerHandshakeHandler (NIOSOCKS in swift-nio-extras provides the client side; write the server side) → then like CONNECT
```

> **Concept: why write our own HTTP/1 decoder?** NIO's `HTTPRequestDecoder` (llhttp-based) is strict
> and normalizes. It rejects or rewrites malformed requests, which a security proxy must forward as-is
> when possible. Our decoder frames messages (it finds the end of headers and applies the body
> framing rules) but keeps the bytes exactly as received.

### 4.2 Request pipeline (async, on the connection's event loop, then hop to a Task)

1. Build `RawRequest`, compute `HTTPTarget` (absolute-form / CONNECT authority / Host header).
2. Apply match & replace (request).
3. `InterceptGate.process(request)`: if intercept is on and the rules match, enqueue it and `await`
   the user's decision (`CheckedContinuation`). While it waits, apply backpressure to that client
   connection only (stop reading).
4. Run the extension `onProxyRequest` hooks (F18).
5. Send via `HTTPEngine` (F03), reusing pooled upstream connections; for an MITM'd TLS connection,
   prefer the upstream connection pre-opened during ALPN mirroring.
6. Response: match & replace (response) → intercept response → extension hooks → strip options
   (PRX-044) → write to the client.
7. Record the exchange (async coalesced write) and emit events.

### 4.3 Response streaming

Stream large or slow responses to the client while recording them, instead of buffering the whole
body. Cap the recorded body at the "max recorded body" setting (default 50 MB, rest truncated with a
flag). If response interception or rewriting rules apply, buffer the response (bounded by the same
limit).

### 4.4 Content encoding

Store the response as received (compressed). The editor decompresses for display (gzip, deflate,
br, zstd), and the Pretty view always shows decoded text. Match & replace on a body decodes, edits
and re-encodes (or drops `Content-Encoding` when the "simplify encoding" option is on).

## 5. Edge cases

- `Expect: 100-continue` (forward the 100 to the client and stream the body).
- Pipelined HTTP/1 requests from clients (process them in order).
- `CONNECT` to non-TLS ports (for example a WebSocket over plain TCP): detect TLS by the first byte
  `0x16`; if it isn't TLS, treat the stream as plain HTTP inside the tunnel.
- Clients that send HTTP/2 with prior knowledge (cleartext h2c preface `PRI * HTTP/2.0`).
- Upstream TLS failures: return a `502` with an HTML explanation page to the client and log the
  error event.
- Client certificate requests from upstream: use the configured client certificate (F15 SES-040).
- Loop detection: a request to the proxy's own listener address → serve the landing page (PRX-046)
  instead of looping.

## 6. Acceptance tests

1. A curl through the proxy (`curl -x 127.0.0.1:8080 http://127.0.0.1:8088/echo`) returns the echo,
   and the history has one row with matching bytes.
2. A curl with the CA (`--cacert gulp-ca.pem`) to `https://localhost:8443/h2 --http2` → the history
   row has HTTP/2 and decrypted bodies.
3. Intercept on → the request waits → edit the parameter → forward → VulnLab `/echo` shows the
   edited value; the history marks the row edited and keeps the original.
4. A match & replace "add header `X-Test: 1`" → `/echo` shows the header for every request.
5. A host on the TLS pass-through list → the client sees the real server certificate; the Logger
   shows the tunnel entry.
6. A WebSocket chat via the Gulp Browser → messages in both directions appear; an intercepted
   message, edited, arrives changed.
