# F26 — WebSocket Security Workbench

> Milestone: M22 · Modules: `GulpFeatures/WSX` + helpers in `GulpHTTP`/`GulpFuzzer` ·
> Depends on: F01, F03, F07, F08, F10, F15

## 1. Purpose

F01 proxies, intercepts and edits WebSocket frames but can't **replay**, **fuzz**, or
**security-test** a socket. This adds a WS Repeater (reconnect + resend + iterate), a WS Fuzzer
(payload sets into a message template with match/extract), and dedicated checks — Cross-Site
WebSocket Hijacking (CSWSH), handshake-time vs per-message authorization, and message-level
injection delivered over WS and OAST-correlated. Modern apps (chat, trading, collaborative editors,
GraphQL-over-WS subscriptions) run critical logic over sockets that today's tooling barely reaches.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| WSX-001 | P0 | **WS Repeater**: open a WebSocket (reusing the F01/F03 handshake + proxy/scope config, honoring cookies/identities from F15) and send/edit/resend individual frames (text/binary/ping/close) with a per-connection history. |
| WSX-002 | P0 | **WS Fuzzer**: fuzz a message template with `§…§` insertion points across payload sets (reusing the F07 engine) over one live socket, with match/extract rules on returned frames and a results grid. |
| WSX-003 | P0 | **CSWSH**: replay the upgrade handshake with a forged/absent/cross-origin `Origin` header and report whether the server still upgrades and returns authenticated data; raise a CSWSH issue (F08). |
| WSX-004 | P0 | Distinguish **handshake-time vs per-message authorization** by replaying messages with a stripped/other-identity session and reporting whether privileged actions still succeed. |
| WSX-005 | P1 | OAST-correlated (F10) blind injection over WS messages (SSRF/command/XXE-style payloads carried in frames). |
| WSX-006 | P1 | Decode common WS sub-protocols/envelopes (JSON, STOMP, SignalR, socket.io, GraphQL-WS `connection_init`/`subscribe`) into an editable structured view and re-encode on send. |
| WSX-007 | P1 | Auto-generate insertion points from structured WS messages for the Fuzzer; a "send selected frame to WS Repeater/Fuzzer" action from WS history (F01 PRX-035). |
| WSX-008 | P2 | Scripted message sequences (send A, await a frame matching X, then send B) for stateful protocols, reusing the macro concept (F15). |

## 3. UI

A WebSocket tool with: a connection bar (URL, upgrade headers, connect/disconnect/reconnect,
identity picker); a message log (direction, opcode, time) shared with F01's WS viewer; an editor for
the frame to send; a Fuzzer sub-view (template + payload sets + results grid); and a checks panel
(CSWSH, per-message-authz) feeding Issues.

## 4. Implementation notes

- Builds on `HTTPEngine.openWebSocket` (F03) and the WS framing/`permessage-deflate` handling from
  F01; the Repeater/Fuzzer reuse the F07 payload engine and grep/extract.
- CSWSH test re-issues the raw upgrade with mutated `Origin`/cookies and inspects the `101` + first
  authenticated frames; per-message-authz test re-sends captured frames under a different/empty
  identity (F15).
- Structured decoders (WSX-006) are the same registry idea as F12 transforms; unknown protocols fall
  back to raw text/hex.
- All sends are scope-gated and honor the Governor limiter (F29).

## 5. Edge cases

- Sockets that require a sub-protocol handshake (`Sec-WebSocket-Protocol`) — preserve it on replay.
- Heartbeats/keepalives — the Repeater must auto-pong (configurable) so the socket isn't closed mid-test.
- Binary/fragmented messages — reassemble for editing, re-fragment faithfully on send (use the
  `ws_messages.frames_json` metadata, doc 04).
- Servers that authorize only at handshake — the per-message test is exactly what reveals it; don't
  treat a successful replay as benign.

## 6. Acceptance tests

1. VulnLab `/ws/chat`: the WS Repeater resends an edited frame and shows the mutated echo; a
   2-position fuzz runs with an extract rule on the reply.
2. A VulnLab socket that authenticates only at handshake accepts a replayed privileged message under
   a stripped session and is flagged; the per-message-authz twin rejects it.
3. A socket that upgrades with a cross-origin `Origin` and returns user data is reported as CSWSH;
   the Origin-checking twin is clean.
4. A blind command payload over WS yields a Beacon interaction correlated to the frame.
