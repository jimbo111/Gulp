# F26 — WebSocket Security Workbench (merged)

> Milestone: none — merged into other specs on 2026-11-08 · Modules: none of its own (was
> `GulpFeatures/WSX`) · Was scheduled: M22 (post-1.0) · Depends on: F01, F03, F06, F07, F08, F10, F15

## 1. Purpose

**Merged (2026-11-08 feature review, `docs/FEATURE-REVIEW.md` §3.3; product decision #7 in
`docs/07-decisions.md`).** WebSocket proxying, intercept and history are F01 §2.4 and the WebSocket
Repeater is F06 REP-012 (both v1). The security-testing additions this spec described — fuzzing over a
live socket, the CSWSH check, per-message authorization and sub-protocol decoding — now live in the
spec of the tool each one extends. They stay **post-1.0**: the roadmap's M22 milestone schedules them
in their new homes. The requirement IDs are unchanged, so existing references keep working.

## 2. Requirements

### 2.1 Where each requirement went

| New home | Requirements (original IDs kept) | Milestone now |
|---|---|---|
| F07 Fuzzer §2.6 (WebSocket fuzzing) | WSX-002, WSX-005, WSX-007 | M22 |
| F08 Scanner §3.6 (WebSocket checks: CSWSH) | WSX-003 | M22 |
| F23 Advanced tools §1 (Authz Matrix: per-message authorization) | WSX-004 | M22 |
| F01 Proxy §2.4 (extends PRX-036: sub-protocol decode/re-encode) | WSX-006 | M22 |
| F15 Sessions §2.3 (scripted WS message sequences, as macros) | WSX-008 | M22 |

### 2.2 Cut requirements

| ID | Pri | Requirement |
|---|---|---|
| WSX-001 | P0 | **Cut (2026-11-08 feature review)** — restated F06 REP-012 (the WS Repeater). Its extensions are covered by WSX-006 (decoding), WSX-007 (insertion points) and WSX-004 (identity swap). |

## 3. UI

None of its own: the WS Fuzzer is a Fuzzer attack type, CSWSH is a Scanner check, per-message
authorization is an Authz Matrix mode, and decoding is a WS history/Repeater view.

## 4. Implementation notes

The WebSocket frame codec lives in `GulpHTTP` (F03 §2), shared by the proxy, the WS Repeater and the
WS Fuzzer. See the new home specs for the rest.

## 5. Edge cases

See the new home specs (F07 §4/§5 carry the socket edge cases: sub-protocol handshakes, heartbeats,
fragmentation).

## 6. Acceptance tests

Moved with their requirements: test 1 → F06 §6 (WS Repeater) and F07 §6 (WS fuzz); test 2 → F23 §9;
test 3 → F08 §7; test 4 → F07 §6. The VulnLab sockets they need are in doc 06 §3.1 (M22 row).
