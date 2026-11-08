# Feature review (2026-11-07)

An independent review of all 32 feature specs against how web apps and their testing look in 2026,
and against the goal in `00-vision.md`: a credible, daily-usable macOS alternative for pentesters and
bug-bounty hunters, built by a small team. This file records the verdicts, what was **adopted**, and
what is **proposed and waiting for the owner's decision** (scope cuts are product decisions,
CLAUDE.md §4).

> **Update 2026-11-08: the owner adopted every §3 proposal** ("Adopt the feature review
> proposals"). §3 is kept unchanged as the record; how each proposal was applied — the new IDs, the
> milestone splits and the beta gate, the merged stubs and the cuts — is in `docs/07-decisions.md`
> (product decision #7 and the 2026-11-08 small decisions) and in `docs/03-roadmap.md`.

## 1. Summary

The core workflow is sound and mostly current. The gaps are at the protocol edge (streaming
responses, HTTP/2 trailers, gRPC, ECH, capture for apps that ignore the proxy, request signing). The
bigger issue is **scope**: about a third of the specs overlap, and several daily-driver tools
(Authz Matrix, JWT, API import, GraphQL) arrive only in M19.

## 2. Adopted now (scheduling and correctness; no feature removed)

| Change | Where |
|---|---|
| M3 split into **M3a** (CA, CONNECT/MITM, HTTP/1.1) and **M3b** (HTTP/2 both sides, trailers), so each has a working DoD | `03-roadmap.md` |
| New **HTTP-027** (P0, M3b): keep and forward HTTP/2 trailers (gRPC needs `grpc-status`) | F03 |
| New **TLS-017** (P1): ECH-aware MITM — mint for the outer SNI, record "ECH offered", Gulp Browser disables ECH | F02 |
| **TLS-015** updated: JA4 + HTTP/2 SETTINGS fingerprint (JA3 is obsolete since Chrome randomises extension order) | F02 |
| **MAC-011** corrected: macOS *does* support per-app transparent proxying (Network Extension); post-1.0 P1 | F24 |
| **BRW-002** corrected: fallback is the login-keychain install; Chrome on macOS doesn't use NSS | F16 |

## 3. Proposals — **Adopted 2026-11-08**

### 3.1 Missing capabilities (add)

| # | Capability | Proposed home | Priority / milestone |
|---|---|---|---|
| A1 | Long-lived streaming responses (SSE, streamed fetch): stream through the proxy, in-progress history rows, event view | F01 §4.3, F05, F06 | P0, M4 |
| A2 | gRPC / gRPC-Web / Connect + schema-less protobuf decode, `.proto`/reflection import | new F33 (promote ADV-053) | P1, ~M9–M10 |
| A3 | Request signing as session actions: DPoP (RFC 9449), HTTP Message Signatures (RFC 9421), AWS SigV4 | F15 | P1, M12 |
| A4 | Passkeys/WebAuthn: CDP virtual authenticator for login recording and crawl | F16/F15 | P1, M13 |
| A5 | Paste-to-request (cURL/fetch/raw) and Burp/Caido history import (lowers switching cost) | F06/F20 | P1, M5–M6 |
| A6 | Scanner checks: server-side prototype pollution, client-side path traversal, mass assignment, upload bypasses, JWT (alg:none, kid) | F08 | P1, M11+ |
| A7 | Bounded agentic AI follow-up ("investigate this endpoint" within scope/rate/approval limits) | F22 | P1, M18 |
| A8 | Testing AI-agent endpoints (remote MCP servers, tool poisoning) | F32 | P1, post-1.0 |
| A9 | HTTP/3 upstream client for Repeater; flag `Alt-Svc: h3` in history (interception stays a non-goal) | F03 | P2, post-1.0 |

### 3.2 Re-sequencing (earlier value)

1. A **daily-driver beta after M9**: proxy, TLS/HTTP/2, intercept, Repeater, Fuzzer (with content
   discovery), Decoder/JWT, Comparer, search, Notebook. Ship it to real users.
2. Pull forward: MCP tool surface (AUT-020…023, read + `send_request`) and API/cURL/HAR import to
   ~M6; JWT tooling into F12 (M7); Authz Matrix to its own milestone right after M12; GraphQL with
   the browser (~M13); Gulp Browser launch (BRW-001…004) to M3/M4 as the zero-setup capture path.
3. Split oversized milestones: M4, M11 (into three), M13, M16, M19.

### 3.3 Merge (remove duplication)

| Spec | Proposed merge |
|---|---|
| F17 Engagement tools | ETL-001/002/005 duplicate HIS-050/HIS-053/TGT-008; Copy-as → UI-040 (M4); content discovery ETL-003 → F07 (M8); keep a small CSRF PoC |
| F26 WebSocket workbench | WSX-002 → F07, WSX-003 → F08 check, WSX-004 → Authz Matrix, WSX-006 → PRX-036; WSX-001 restates REP-012 |
| F28 Cache poisoning | → an F08 check family (post-1.0) |
| F29 Governor | limiter → F03 (HTTP-013 already is it) + a workspace panic stop; drop GOV-004/005/008/009 |
| F30 Drift & retest | retest (DRF-003…005, 009) → F08/F21; drop baselines |
| F31 Journal | coverage → F04, timeline → F14; drop JRN-004/006/007 |
| Import/export | HAR/collection import is specified five times (HIS-044, PRJ-008, TGT-009, ADV-051, AUT-004) → one F20 service |

### 3.4 Defer or cut

| Item | Proposal | Reason |
|---|---|---|
| F11 Sequencer (SEQ-001…006, all P0) | out of v1 | rarely finds bugs against modern frameworks/JWTs; a whole milestone |
| Frame Kit (BRW-020…022) | cut | clickjacking is out of scope in most programs |
| DOM Probe (BRW-010/011) | P0 → P1 | |
| Beacon server (BCN-020…022) | post-1.0 | interactsh support (BCN-005) covers v1 |
| Check Recipes (SCN-060…062) | P0 → P1, out of M11 | |
| Extensions: Python SDK (EXT-012) P0 → P1; Gallery (EXT-020/021) post-1.0 | | no community yet |
| Reporting: PDF/branding (RPT-005/009) → P2; promote RPT-012 (bug-bounty Markdown) | | |
| AI: AI-007/009 → P2 | | |
| macOS: MAC-020/022/023 → P2 | | |
| PRX-048 (Unix-socket listener) | cut | |

Net effect: roughly 1.5–2 milestones removed from v1, and the most-used bug-bounty tools land
months earlier.

## 4. Verdict per spec (from the review)

CORE-v1: F01–F10 (Beacon client only), F12–F16 (Browser launch early; Frame Kit cut), F18–F22
(trimmed), F24, F27 (trimmed, earlier). KEEP-LATER: F11, F25 (first post-1.0), F32 (first post-1.0).
MERGE: F17, F23 (split by tool), F26, F28, F29, F30, F31.
