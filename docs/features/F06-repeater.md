# F06 — Repeater

> Milestone: M5 · Modules: `GulpRepeater`, `GulpFeatures/Repeater` · Depends on: F03, F04, F12

## 1. Purpose

Repeater is the manual-testing workhorse: send a request, see the response, tweak it, send it again.
A tester lives here, iterating on a single request to understand and exploit behavior.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| REP-001 | P0 | Tabs, each holding one editable request, its target, send options, and a response pane. "Send to Repeater" (⌘R) opens a new tab prefilled from any exchange. |
| REP-002 | P0 | Send (⌘↩) via the HTTP engine; show the response in the MessageEditor with status, length and time. Sends run concurrently per tab without blocking the UI; a tab can be sending while others are edited. |
| REP-003 | P0 | Per-tab target editor (scheme/host/port/SNI/IP override) and HTTP version preference; "Update Content-Length" toggle (default on). |
| REP-004 | P0 | Per-tab request **history** (every send), navigable with ◀ ▶ (and ⌘[ / ⌘]); each entry keeps the exact request and response. Shows a diff against the previous response (UI-030) on demand. |
| REP-005 | P0 | Tab management: rename (double-click), reorder (drag), close (⌘W), reopen-closed (⌘⇧T), colored labels, and **groups** (REP-010). Tabs persist in the project. |
| REP-006 | P0 | Follow redirects option (never/on-site/in-scope/always, max hops); when on, show the redirect chain and let the user step through it. |
| REP-007 | P0 | Connection option: reuse vs. new connection; automatically reconnect on failure. Show connection info (reused, ALPN, TLS) for each send. |
| REP-008 | P1 | Inline **Transform Tags** (F12) in the request are evaluated on send (e.g. `«base64(...)»`, `«now()»`, `«var(csrf)»`); a toggle enables/disables evaluation, and a preview shows the rendered bytes. |
| REP-009 | P1 | Inspector editing (UI-020): change a param/header/cookie/pseudo-header via the structured panel and the raw updates. |
| REP-010 | P1 | **Groups** of tabs with a group **send mode** (F03 group sends: sequential-same-conn, sequential-separate, parallel, single-packet). "Send group" issues all requests per the mode and shows a combined results table (status, length, time, order). This is the race-condition workflow. |
| REP-011 | P1 | Save/variable capture: extract a value from a response (regex or Inspector pick) into a named variable usable by Transform Tags in this or other tabs (e.g. grab a CSRF token from a GET, use it in a POST). |
| REP-012 | P1 | WebSocket Repeater: a tab can hold a WS session — open the upgrade, then send/receive frames interactively, with a message log and an editor; reconnect button. |
| REP-013 | P2 | "Send sequence": chain tabs so the output (variables) of one feeds the next; a lightweight multi-step runner (a precursor to macros, F15). |
| REP-014 | P2 | Auto-resend on edit (debounced) mode for fast iteration; and a "resend every N seconds" option (polling), with a clear stop. |
| REP-015 | P2 | Response rendering niceties: pin a search term (UI-015), word-wrap toggle, show non-printables, and a "render" tab for HTML (sandboxed, doc 01 §7). |

## 3. UI

- A horizontal tab bar with a `+`; groups are shown as colored brackets around their tabs or in a
  collapsible rail. A tab shows a status dot (idle/sending/error).
- Layout: request on the left, response on the right (switchable). Top bar: Send/Cancel, target
  field, version picker, options popover (redirects, connection, content-length, tags), history
  arrows, "Send to…", and (in a group) "Send group" with a mode picker.
- A group-send results panel: a small table of the group's requests with status/length/time and the
  final-byte spread (F03 HTTP-035); selecting a row shows that exchange.

## 4. Implementation notes

- `RepeaterService` (actor) owns tab state and persists drafts to `repeater_tabs` (draft bytes as a
  blob) and sends to `repeater_history` (referencing `exchanges`). Debounce draft saves (≈500 ms).
- Each send is a `Task`; keep a handle per tab so Cancel works. Don't record Repeater sends to Proxy
  history, but do record them to the Logger (source `.repeater`) and the tab history.
- Transform Tags and variables: a per-project `VariableStore` (name → bytes, with scope: tab/global)
  that the tag evaluator reads; capture rules run on each response.
- Group single-packet send delegates entirely to `HTTPEngine.sendGroup` (F03 HTTP-033/034).
- WS Repeater uses `HTTPEngine.openWebSocket`; frames are shown with the same WS viewer as F01.

## 5. Edge cases

- A request edited to be unparsable: still sendable; the Inspector shows "unparsed" and disables
  structured edits for the broken part.
- Target host differs from the `Host` header (deliberate): respect the explicit target; show a small
  "Host ≠ target" hint, not an error.
- Huge responses: stream into the response store, show the first page immediately.
- Closing a tab mid-send cancels it.

## 6. Acceptance tests

1. ⌘R from a history row opens a tab with identical request bytes; ⌘↩ returns the same response as
   the original (allowing for time-sensitive values).
2. Editing a query param and resending changes the echoed value at VulnLab `/echo`; the history
   arrows step between the two responses and the diff highlights the change.
3. Capture the CSRF token from `/login` (GET) into `«var(csrf)»`, use it in the POST, and the login
   succeeds (safe-twin behavior).
4. A group of 20 tabs in single-packet mode against `/race/redeem` yields more than one successful
   redemption (the bug triggers); the results table shows the timing spread.
5. Tabs, groups and colors survive closing and reopening the project.
