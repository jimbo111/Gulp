# 05 — UI and UX

Gulp must feel like a first-class Mac app. Follow Apple's Human Interface Guidelines, use system
fonts and colors (so dark mode, accent colors and the current macOS look work automatically), and
support keyboard navigation everywhere.

## 1. Windows and documents

- Each open project is one **document window** (`DocumentGroup`-style behavior, implemented with
  `WindowGroup(for: ProjectRef.self)` plus custom open and save panels, because a `.gulp` file is a
  live database, not a file you load and save).
- **Launcher window** (shown at startup when no project is open): New Temporary Project, New
  Project…, Open…, a recent-projects list, and a "Use settings from…" selector.
- **Detachable tools**: any Repeater tab, Fuzzer attack, Decoder or Comparer can be torn off into
  its own window (⌘⇧D "Detach").
- **Settings window** (⌘,): SwiftUI `Settings` scene with tabs: General, Proxy, TLS, Network, HTTP,
  Scanner, Beacon, Browser, Extensions, Automation, AI, Appearance, Shortcuts, Updates, Diagnostics.
  (Automation hosts the REST/MCP server controls, F21 §3; Updates hosts Sparkle, F24 MAC-026.) This
  is the canonical pane list — doc 04 §6, F20 PRJ-021 and every feature that adds settings reference
  it. Each pane shows whether a value is **User** or **Project** level (a small segmented "Applies
  to" control).

## 2. Main window layout

```
┌───────────────────────────────────────────────────────────────────────────────────────┐
│ ● ● ●   [Project name ▾]   [Intercept: OFF ⏸]  [Listener 127.0.0.1:8080 ●]   [🔍 ⌘K]    │ ← toolbar
├──────────────┬────────────────────────────────────────────────────────────────────────┤
│ DASHBOARD    │  ┌ Tab bar (per tool: e.g. Repeater tabs 1 2 3 +) ───────────────────┐  │
│  Dashboard   │  │                                                                   │  │
│ TRAFFIC      │  │  Tool content                                                     │  │
│  Proxy       │  │  (tables, editors, split views)                                   │  │
│  Target      │  │                                                                   │  │
│  Logger      │  │                                                                   │  │
│ TOOLS        │  │                                                                   │  │
│  Repeater  3 │  │                                                                   │  │
│  Fuzzer      │  │                                                                   │  │
│  Scanner   ⚠ │  │                                                                   │  │
│  Beacon      │  │                                                                   │  │
│  Sequencer   │  │                                                                   │  │
│  Decoder     │  │                                                                   │  │
│  Comparer    │  │                                                                   │  │
│  Authz Matrix│  │                                                                   │  │
│  JWT         │  │                                                                   │  │
│  GraphQL     │  └───────────────────────────────────────────────────────────────────┘  │
│ WORKSPACE    │                                                                        │
│  Notebook    │                                                                        │
│  Extensions  │                                                                        │
│  Assistant   │                                                                        │
├──────────────┴────────────────────────────────────────────────────────────────────────┤
│ Status bar: tasks running (2) · Beacon ● · memory · requests/s · event log ⚠ 1         │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

- Sidebar: `NavigationSplitView` with sections. Badges show counts: Repeater tabs, new issues,
  intercepted items waiting, new Beacon interactions. The user can hide or reorder tools
  (Settings → Appearance).
- Toolbar: project switcher, a global **Intercept toggle** (⌘⇧I), listener status, browser launch
  button, command palette.
- Status bar: running tasks (clicking opens the task list), Beacon status, throughput, event-log
  indicator.

## 3. Dashboard

- **Tasks** panel: live passive scan, crawl/audit tasks, fuzzer attacks. Each shows progress,
  request count, errors and pause/resume/cancel controls.
- **Issues** panel: an aggregated issue tree (severity → type → URL) with counts by severity
  (High/Medium/Low/Info) as colored badges and a small Swift Charts donut.
- **Event log**: a filterable list of `GulpEvent.log`.
- **Beacon feed**: the latest out-of-band interactions.

## 4. Shared components (GulpUI)

These are used everywhere. Build them once, in M2/M4, and reuse them. **Priority:** every `UI-xxx`
component is **P0 for the milestone that first needs it** (the roadmap lists which — e.g. the
`MessageEditor` in M4); they have no `Pri` column because they are shared infrastructure, not
optional features. The same holds for the §5 shortcuts (they ship with the actions they trigger).

| ID | Component | Description |
|---|---|---|
| UI-001 | `ExchangeTable` | NSTableView-backed, paged from the store (only visible rows plus a 200-row prefetch window are materialized). Sortable columns, column chooser, row highlight colors, multi-select, type-to-filter, drag-out (as `.http` text or HAR) |
| UI-002 | `FilterBar` | GulpQL text field with autocomplete and syntax coloring, plus quick-filter chips (In scope, Hide images/CSS/fonts, Status 2xx/3xx/4xx/5xx, Has params, Commented/Highlighted, MIME types), saved filters |
| UI-010 | `MessageEditor` | NSTextView (TextKit 2) with tabs: **Pretty** (formatted JSON/XML/HTML/JS, read-mostly; edits map back to raw where possible), **Raw** (exact bytes as text; non-printables shown as `\xNN` glyph tokens), **Hex** (UI-012), **Render** (sandboxed WKWebView, doc 01 §7). Supports read-only and editable modes |
| UI-011 | Syntax highlighting | Incremental and off-main. Highlights the request line, header names and values, cookies, parameters (name/value), JSON/XML/HTML/JS tokens. Theme follows light/dark mode. Bodies above 2 MB: highlight only the visible range |
| UI-012 | `HexEditor` | Custom NSView: offset / hex / ASCII columns, insert and overwrite, selection synced with the Raw tab |
| UI-013 | Editor search | ⌘F find bar with regex, case sensitivity, a match count and "highlight all"; ⌘G next |
| UI-014 | Line-wrap / invisible-chars toggles | Show CR/LF/TAB glyphs. Essential for smuggling work |
| UI-015 | Auto-scroll-to-match | Each editor can pin a search term so that, for every new response, it scrolls to the first match (useful in Repeater) |
| UI-020 | `InspectorPanel` | Right sidebar next to any message: request attributes (method, path, protocol), query params, body params, cookies, headers, HTTP/2 pseudo-headers, response headers, **selected text** decoded live (URL, HTML, Base64, hex, JWT…). Each item is editable and writes back to the raw message |
| UI-021 | `DecoderPopover` | Select text in any editor → ⌥⌘D shows a popover with the decoded value and "Replace selection with encoded…" actions |
| UI-030 | `DiffView` | Side-by-side or unified diff with word/byte modes (F13); reused in Repeater ("compare with previous response") |
| UI-040 | `SendToMenu` | One context-menu builder used by every table and editor: Send to Repeater (⌘R), Fuzzer (⌘I), Scanner (Active/Passive), Comparer (request/response), Decoder, Sequencer, Notebook (⌘⇧N), Authz Matrix, Copy as cURL/Python/JS/Go, Copy URL, Save item, Engagement tools ▸, Extensions ▸, Assistant ▸ Explain |
| UI-041 | `HighlightMenu` | Set a highlight color (⌘1…⌘9 when the table has focus), add a comment (⌘/) |
| UI-050 | `SplitLayoutControl` | Toggle request/response layout: side-by-side, top/bottom, or tabs. Remembered per tool |
| UI-060 | `TreeView` | NSOutlineView for the site map and the issue tree |
| UI-070 | `CommandPalette` | ⌘K fuzzy finder over actions, tools, Repeater tabs, settings panes, recent items |
| UI-080 | `PayloadListEditor` | A list editor with paste, load-from-file, wordlist picker, dedup, and the count shown |
| UI-090 | `ToastCenter` | Non-modal notifications (bottom-right), plus macOS user notifications for long tasks when the app is in the background |

## 5. Keyboard shortcuts (defaults; remappable in Settings → Shortcuts)

| Action | Shortcut |
|---|---|
| Command palette | ⌘K |
| Toggle intercept | ⌘⇧I |
| Forward intercepted message | ⌥⌘F |
| Drop intercepted message | ⌥⌘X |
| Send to Repeater | ⌘R |
| Send to Fuzzer | ⌘I |
| Send request (Repeater) | ⌘↩ |
| New Repeater tab | ⌘T |
| Close tab | ⌘W |
| Next/previous tab | ⌃⇥ / ⌃⇧⇥ |
| Go to tool N in sidebar | ⌘⌥1…9 |
| Add to Notebook | ⌘⇧N |
| Comment on item | ⌘/ |
| Highlight color | ⌘1…⌘9 (table focus) |
| URL-encode / decode selection | ⌘U / ⌘⇧U |
| Base64-encode / decode selection | ⌘B / ⌘⇧B |
| Find in editor | ⌘F / ⌘G |
| Global search | ⌘⇧F |
| Launch Gulp Browser | ⌘⇧O |
| Detach tab to window | ⌘⇧D |

## 6. Visual design

- System font for the UI; **SF Mono** (or the user's choice) for message editors. Default size 12,
  and ⌘+ / ⌘- zoom the editors.
- Severity colors: High = systemRed, Medium = systemOrange, Low = systemYellow, Info = systemBlue.
  Confidence is shown as text (Certain/Firm/Tentative) with an icon weight.
- Highlight colors use the system palette at ~35% alpha in the row background, so the text keeps
  enough contrast in both appearances.
- SF Symbols for all icons (no custom icon set needed except the app icon).
- Empty states: each tool shows a short explanation and the one action that gets started, for
  example "No requests yet — launch the Gulp Browser (⌘⇧O) or point a client to 127.0.0.1:8080".

## 7. Accessibility and quality

- Every control has an accessibility label. Tables expose row summaries (for example
  "GET example.com /login, 200, 3.2 kilobytes").
- Full keyboard navigation: Tab moves between panes, and arrows work in tables and trees.
- Respect Reduce Motion, Increase Contrast and Dynamic Type where macOS supports it.
- All user-visible strings go through `String(localized:)` so they can be localized later.

## 8. View model conventions (GulpFeatures)

```swift
@MainActor @Observable
final class HTTPHistoryViewModel {
    private let session: ProjectSession
    var filter: GulpQLExpression?
    var rowCount: Int = 0                      // the table asks for rows by index → paged fetch
    func row(at index: Int) -> ExchangeRowSummary?   // served from a page cache, fetched async
    func apply(events: [GulpEvent])            // called by the coalescer (≤ every 100 ms)
}
```

- Views never call `ProjectSession` directly. View models do, and they are the only bridge.
- Previews: every feature view has a SwiftUI preview backed by an in-memory `ProjectSession` with
  fixture data (`ProjectSession.preview()`).
