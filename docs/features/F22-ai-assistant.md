# F22 — Gulp Assistant (AI)

> Milestone: M18 · Modules: `GulpAI`, `GulpFeatures/Assistant` · Depends on: F03, F05, F08, F19, F21

## 1. Purpose

An optional AI assistant that helps a tester understand traffic, spot issues, craft payloads, and
draft reports — grounded in the actual project data via the same tool surface the MCP server exposes
(F21). It's **off by default**, requires explicit consent, and redacts data before sending it to any
provider.

> **Note on trust.** AI output is advisory. The assistant can *suggest* and, with approval, *drive*
> Gulp's tools (all ScopeGuard-checked). It never bypasses scope or approval, and anything it sends
> to a model is gated by the egress/consent and redaction rules below.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| AI-001 | P0 | **Provider abstraction**: an `LLMProvider` protocol (chat + streaming + tool-use). First implementation: Anthropic Messages API (Claude), streaming with tool calls. Config: API key (Keychain), model, max tokens, temperature. |
| AI-002 | P0 | **Consent & egress control**: disabled until the user enables it and acknowledges that selected data will be sent to the configured provider; a persistent indicator when enabled; nothing is sent implicitly. (v1 ships **Claude only** — doc 07 decision #5; the `LLMProvider` abstraction leaves room for OpenAI-compatible and local/self-hosted providers later, see AI-011.) |
| AI-003 | P0 | **Redaction pipeline**: before any request to the provider, strip/mask secrets (auth headers, cookies, tokens, API keys, obvious PII) via patterns; show the user what will be sent (a preview for one-shot actions) and let them edit/cancel. Redaction is on by default and configurable. |
| AI-004 | P0 | **Grounded tool use**: the assistant uses the F21 tool surface (list/get exchanges, search, send request, start scan, list issues, scope, Beacon, notes). Active actions are ScopeGuard-checked and honor the approval mode; all actions are logged and attributed `source = .ai`. |
| AI-005 | P0 | **Context actions** from anywhere (UI-040 "Assistant ▸"): **Explain this request/response**, **What's suspicious here?**, **Suggest payloads for this parameter**, **Explain this issue & how to exploit/fix**, **Write a repro** — each builds a redacted, grounded prompt about the selected item. |
| AI-006 | P1 | **Chat panel** scoped to the project: ask questions ("where does this token come from?", "which endpoints take a redirect param?"); the assistant answers by calling tools (search/filter) and citing the exchanges it used (clickable). |
| AI-007 | P2 | **Payload crafting**: given a parameter/context, propose payloads and (with approval) run them via the Fuzzer/Repeater and summarize results; explain why each payload matters. *(P1 → P2 by the 2026-11-08 feature review.)* |
| AI-008 | P1 | **Triage assist**: summarize/prioritize issues, flag likely false positives with reasoning, and cluster related findings. Clearly marked as suggestions; never auto-changes issue status without confirmation. |
| AI-009 | P2 | **Report drafting** (F19 RPT-013): draft the executive summary and per-issue narratives from the real findings; user edits before use; marked as AI-drafted. *(P1 → P2 by the 2026-11-08 feature review.)* |
| AI-010 | P1 | **Cost/limits**: show token usage and an optional budget cap; a kill switch; streaming with cancel. |
| AI-011 | P2 | **Local model support** (Ollama/llama.cpp via an OpenAI-compatible endpoint) as a first-class provider for fully-offline use. |
| AI-012 | P2 | **Explain mode for beginners**: deeper, didactic explanations of vulns/traffic (fits the "teach me" use case) with links to the issue catalog. |
| AI-013 | P1 | **Bounded agentic follow-up**: "Investigate this endpoint" (from an exchange, site-map node or issue) lets the assistant plan and run a short sequence of tool calls (search, Repeater sends, a targeted scan of one insertion point) to confirm or rule out a hypothesis, within hard limits the user sets per run — in-scope only (ScopeGuard), a request budget and rate cap (drawing from the shared limiter, F03 §3.4), a step budget, and the approval mode for every active action (AUT-023). It shows the plan, streams each step with its citations, stops at any limit or on the panic stop (F20 GOV-001), and ends with a summary and optional Notebook entry. *(Added by the 2026-11-08 feature review, A7; M18.)* |

## 3. UI

An Assistant tool with a chat panel (streaming, tool-call trace shown as collapsible steps with
clickable exchange/issue citations), plus the "Assistant ▸" context actions everywhere. Settings →
AI: provider, model, key, redaction patterns and preview, approval mode, budget, and the egress
acknowledgment. A clear on/off indicator in the status bar when enabled.

## 4. Implementation notes

- `GulpAI` depends only on engines + `GulpReport`; the provider is pluggable. Tool-use loops reuse
  the exact DTOs/schemas from F21 (one definition), so the assistant and the MCP server expose
  identical capabilities.
- Redaction runs on any payload (messages + tool results) leaving the app; implement as a
  `RedactionFilter` over the DTOs with user-editable rules; keep a "what was sent" log.
- Streaming via the provider's SSE; map tool calls to F21 service calls through the same `APIGate`
  (scope/approval/audit) the MCP server uses.
- Keep prompts/system messages in resources, versioned; include the issue catalog text for grounded
  remediation.
- Never store the API key outside the Keychain; never log raw prompts containing unredacted secrets.

## 5. Edge cases

- Provider/network down → graceful error; the rest of Gulp is unaffected (AI is isolated).
- A model tool-call requests an out-of-scope/destructive action → blocked (ScopeGuard/approval) and
  reported back to the model as a refusal it must respect.
- Oversized context → the assistant must fetch via tools/pagination, not dump the whole project.
- Redaction gaps → the "preview before send" and the egress indicator are the backstop; document
  that redaction is best-effort.

## 6. Acceptance tests

1. With AI disabled, no provider calls are possible and the UI makes that clear; enabling requires
   the egress acknowledgment.
2. "Explain this issue" on a VulnLab finding returns a grounded explanation citing the actual
   exchange; the redaction preview shows the auth cookie masked.
3. The assistant answers "which endpoints accept a redirect parameter?" by calling search/filter
   tools and citing the right exchanges.
4. An AI-initiated active scan on an out-of-scope host is blocked and surfaced; in-scope with
   approval mode on, it waits for confirmation; all actions appear in the audit log as `.ai`.
5. (AI-011, post-v1) When a local OpenAI-compatible provider is added, switching to it keeps all data
   on-prem (no external calls observed). Not required for the Claude-only v1 (doc 07 decision #5).
