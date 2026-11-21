// GulpAI — the bounded agentic loop (F22 AI-013). "Investigate this endpoint" lets the assistant plan
// and run a short sequence of tool calls to confirm or rule out a hypothesis, within hard limits the
// user sets: a step budget (provider round-trips), a request budget (active sends, which the executor
// runs through ScopeGuard and the approval mode), and a cancel/panic stop. The loop redacts every tool
// result before it goes back to the provider. The executor and provider are injected, so the loop is
// tested end-to-end with a scripted mock provider and no network.

import Foundation

/// Hard limits for one agentic run.
public struct AgentLimits: Sendable {
    /// Maximum provider round-trips.
    public var maxSteps: Int
    /// Maximum active sends (ScopeGuard-checked by the executor).
    public var maxRequests: Int

    public init(maxSteps: Int = 8, maxRequests: Int = 30) {
        self.maxSteps = maxSteps
        self.maxRequests = maxRequests
    }
}

/// Why an agentic run ended.
public enum AgentStop: String, Sendable {
    case answered, stepBudget, requestBudget, cancelled
}

/// The result of running a tool.
public struct ToolOutcome: Sendable {
    public var content: String
    /// Whether this call was an active send (counts against the request budget).
    public var countsAsRequest: Bool

    public init(content: String, countsAsRequest: Bool = false) {
        self.content = content
        self.countsAsRequest = countsAsRequest
    }
}

/// The outcome of an agentic run.
public struct AgentResult: Sendable {
    public var answer: String
    public var stop: AgentStop
    public var steps: Int
    public var requests: Int
    public var inputTokens: Int
    public var outputTokens: Int
    public var transcript: [LLMMessage]
}

/// Runs a bounded tool-use loop over an `LLMProvider`.
public actor Agent {
    private let provider: LLMProvider
    private let redactor: Redactor

    /// An agent over `provider`, redacting tool results with `redactor` before they are sent back.
    public init(provider: LLMProvider, redactor: Redactor = Redactor()) {
        self.provider = provider
        self.redactor = redactor
    }

    /// Run the loop. `sendTools` names the tools that count against the request budget; `execute`
    /// runs a tool call (and is where ScopeGuard/approval live). `isCancelled` is polled between steps
    /// (the panic stop / kill switch).
    public func run(
        system: String, user: String, tools: [LLMTool], limits: AgentLimits = AgentLimits(),
        sendTools: Set<String> = [], isCancelled: @Sendable () -> Bool = { false },
        execute: @Sendable (LLMToolCall) async -> ToolOutcome
    ) async throws -> AgentResult {
        var messages = [
            LLMMessage(role: .system, content: system),
            LLMMessage(role: .user, content: redactor.redact(user).text),
        ]
        var steps = 0, requests = 0, inputTokens = 0, outputTokens = 0
        var lastText = ""

        while true {
            if isCancelled() {
                return result(lastText, .cancelled, steps, requests, inputTokens, outputTokens, messages)
            }
            if steps >= limits.maxSteps {
                return result(lastText, .stepBudget, steps, requests, inputTokens, outputTokens, messages)
            }
            let response = try await provider.complete(messages: messages, tools: tools)
            steps += 1
            inputTokens += response.inputTokens
            outputTokens += response.outputTokens
            let text = response.text ?? ""
            if !text.isEmpty { lastText = text }
            if !text.isEmpty || !response.toolCalls.isEmpty {
                // The calls stay in the transcript so the next request can pair each result with its call.
                messages.append(LLMMessage(role: .assistant, content: text, toolCalls: response.toolCalls))
            }
            guard !response.toolCalls.isEmpty, response.stopReason != .endTurn else {
                return result(lastText, .answered, steps, requests, inputTokens, outputTokens, messages)
            }
            var hitRequestBudget = false
            for call in response.toolCalls {
                if sendTools.contains(call.name), requests >= limits.maxRequests {
                    messages.append(
                        LLMMessage(
                            role: .tool, content: "request budget reached — not sent", toolCallID: call.id))
                    hitRequestBudget = true
                    continue
                }
                let outcome = await execute(call)
                if outcome.countsAsRequest { requests += 1 }
                messages.append(
                    LLMMessage(
                        role: .tool, content: redactor.redact(outcome.content).text, toolCallID: call.id))
            }
            if hitRequestBudget {
                return result(lastText, .requestBudget, steps, requests, inputTokens, outputTokens, messages)
            }
        }
    }

    private func result(
        _ answer: String, _ stop: AgentStop, _ steps: Int, _ requests: Int, _ inTok: Int, _ outTok: Int,
        _ transcript: [LLMMessage]
    ) -> AgentResult {
        AgentResult(
            answer: answer, stop: stop, steps: steps, requests: requests, inputTokens: inTok,
            outputTokens: outTok, transcript: transcript)
    }
}
