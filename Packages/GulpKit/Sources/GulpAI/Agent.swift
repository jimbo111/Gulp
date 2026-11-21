// GulpAI — the bounded agentic loop (F22 AI-013). "Investigate this endpoint" lets the assistant plan
// and run a short sequence of tool calls to confirm or rule out a hypothesis, within hard limits the
// user sets: a step budget (provider round-trips), a request budget (active sends), and a
// cancel/panic stop. The loop redacts every tool result before it goes back to the provider.
//
// Tools are the shared agent tool surface, and every call goes through `APIGate` (GulpWorkspace;
// architecture §3 rule 6): ScopeGuard, the approval policy and the audit log apply exactly as they do
// for MCP clients, sends are recorded as `.ai`, and the gate's active tools count against the request
// budget. A call whose audit write fails ends the run with that error. The loop itself takes an
// injected executor (internal), so it is tested end-to-end with a scripted provider and no network.

import Foundation
import GulpWorkspace

/// Hard limits for one agentic run.
public struct AgentLimits: Sendable {
    /// Maximum provider round-trips.
    public var maxSteps: Int
    /// Maximum active sends.
    public var maxRequests: Int

    /// Limits of `maxSteps` round-trips and `maxRequests` active sends.
    public init(maxSteps: Int = 8, maxRequests: Int = 30) {
        self.maxSteps = maxSteps
        self.maxRequests = maxRequests
    }
}

/// Why an agentic run ended.
public enum AgentStop: String, Sendable {
    /// The model answered without asking for more tools.
    case answered
    /// The step budget ran out.
    case stepBudget
    /// The model asked for an active send past the request budget.
    case requestBudget
    /// The run was cancelled (panic stop / kill switch).
    case cancelled
}

/// The result of running a tool.
struct ToolOutcome: Sendable {
    var content: String
    /// Whether this call was an active send (counts against the request budget).
    var countsAsRequest: Bool

    init(content: String, countsAsRequest: Bool = false) {
        self.content = content
        self.countsAsRequest = countsAsRequest
    }
}

/// The outcome of an agentic run.
public struct AgentResult: Sendable {
    /// The model's last text.
    public var answer: String
    /// Why the run ended.
    public var stop: AgentStop
    /// Provider round-trips made.
    public var steps: Int
    /// Active sends made.
    public var requests: Int
    /// Input tokens used, as the provider reported them.
    public var inputTokens: Int
    /// Output tokens used, as the provider reported them.
    public var outputTokens: Int
    /// The conversation as sent (tool results redacted).
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

    /// Run the loop over the agent tool surface, every call through `gate` and audited as
    /// `ai:<model>`. `isCancelled` is polled between steps (the panic stop / kill switch). Throws when
    /// the provider fails or a tool call's audit write fails.
    public func run(
        system: String, user: String, gate: APIGate, limits: AgentLimits = AgentLimits(),
        isCancelled: @Sendable () -> Bool = { false }
    ) async throws -> AgentResult {
        let tools = APIGate.tools.map {
            LLMTool(name: $0.name, description: $0.description, schema: $0.inputSchema)
        }
        let caller = "ai:\(provider.model)"
        return try await run(
            system: system, user: user, tools: tools, limits: limits,
            sendTools: Set(APIGate.tools.filter(\.isActive).map(\.name)), isCancelled: isCancelled
        ) { call in
            let result = try await gate.call(call.name, arguments: Data(call.arguments.utf8), caller: caller)
            return ToolOutcome(
                content: String(decoding: result.json, as: UTF8.self), countsAsRequest: result.sent)
        }
    }

    /// The loop over an injected executor. `sendTools` names the tools that count against the request
    /// budget; `execute` runs a tool call.
    func run(
        system: String, user: String, tools: [LLMTool], limits: AgentLimits = AgentLimits(),
        sendTools: Set<String> = [], isCancelled: @Sendable () -> Bool = { false },
        execute: @Sendable (LLMToolCall) async throws -> ToolOutcome
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
                let outcome = try await execute(call)
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
