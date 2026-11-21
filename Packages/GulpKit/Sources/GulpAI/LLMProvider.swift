// GulpAI — the provider abstraction (F22 AI-001). An `LLMProvider` turns a conversation (plus the
// tools the assistant may call) into either a text answer or a set of tool calls. The first provider
// is Anthropic's Messages API (Claude, doc 07 decision #5); the protocol leaves room for
// OpenAI-compatible and local providers later. The protocol and the types are pure, so the agent loop
// is tested with a scripted mock provider without any network or key.

import Foundation

/// A role in the conversation.
public enum LLMRole: String, Sendable, Codable {
    case system, user, assistant, tool
}

/// One message in the conversation. An `assistant` message carries the model's text and the tool
/// calls it made; each call is answered by a `tool` message with its id, so a provider can pair every
/// tool result with the call it answers.
public struct LLMMessage: Sendable, Codable, Equatable {
    /// Who said it.
    public var role: LLMRole
    /// The text (for a `tool` message, the tool's result).
    public var content: String
    /// For an `assistant` message, the tool calls the model made in that turn.
    public var toolCalls: [LLMToolCall]
    /// For a `tool` message, the id of the tool call it answers.
    public var toolCallID: String?

    /// A message; `toolCalls` only on `assistant` messages, `toolCallID` only on `tool` messages.
    public init(role: LLMRole, content: String, toolCalls: [LLMToolCall] = [], toolCallID: String? = nil) {
        self.role = role
        self.content = content
        self.toolCalls = toolCalls
        self.toolCallID = toolCallID
    }
}

/// A tool the assistant may call (the F21 agent surface: list/get exchanges, search, send, scan, …).
public struct LLMTool: Sendable, Codable, Equatable {
    /// The name the model calls the tool by.
    public var name: String
    /// What the tool does, as shown to the model.
    public var description: String
    /// A JSON-schema object (as a JSON string) describing the arguments.
    public var schema: String

    /// A tool; `schema` defaults to an empty JSON object.
    public init(name: String, description: String, schema: String = "{}") {
        self.name = name
        self.description = description
        self.schema = schema
    }
}

/// A tool call the model asked for.
public struct LLMToolCall: Sendable, Codable, Equatable {
    /// The provider's id for the call; the `tool` message that answers it carries the same id.
    public var id: String
    /// The name of the tool to run.
    public var name: String
    /// The arguments as a JSON object string.
    public var arguments: String

    /// A tool call.
    public init(id: String, name: String, arguments: String) {
        self.id = id
        self.name = name
        self.arguments = arguments
    }
}

/// Why the model stopped.
public enum LLMStopReason: String, Sendable, Codable {
    case endTurn, toolUse, maxTokens, stop
}

/// A provider's response: a final text, or tool calls to run, or both.
public struct LLMResponse: Sendable, Codable, Equatable {
    /// The model's text, if it produced any.
    public var text: String?
    /// The tool calls the model asked for, in order.
    public var toolCalls: [LLMToolCall]
    /// Why the model stopped.
    public var stopReason: LLMStopReason
    /// Tokens used (for the budget/usage display, AI-010), if the provider reports them.
    public var inputTokens: Int
    /// Output tokens used, if the provider reports them.
    public var outputTokens: Int

    /// A response; by default an empty end-of-turn with no usage.
    public init(
        text: String? = nil, toolCalls: [LLMToolCall] = [], stopReason: LLMStopReason = .endTurn,
        inputTokens: Int = 0, outputTokens: Int = 0
    ) {
        self.text = text
        self.toolCalls = toolCalls
        self.stopReason = stopReason
        self.inputTokens = inputTokens
        self.outputTokens = outputTokens
    }
}

/// A chat completion provider (chat + tool use). Streaming is a provider detail layered on top.
public protocol LLMProvider: Sendable {
    /// The model identifier this provider is configured for.
    var model: String { get }
    /// Complete `messages`, offering `tools` the model may call.
    func complete(messages: [LLMMessage], tools: [LLMTool]) async throws -> LLMResponse
}
