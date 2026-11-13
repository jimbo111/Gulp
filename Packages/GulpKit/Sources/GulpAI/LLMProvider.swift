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

/// One message in the conversation.
public struct LLMMessage: Sendable, Codable, Equatable {
    public var role: LLMRole
    public var content: String
    /// For a `tool` message, the id of the tool call it answers.
    public var toolCallID: String?

    public init(role: LLMRole, content: String, toolCallID: String? = nil) {
        self.role = role
        self.content = content
        self.toolCallID = toolCallID
    }
}

/// A tool the assistant may call (the F21 agent surface: list/get exchanges, search, send, scan, …).
public struct LLMTool: Sendable, Codable, Equatable {
    public var name: String
    public var description: String
    /// A JSON-schema object (as a JSON string) describing the arguments.
    public var schema: String

    public init(name: String, description: String, schema: String = "{}") {
        self.name = name
        self.description = description
        self.schema = schema
    }
}

/// A tool call the model asked for.
public struct LLMToolCall: Sendable, Codable, Equatable {
    public var id: String
    public var name: String
    /// The arguments as a JSON object string.
    public var arguments: String

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
    public var text: String?
    public var toolCalls: [LLMToolCall]
    public var stopReason: LLMStopReason
    /// Tokens used (for the budget/usage display, AI-010), if the provider reports them.
    public var inputTokens: Int
    public var outputTokens: Int

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
