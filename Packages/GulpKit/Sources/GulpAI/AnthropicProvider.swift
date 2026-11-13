// GulpAI — the Anthropic Messages API provider (F22 AI-001; Claude is the v1 provider, doc 07 #5). It
// formats the conversation and tools as the Messages API expects and parses the `text`/`tool_use`
// content blocks, stop reason and token usage back out. The HTTP transport is injected (`send`: request
// body -> response body), so the wire formatting and parsing are tested with a canned response while
// the workspace supplies the real engine call (api.anthropic.com, the key from the Keychain) at
// runtime. No key or network is needed to test this type.

import Foundation

/// A provider backed by Anthropic's Messages API.
public struct AnthropicProvider: LLMProvider {
    public let model: String
    public let maxTokens: Int
    private let send: @Sendable (Data) async throws -> Data

    /// `send` performs the HTTPS POST (body in, body out); the workspace wires it to the engine with
    /// the `x-api-key`/`anthropic-version` headers.
    public init(
        model: String = "claude-sonnet-4-5", maxTokens: Int = 1024,
        send: @escaping @Sendable (Data) async throws -> Data
    ) {
        self.model = model
        self.maxTokens = maxTokens
        self.send = send
    }

    /// The request body for `messages`/`tools`, as the Messages API expects it.
    public func requestBody(messages: [LLMMessage], tools: [LLMTool]) -> Data {
        var system = ""
        var apiMessages: [[String: Any]] = []
        for message in messages {
            switch message.role {
            case .system:
                system += (system.isEmpty ? "" : "\n") + message.content
            case .user:
                apiMessages.append(["role": "user", "content": message.content])
            case .assistant:
                apiMessages.append(["role": "assistant", "content": message.content])
            case .tool:
                // A tool result is a user turn with a tool_result content block.
                apiMessages.append([
                    "role": "user",
                    "content": [
                        [
                            "type": "tool_result", "tool_use_id": message.toolCallID ?? "",
                            "content": message.content,
                        ]
                    ],
                ])
            }
        }
        var body: [String: Any] = [
            "model": model, "max_tokens": maxTokens, "messages": apiMessages,
        ]
        if !system.isEmpty { body["system"] = system }
        if !tools.isEmpty {
            body["tools"] = tools.map { tool -> [String: Any] in
                let schema =
                    (try? JSONSerialization.jsonObject(with: Data(tool.schema.utf8))) as? [String: Any]
                    ?? ["type": "object"]
                return ["name": tool.name, "description": tool.description, "input_schema": schema]
            }
        }
        return (try? JSONSerialization.data(withJSONObject: body)) ?? Data("{}".utf8)
    }

    /// Parse a Messages API response body into an `LLMResponse`.
    public func parse(_ data: Data) -> LLMResponse {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return LLMResponse(text: nil, stopReason: .stop)
        }
        var text: String?
        var toolCalls: [LLMToolCall] = []
        for block in object["content"] as? [[String: Any]] ?? [] {
            switch block["type"] as? String {
            case "text":
                text = (text ?? "") + (block["text"] as? String ?? "")
            case "tool_use":
                let input =
                    (block["input"] as? [String: Any]).flatMap {
                        try? JSONSerialization.data(withJSONObject: $0)
                    }.map { String(decoding: $0, as: UTF8.self) } ?? "{}"
                toolCalls.append(
                    LLMToolCall(
                        id: block["id"] as? String ?? "", name: block["name"] as? String ?? "",
                        arguments: input))
            default:
                break
            }
        }
        let usage = object["usage"] as? [String: Any]
        let stop: LLMStopReason
        switch object["stop_reason"] as? String {
        case "tool_use": stop = .toolUse
        case "max_tokens": stop = .maxTokens
        case "end_turn": stop = .endTurn
        default: stop = toolCalls.isEmpty ? .endTurn : .toolUse
        }
        return LLMResponse(
            text: text, toolCalls: toolCalls, stopReason: stop,
            inputTokens: usage?["input_tokens"] as? Int ?? 0,
            outputTokens: usage?["output_tokens"] as? Int ?? 0)
    }

    public func complete(messages: [LLMMessage], tools: [LLMTool]) async throws -> LLMResponse {
        parse(try await send(requestBody(messages: messages, tools: tools)))
    }
}
