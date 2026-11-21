// GulpAI — the Anthropic Messages API provider (F22 AI-001; Claude is the v1 provider, doc 07 #5). It
// formats the conversation and tools as the Messages API expects and parses the `text`/`tool_use`
// content blocks, stop reason and token usage back out. The HTTP transport is injected (`send`: request
// body -> response body), so the wire formatting and parsing are tested with a canned response while
// the workspace supplies the real engine call (api.anthropic.com, the key from the Keychain) at
// runtime. No key or network is needed to test this type.
//
// Tool use on the wire: an assistant turn is a `text` block (when there is text) followed by one
// `tool_use` block per call; the next user turn holds one `tool_result` block per call, all in that
// single message, each naming the `tool_use_id` it answers.

import Foundation

/// A provider backed by Anthropic's Messages API.
public struct AnthropicProvider: LLMProvider {
    /// The model id sent with every request.
    public let model: String
    /// The per-response output cap.
    public let maxTokens: Int
    private let send: @Sendable (Data) async throws -> Data

    /// An error response from the Messages API (`{"type":"error","error":{…}}`), or a body that is
    /// not a Messages API response at all.
    public struct APIError: Error, Sendable, Equatable, CustomStringConvertible {
        /// The API's error type (`invalid_request_error`, `overloaded_error`, …), or `invalid_response`.
        public var type: String
        /// The API's message.
        public var message: String
        /// A readable form of the error: `type: message`.
        public var description: String { "\(type): \(message)" }
    }

    /// `send` performs the HTTPS POST (body in, body out); the workspace wires it to the engine with
    /// the `x-api-key`/`anthropic-version` headers. The app overrides `model` from the AI settings.
    public init(
        model: String = "claude-opus-5-5", maxTokens: Int = 16_000,
        send: @escaping @Sendable (Data) async throws -> Data
    ) {
        self.model = model
        self.maxTokens = maxTokens
        self.send = send
    }

    /// The request body for `messages`/`tools`, as the Messages API expects it. Throws when a tool
    /// call's arguments or a tool's schema is not a JSON object.
    public func requestBody(messages: [LLMMessage], tools: [LLMTool]) throws -> Data {
        var system = ""
        var apiMessages: [[String: Any]] = []
        for message in messages {
            switch message.role {
            case .system:
                system += (system.isEmpty ? "" : "\n") + message.content
            case .user:
                apiMessages.append(["role": "user", "content": message.content])
            case .assistant:
                var blocks: [[String: Any]] = []
                if !message.content.isEmpty { blocks.append(["type": "text", "text": message.content]) }
                for call in message.toolCalls {
                    blocks.append([
                        "type": "tool_use", "id": call.id, "name": call.name,
                        "input": try Self.object(call.arguments, what: "arguments of tool call \(call.id)"),
                    ])
                }
                apiMessages.append(["role": "assistant", "content": blocks])
            case .tool:
                let result: [String: Any] = [
                    "type": "tool_result", "tool_use_id": message.toolCallID ?? "",
                    "content": message.content,
                ]
                // All of one turn's results go in one user message, right after the assistant turn.
                if let last = apiMessages.last, last["role"] as? String == "user",
                    var blocks = last["content"] as? [[String: Any]]
                {
                    blocks.append(result)
                    apiMessages[apiMessages.count - 1]["content"] = blocks
                } else {
                    apiMessages.append(["role": "user", "content": [result]])
                }
            }
        }
        var body: [String: Any] = [
            "model": model, "max_tokens": maxTokens, "messages": apiMessages,
        ]
        if !system.isEmpty { body["system"] = system }
        if !tools.isEmpty {
            body["tools"] = try tools.map { tool -> [String: Any] in
                [
                    "name": tool.name, "description": tool.description,
                    "input_schema": try Self.object(tool.schema, what: "schema of tool \(tool.name)"),
                ]
            }
        }
        return try JSONSerialization.data(withJSONObject: body)
    }

    /// `json` parsed as a JSON object.
    static func object(_ json: String, what: String) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] else {
            throw APIError(type: "invalid_request", message: "The \(what) is not a JSON object.")
        }
        return object
    }

    /// Parse a Messages API response body into an `LLMResponse`; an error body throws `APIError`.
    public func parse(_ data: Data) throws -> LLMResponse {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            object["type"] as? String != "error"
        else {
            let error =
                (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"]
                as? [String: Any]
            throw APIError(
                type: error?["type"] as? String ?? "invalid_response",
                message: error?["message"] as? String ?? String(decoding: data.prefix(500), as: UTF8.self))
        }
        var text: String?
        var toolCalls: [LLMToolCall] = []
        for block in object["content"] as? [[String: Any]] ?? [] {
            switch block["type"] as? String {
            case "text":
                text = (text ?? "") + (block["text"] as? String ?? "")
            case "tool_use":
                let input = try JSONSerialization.data(
                    withJSONObject: block["input"] as? [String: Any] ?? [:])
                toolCalls.append(
                    LLMToolCall(
                        id: block["id"] as? String ?? "", name: block["name"] as? String ?? "",
                        arguments: String(decoding: input, as: UTF8.self)))
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

    /// Sends `messages` and `tools` through the injected transport and parses the reply.
    public func complete(messages: [LLMMessage], tools: [LLMTool]) async throws -> LLMResponse {
        try parse(try await send(requestBody(messages: messages, tools: tools)))
    }
}
