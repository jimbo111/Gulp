import Foundation
import Testing

@testable import GulpAI

@Suite("GulpAI scaffolding")
struct GulpAIScaffolding {
    @Test("module marker is wired")
    func moduleMarker() { #expect(GulpAI.moduleName == "GulpAI") }
}

@Suite("GulpAI — redaction (AI-003)")
struct RedactionTests {
    @Test("secrets are masked; header names are kept; disabling is a no-op")
    func redact() {
        let redactor = Redactor()
        let text =
            "GET / HTTP/1.1\r\nAuthorization: Bearer abcdef123456\r\nCookie: SID=secretvalue\r\n"
            + "aws=AKIAIOSFODNN7EXAMPLE api_key: 0123456789abcdef"
        let result = redactor.redact(text)
        #expect(result.text.contains("Authorization: [REDACTED]"))
        #expect(result.text.contains("Cookie: [REDACTED]"))
        #expect(!result.text.contains("AKIAIOSFODNN7EXAMPLE"))
        #expect(!result.text.contains("secretvalue"))
        #expect(result.total >= 3)
        // Disabled leaves the text untouched.
        #expect(Redactor(enabled: false).redact(text).text == text)
    }

    @Test("AI-003: a PEM private key is masked whole, body included (also when the END line is cut off)")
    func test_AI003_privateKeyBody() {
        let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
        let pem = "key:\n-----BEGIN PRIVATE KEY-----\n\(body)\nAbCd==\n-----END PRIVATE KEY-----\nafter"
        let result = Redactor().redact(pem)
        #expect(!result.text.contains(body) && !result.text.contains("AbCd=="))
        #expect(result.text == "key:\n[REDACTED]\nafter")
        let truncated = Redactor().redact("-----BEGIN RSA PRIVATE KEY-----\n\(body)\n")
        #expect(!truncated.text.contains(body))
    }

    @Test("AI-003: JSON-quoted secrets keep their key and lose their value")
    func test_AI003_jsonSecrets() {
        let json =
            #"{"user":"bob","password":"hunter22","#
            + #""access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln","api_key": "k\"9"}"#
        let result = Redactor().redact(json).text
        #expect(result.contains(#""user":"bob""#))
        #expect(result.contains(#""password":"[REDACTED]""#))
        #expect(result.contains(#""access_token":"[REDACTED]""#))
        #expect(result.contains(#""api_key": "[REDACTED]""#))
        #expect(!result.contains("hunter22") && !result.contains("eyJhbGci") && !result.contains(#"k\"9"#))
    }

    @Test("AI-003: Proxy-Authorization values are masked like Authorization")
    func test_AI003_proxyAuthorization() {
        let text = "GET http://x/ HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nHost: x\r\n\r\n"
        let result = Redactor().redact(text).text
        #expect(result.contains("Proxy-Authorization: [REDACTED]\r\n"))
        #expect(!result.contains("dXNlcjpwYXNz") && result.contains("Host: x"))
    }

    @Test("AI-003: a bare JWT anywhere in the text is masked")
    func test_AI003_bareJWT() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let result = Redactor().redact("GET /session/\(jwt)/view?x=1 HTTP/1.1")
        #expect(result.text == "GET /session/[REDACTED]/view?x=1 HTTP/1.1")
    }
}

/// A provider that returns a scripted sequence of responses and records what it was asked.
final class ScriptedProvider: LLMProvider, @unchecked Sendable {
    let model = "mock"
    private let lock = NSLock()
    private var queue: [LLMResponse]
    private var _received: [[LLMMessage]] = []
    var received: [[LLMMessage]] { lock.withLock { _received } }

    init(_ responses: [LLMResponse]) { queue = responses }

    func complete(messages: [LLMMessage], tools: [LLMTool]) async throws -> LLMResponse {
        lock.withLock {
            _received.append(messages)
            return queue.isEmpty ? LLMResponse(text: "done", stopReason: .endTurn) : queue.removeFirst()
        }
    }
}

@Suite("GulpAI — bounded agentic loop (AI-013)")
struct AgentTests {
    let searchTool = LLMTool(name: "search", description: "search history")

    @Test("the loop runs a tool, feeds back a redacted result, and returns the final answer")
    func answered() async throws {
        let provider = ScriptedProvider([
            LLMResponse(
                toolCalls: [LLMToolCall(id: "1", name: "search", arguments: #"{"q":"token"}"#)],
                stopReason: .toolUse),
            LLMResponse(text: "The token comes from /login.", stopReason: .endTurn),
        ])
        let agent = Agent(provider: provider)
        let result = try await agent.run(
            system: "s", user: "where is the token?", tools: [searchTool],
            execute: { _ in ToolOutcome(content: "exchange 5 carried Bearer abcdef123456789") })
        #expect(result.stop == .answered)
        #expect(result.answer == "The token comes from /login.")
        #expect(result.steps == 2)
        // The tool result fed back on the 2nd round-trip was redacted.
        let fedBack = provider.received.last?.first { $0.role == .tool }
        #expect(fedBack?.content.contains("[REDACTED]") == true)
    }

    @Test("the step budget stops a model that keeps calling tools")
    func stepBudget() async throws {
        let loop = LLMResponse(
            toolCalls: [LLMToolCall(id: "x", name: "search", arguments: "{}")], stopReason: .toolUse)
        let agent = Agent(provider: ScriptedProvider(Array(repeating: loop, count: 20)))
        let result = try await agent.run(
            system: "s", user: "go", tools: [searchTool], limits: AgentLimits(maxSteps: 3),
            execute: { _ in ToolOutcome(content: "ok") })
        #expect(result.stop == .stepBudget)
        #expect(result.steps == 3)
    }

    @Test("the request budget blocks active sends past the cap")
    func requestBudget() async throws {
        let send = LLMResponse(
            toolCalls: [LLMToolCall(id: "s", name: "sendRequest", arguments: "{}")], stopReason: .toolUse)
        let agent = Agent(provider: ScriptedProvider(Array(repeating: send, count: 20)))
        let result = try await agent.run(
            system: "s", user: "probe", tools: [LLMTool(name: "sendRequest", description: "send")],
            limits: AgentLimits(maxSteps: 10, maxRequests: 1), sendTools: ["sendRequest"],
            execute: { _ in ToolOutcome(content: "HTTP/1.1 200 OK", countsAsRequest: true) })
        #expect(result.stop == .requestBudget)
        #expect(result.requests == 1)
    }

    @Test("the kill switch / panic stop ends the run immediately")
    func cancelled() async throws {
        let agent = Agent(provider: ScriptedProvider([]))
        let result = try await agent.run(
            system: "s", user: "go", tools: [searchTool], isCancelled: { true },
            execute: { _ in ToolOutcome(content: "ok") })
        #expect(result.stop == .cancelled)
        #expect(result.steps == 0)
    }
}

@Suite("GulpAI — Anthropic provider wire format (AI-001)")
struct AnthropicProviderTests {
    @Test("the request body carries system, messages, tool results and tools")
    func requestBody() throws {
        let provider = AnthropicProvider(model: "claude-sonnet-4-5", send: { _ in Data() })
        let body = provider.requestBody(
            messages: [
                LLMMessage(role: .system, content: "you are Gulp"),
                LLMMessage(role: .user, content: "explain this"),
                LLMMessage(role: .tool, content: "exchange 5", toolCallID: "tc1"),
            ],
            tools: [LLMTool(name: "search", description: "search", schema: #"{"type":"object"}"#)])
        let object = try #require(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        #expect(object["model"] as? String == "claude-sonnet-4-5")
        #expect(object["system"] as? String == "you are Gulp")
        let messages = try #require(object["messages"] as? [[String: Any]])
        #expect(messages.count == 2)  // user + the tool-result user turn
        let toolResult = ((messages.last?["content"] as? [[String: Any]])?.first)
        #expect(toolResult?["type"] as? String == "tool_result")
        #expect(toolResult?["tool_use_id"] as? String == "tc1")
        #expect((object["tools"] as? [[String: Any]])?.first?["name"] as? String == "search")
    }

    @Test("a text + tool_use response parses into an LLMResponse with usage")
    func parseResponse() {
        let provider = AnthropicProvider(send: { _ in Data() })
        let json = Data(
            #"""
            {"content":[{"type":"text","text":"Let me look."},
                        {"type":"tool_use","id":"tu1","name":"search","input":{"q":"token"}}],
             "stop_reason":"tool_use","usage":{"input_tokens":12,"output_tokens":7}}
            """#.utf8)
        let response = provider.parse(json)
        #expect(response.text == "Let me look.")
        #expect(response.toolCalls == [LLMToolCall(id: "tu1", name: "search", arguments: #"{"q":"token"}"#)])
        #expect(response.stopReason == .toolUse)
        #expect(response.inputTokens == 12 && response.outputTokens == 7)
    }
}
