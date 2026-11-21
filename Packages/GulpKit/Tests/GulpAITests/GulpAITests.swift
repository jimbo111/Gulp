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

    @Test(
        "AI-003: redaction is linear on attacker-shaped input (no catastrophic backtracking)",
        arguments: [
            ("a", 1 << 20),  // a 1 MB name-character run with no keyword
            ("eyJ-", 1 << 18),  // JWT starts with no dot
            ("\"a", 1 << 19),  // quote-name runs with no keyword
            ("-----BEGIN PRIVATE KEY-----\n", 1 << 15),  // BEGIN lines, no END
        ])
    func test_AI003_linearTime(unit: String, count: Int) {
        let input = String(repeating: unit, count: count)
        let elapsed = ContinuousClock().measure { _ = Redactor().redact(input) }
        #expect(elapsed < .seconds(1))
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
    @Test("AI-001: assistant turns carry text + tool_use; one turn's tool results share one user message")
    func test_AI001_requestBodyToolRound() throws {
        let provider = AnthropicProvider(model: "claude-opus-5-5", send: { _ in Data() })
        let body = try provider.requestBody(
            messages: [
                LLMMessage(role: .system, content: "you are Gulp"),
                LLMMessage(role: .user, content: "explain this"),
                LLMMessage(
                    role: .assistant, content: "Let me look.",
                    toolCalls: [
                        LLMToolCall(id: "tc1", name: "search", arguments: #"{"q":"a"}"#),
                        LLMToolCall(id: "tc2", name: "search", arguments: #"{"q":"b"}"#),
                    ]),
                LLMMessage(role: .tool, content: "exchange 5", toolCallID: "tc1"),
                LLMMessage(role: .tool, content: "nothing", toolCallID: "tc2"),
            ],
            tools: [LLMTool(name: "search", description: "search", schema: #"{"type":"object"}"#)])
        let object = try #require(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        #expect(object["model"] as? String == "claude-opus-5-5")
        #expect(object["system"] as? String == "you are Gulp")
        #expect((object["tools"] as? [[String: Any]])?.first?["name"] as? String == "search")
        let messages = try #require(object["messages"] as? [[String: Any]])
        #expect(messages.map { $0["role"] as? String } == ["user", "assistant", "user"])
        let assistant = try #require(messages[1]["content"] as? [[String: Any]])
        #expect(assistant.map { $0["type"] as? String } == ["text", "tool_use", "tool_use"])
        #expect(assistant[0]["text"] as? String == "Let me look.")
        #expect(assistant[1]["id"] as? String == "tc1" && assistant[1]["name"] as? String == "search")
        #expect((assistant[1]["input"] as? [String: Any])?["q"] as? String == "a")
        let results = try #require(messages[2]["content"] as? [[String: Any]])
        #expect(results.map { $0["type"] as? String } == ["tool_result", "tool_result"])
        #expect(results.map { $0["tool_use_id"] as? String } == ["tc1", "tc2"])
        #expect(results[0]["content"] as? String == "exchange 5")
    }

    @Test("AI-001: after a tool round the agent's next request answers every tool_use it made")
    func test_AI001_agentSecondRoundIsValid() async throws {
        let scripted = ScriptedProvider([
            LLMResponse(
                text: "Checking.",
                toolCalls: [
                    LLMToolCall(id: "t1", name: "search", arguments: "{}"),
                    LLMToolCall(id: "t2", name: "search", arguments: "{}"),
                ], stopReason: .toolUse),
            LLMResponse(text: "Done.", stopReason: .endTurn),
        ])
        _ = try await Agent(provider: scripted).run(
            system: "s", user: "go", tools: [LLMTool(name: "search", description: "search")],
            execute: { _ in ToolOutcome(content: "ok") })
        let second = try #require(scripted.received.last)
        let body = try AnthropicProvider(send: { _ in Data() }).requestBody(messages: second, tools: [])
        let object = try #require(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        let messages = try #require(object["messages"] as? [[String: Any]])
        // The user turn of tool_results follows an assistant turn with the matching tool_use ids.
        #expect(messages.map { $0["role"] as? String } == ["user", "assistant", "user"])
        let blocks = messages[1]["content"] as? [[String: Any]] ?? []
        let uses = blocks.filter { $0["type"] as? String == "tool_use" }
        let results = messages[2]["content"] as? [[String: Any]] ?? []
        #expect(uses.map { $0["id"] as? String } == ["t1", "t2"])
        #expect(results.map { $0["tool_use_id"] as? String } == ["t1", "t2"])
    }

    @Test("AI-001: an API error body is an error, not an empty answer")
    func test_AI001_errorBodyThrows() {
        let provider = AnthropicProvider(send: { _ in Data() })
        let error = Data(
            #"{"type":"error","error":{"type":"invalid_request_error","message":"bad tool_use_id"}}"#.utf8)
        #expect(throws: AnthropicProvider.APIError.self) { try provider.parse(error) }
    }

    @Test("a text + tool_use response parses into an LLMResponse with usage")
    func parseResponse() throws {
        let provider = AnthropicProvider(send: { _ in Data() })
        let json = Data(
            #"""
            {"content":[{"type":"text","text":"Let me look."},
                        {"type":"tool_use","id":"tu1","name":"search","input":{"q":"token"}}],
             "stop_reason":"tool_use","usage":{"input_tokens":12,"output_tokens":7}}
            """#.utf8)
        let response = try provider.parse(json)
        #expect(response.text == "Let me look.")
        #expect(response.toolCalls == [LLMToolCall(id: "tu1", name: "search", arguments: #"{"q":"token"}"#)])
        #expect(response.stopReason == .toolUse)
        #expect(response.inputTokens == 12 && response.outputTokens == 7)
    }
}
