// GulpWorkspace — the agent tool surface and its gate (architecture §3 rule 6; F21 AUT-021/AUT-023,
// F22 AI-004). The tools an automated or AI caller can run — their names, JSON schemas, argument
// checks and JSON results — are defined once here, and every call goes through `APIGate.call`:
//
//   validate → (active tools) ScopeGuard → approval policy → send → audit
//
// The MCP server (GulpAutomation) and the assistant (GulpAI) are thin adapters over this one gate, so
// they expose identical capabilities under identical rules. Every call is written to the project's
// audit log, attributed to its caller; a call whose audit write fails fails (it throws), so no agent
// action goes unrecorded without the caller knowing. Refusals (bad arguments, out of scope, not
// approved) are not failures: they come back as structured JSON errors the model can read and act on.

import Foundation
import GulpCore
import GulpHTTP
import GulpStore

/// How agent-initiated active actions are approved (AUT-023).
public enum ApprovalPolicy: String, Sendable, CaseIterable, Codable {
    /// In-scope actions run; out-of-scope ones are refused. Headless, this must be chosen
    /// explicitly (AUT-023).
    case inScope = "in-scope"
    /// Every active action needs a human yes from the approver (the app); without one it is refused.
    case ask
    /// Active actions are always refused (read-only agent). The default.
    case deny
}

/// An active action an agent asked for, shown to the human who approves it.
public struct AgentAction: Sendable, Hashable {
    /// Who asked, as written to the audit log (`mcp:claude-code`, `ai:claude-opus-5-5`, …).
    public var caller: String
    /// The tool (`send_request`).
    public var tool: String
    /// What it touches (`https://host:443/path`).
    public var target: String
    /// The request text (for review), truncated.
    public var preview: String
}

/// One tool of the agent surface.
public struct AgentTool: Sendable, Equatable {
    /// The tool's name (`list_exchanges`, …).
    public var name: String
    /// A short human title.
    public var title: String
    /// What the tool does, written for a model.
    public var description: String
    /// The JSON schema of the arguments, as JSON object text.
    public var inputSchema: String
    /// Whether the tool acts on a target (ScopeGuard, the approval policy and request budgets apply).
    public var isActive: Bool
}

/// The result of a tool call.
public struct AgentToolResult: Sendable, Equatable {
    /// The structured result, a JSON object (`{"error": {"code": …, "message": …}}` when refused).
    public var json: Data
    /// Whether the call was refused or failed (bad arguments, out of scope, not approved, send error).
    public var isError: Bool
    /// Whether a request was sent to a target (counts against request budgets).
    public var sent: Bool
}

/// Errors that fail a tool call (as opposed to refusals, which are results).
public enum APIGateError: Error, Sendable, Equatable {
    /// No tool has this name.
    case unknownTool(String)
}

/// The single gate every agent tool call goes through (architecture §3 rule 6).
public struct APIGate: Sendable {
    /// Bodies longer than this are cut in tool results (with a continuation offset).
    public static let defaultMaxBytes = 16_384

    let session: ProjectSession
    let source: ToolSource
    let policy: ApprovalPolicy
    let approver: (@Sendable (AgentAction) async -> Bool)?

    /// A gate for `session`. Sends are recorded with `source` (`.automation` for MCP/REST, `.ai` for
    /// the assistant); `approver` asks a human (the app) when `policy` is `.ask`.
    public init(
        session: ProjectSession, source: ToolSource, policy: ApprovalPolicy = .deny,
        approver: (@Sendable (AgentAction) async -> Bool)? = nil
    ) {
        self.session = session
        self.source = source
        self.policy = policy
        self.approver = approver
    }

    // MARK: the tools (AUT-021)

    /// The tool surface, in a stable order.
    public static let tools: [AgentTool] = [
        AgentTool(
            name: "list_exchanges", title: "List HTTP history",
            description:
                "List recorded HTTP exchanges (newest last), with optional filters. Returns id, method, URL, "
                + "status, length, MIME type and source; use get_exchange for the full messages.",
            inputSchema: schema(
                [
                    "text": ["type": "string", "description": "Substring of host or path."],
                    "in_scope_only": ["type": "boolean"],
                    "status_class": [
                        "type": "integer", "minimum": 1, "maximum": 5, "description": "1…5 for 1xx…5xx.",
                    ],
                    "method": ["type": "string"],
                    "source": [
                        "type": "string",
                        "enum": ["proxy", "repeater", "fuzzer", "scanner", "crawler", "automation", "ai"],
                    ],
                    "offset": ["type": "integer", "minimum": 0, "default": 0],
                    "limit": ["type": "integer", "minimum": 1, "maximum": 100, "default": 20],
                ], required: []),
            isActive: false),
        AgentTool(
            name: "get_exchange", title: "Get an exchange",
            description:
                "The raw request and response of one exchange as text. Messages longer than max_bytes are "
                + "cut; call again with offset = next_offset to continue.",
            inputSchema: schema(
                [
                    "id": ["type": "integer", "minimum": 1],
                    "part": ["type": "string", "enum": ["both", "request", "response"], "default": "both"],
                    "offset": ["type": "integer", "minimum": 0, "default": 0],
                    "max_bytes": [
                        "type": "integer", "minimum": 256, "maximum": 262_144, "default": defaultMaxBytes,
                    ],
                ], required: ["id"]),
            isActive: false),
        AgentTool(
            name: "send_request", title: "Send a raw HTTP request",
            description:
                "Send raw HTTP/1.1 request text to a target URL (scheme://host[:port]) and return the "
                + "response. The bytes are sent as written, except: if the text has no CRLF, its bare LF "
                + "line endings become CRLF; a missing blank line after the headers is added; and "
                + "Content-Length is set to the body length unless update_content_length is false. The "
                + "target must be in the project's scope; out-of-scope sends are refused. The exchange is "
                + "recorded in history.",
            inputSchema: schema(
                [
                    "raw": [
                        "type": "string",
                        "description": "The full request: request line, headers, blank line, body.",
                    ],
                    "target": [
                        "type": "string", "description": "scheme://host[:port], e.g. https://example.com",
                    ],
                    "update_content_length": ["type": "boolean", "default": true],
                    "follow_redirects": ["type": "boolean", "default": false],
                    "timeout_seconds": ["type": "integer", "minimum": 1, "maximum": 120, "default": 30],
                    "max_bytes": [
                        "type": "integer", "minimum": 256, "maximum": 262_144, "default": defaultMaxBytes,
                    ],
                ], required: ["raw", "target"]),
            isActive: true),
        AgentTool(
            name: "get_scope", title: "Get the scope",
            description:
                "The project's scope rules (last match wins; no match is out of scope) and a summary.",
            inputSchema: schema([:], required: []),
            isActive: false),
    ]

    static func schema(_ properties: [String: Any], required: [String]) -> String {
        let object: [String: Any] = [
            "type": "object", "properties": properties, "required": required, "additionalProperties": false,
        ]
        // A literal schema above; one that does not serialize is a programming error.
        return String(decoding: try! encode(object), as: UTF8.self)
    }

    // MARK: calls

    /// Run tool `name` with `arguments` (a JSON object) for `caller` (the audit log's actor,
    /// `mcp:claude-code`, `ai:claude-opus-5-5`, …). Throws for an unknown tool, and when the audit
    /// write fails — after a send, too: the caller then knows the action went unrecorded.
    public func call(_ name: String, arguments: Data, caller: String) async throws -> AgentToolResult {
        guard let tool = Self.tools.first(where: { $0.name == name }) else {
            throw APIGateError.unknownTool(name)
        }
        let parsed = try? JSONSerialization.jsonObject(with: arguments.isEmpty ? Data("{}".utf8) : arguments)
        guard let arguments = parsed as? [String: Any] else {
            return try await refuse(
                caller, name, nil, "invalid_arguments", "arguments must be a JSON object.")
        }
        let schema = try JSONSerialization.jsonObject(with: Data(tool.inputSchema.utf8)) as? [String: Any]
        if let problem = Self.validate(arguments, against: schema ?? [:]) {
            return try await refuse(caller, name, nil, "invalid_arguments", problem)
        }
        switch name {
        case "list_exchanges": return try await listExchanges(arguments, caller: caller)
        case "get_exchange": return try await getExchange(arguments, caller: caller)
        case "send_request": return try await sendRequest(arguments, caller: caller)
        default: return try await getScope(caller: caller)
        }
    }

    /// Write one entry to the audit log (AUT-023). Callers with their own reads (MCP resources) use
    /// this so every agent action lands in the same log; a failed write throws.
    public func audit(caller: String, action: String, target: String?, outcome: String, detail: String?)
        async throws
    {
        try await session.store.appendAudit(
            actor: caller, action: action, target: target, outcome: outcome, detail: detail)
    }

    /// Audit a refusal and return it as a structured error result.
    func refuse(
        _ caller: String, _ action: String, _ target: String?, _ code: String, _ message: String,
        outcome: String = "error", detail: String? = nil, extra: [String: Any] = [:]
    ) async throws -> AgentToolResult {
        try await audit(
            caller: caller, action: action, target: target, outcome: outcome, detail: detail ?? message)
        var error: [String: Any] = ["code": code, "message": message]
        error.merge(extra) { _, new in new }
        return AgentToolResult(json: try Self.encode(["error": error]), isError: true, sent: false)
    }

    /// Check `arguments` against a flat tool schema: required keys, no unknown keys, JSON types,
    /// enums and integer bounds.
    static func validate(_ arguments: [String: Any], against schema: [String: Any]) -> String? {
        let properties = schema["properties"] as? [String: [String: Any]] ?? [:]
        for key in schema["required"] as? [String] ?? [] where arguments[key] == nil {
            return "Missing required argument \"\(key)\"."
        }
        for (key, value) in arguments {
            guard let property = properties[key] else { return "Unknown argument \"\(key)\"." }
            switch property["type"] as? String {
            case "string":
                guard let text = value as? String else { return "\"\(key)\" must be a string." }
                if let choices = property["enum"] as? [String], !choices.contains(text) {
                    return "\"\(key)\" must be one of \(choices.joined(separator: ", "))."
                }
            case "boolean":
                guard isBoolean(value) else { return "\"\(key)\" must be true or false." }
            case "integer":
                guard let number = value as? NSNumber, !isBoolean(value),
                    number.doubleValue == number.doubleValue.rounded()
                else { return "\"\(key)\" must be an integer." }
                if let minimum = property["minimum"] as? Int, number.intValue < minimum {
                    return "\"\(key)\" must be at least \(minimum)."
                }
                if let maximum = property["maximum"] as? Int, number.intValue > maximum {
                    return "\"\(key)\" must be at most \(maximum)."
                }
            default: break
            }
        }
        return nil
    }

    static func isBoolean(_ value: Any) -> Bool {
        guard let number = value as? NSNumber else { return value is Bool }
        #if canImport(Darwin)
        return CFGetTypeID(number) == CFBooleanGetTypeID()
        #else
        return String(cString: number.objCType) == "c" || type(of: value) == Bool.self
        #endif
    }

    /// `value` as compact JSON with sorted keys.
    static func encode(_ value: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    func result(_ value: [String: Any], isError: Bool = false, sent: Bool = false) throws -> AgentToolResult {
        AgentToolResult(json: try Self.encode(value), isError: isError, sent: sent)
    }

    // MARK: read tools

    func listExchanges(_ arguments: [String: Any], caller: String) async throws -> AgentToolResult {
        var filter = HistoryFilter()
        filter.text = arguments["text"] as? String
        filter.inScopeOnly = arguments["in_scope_only"] as? Bool ?? false
        if let statusClass = (arguments["status_class"] as? NSNumber)?.intValue {
            filter.statusClasses = [statusClass]
        }
        if let method = arguments["method"] as? String { filter.methods = [method.uppercased()] }
        if let source = arguments["source"] as? String { filter.source = ToolSource(rawValue: source) }
        let offset = (arguments["offset"] as? NSNumber)?.intValue ?? 0
        let limit = (arguments["limit"] as? NSNumber)?.intValue ?? 20
        let store = await session.store
        await store.writer.flush()
        let total = try await store.count(filter: filter)
        let rows = try await store.summaries(filter: filter, offset: offset, limit: limit)
        let formatter = ISO8601DateFormatter()
        var value: [String: Any] = [
            "total": total, "offset": offset,
            "exchanges": rows.map { row -> [String: Any] in
                var item: [String: Any] = [
                    "id": row.id, "method": row.method ?? "", "url": row.url, "source": row.source.rawValue,
                    "time": formatter.string(from: row.createdAt),
                ]
                if let status = row.status { item["status"] = status }
                if let length = row.responseLength { item["length"] = length }
                if let mime = row.mime { item["mime"] = mime }
                if let comment = row.comment, !comment.isEmpty { item["comment"] = comment }
                return item
            },
        ]
        if offset + rows.count < total { value["next_offset"] = offset + rows.count }
        try await audit(
            caller: caller, action: "list_exchanges", target: nil, outcome: "read",
            detail: "\(rows.count) of \(total)")
        return try result(value)
    }

    func getExchange(_ arguments: [String: Any], caller: String) async throws -> AgentToolResult {
        let id = ExchangeID((arguments["id"] as? NSNumber)?.int64Value ?? 0)
        let part = arguments["part"] as? String ?? "both"
        let offset = (arguments["offset"] as? NSNumber)?.intValue ?? 0
        let maxBytes = (arguments["max_bytes"] as? NSNumber)?.intValue ?? Self.defaultMaxBytes
        let store = await session.store
        await store.writer.flush()
        guard let exchange = try await store.exchange(id: id) else {
            return try await refuse(caller, "get_exchange", nil, "not_found", "No exchange with id \(id).")
        }
        let url = Self.url(of: exchange)
        var value: [String: Any] = [
            "id": exchange.id, "url": url, "source": exchange.source.rawValue,
            "http_version": exchange.httpVersion.rawValue,
        ]
        if let status = exchange.derived.status { value["status"] = status }
        if part != "response" {
            value["request"] = Self.slice(exchange.request.bytes.rawBytes, offset: offset, max: maxBytes)
        }
        if part != "request" {
            value["response"] =
                exchange.response.map { Self.slice($0.wireBytes.rawBytes, offset: offset, max: maxBytes) }
                ?? NSNull()
        }
        try await audit(
            caller: caller, action: "get_exchange", target: url, outcome: "read", detail: "#\(id)")
        return try result(value)
    }

    func getScope(caller: String) async throws -> AgentToolResult {
        let scope = await session.scope()
        let rules = scope.rules.map { rule -> [String: Any] in
            [
                "kind": rule.kind.rawValue, "enabled": rule.enabled, "scheme": rule.scheme.rawValue,
                "host": rule.host, "host_is_regex": rule.hostIsRegex, "port": rule.port, "path": rule.path,
            ]
        }
        try await audit(caller: caller, action: "get_scope", target: nil, outcome: "read", detail: nil)
        return try result(["rules": rules, "summary": scope.summary])
    }

    // MARK: send_request (AUT-023: ScopeGuard → approval policy → send → audit)

    func sendRequest(_ arguments: [String: Any], caller: String) async throws -> AgentToolResult {
        let raw = arguments["raw"] as? String ?? ""
        let targetText = arguments["target"] as? String ?? ""
        guard let target = HTTPTarget(url: targetText) else {
            return try await refuse(
                caller, "send_request", targetText, "invalid_arguments",
                "target must be scheme://host[:port], e.g. https://example.com")
        }
        // Agents often write bare LF; HTTP needs CRLF. Normalize only text with no CR at all (the tool
        // description documents this and the Content-Length update).
        var text = raw
        if !text.contains("\r\n") { text = text.replacingOccurrences(of: "\n", with: "\r\n") }
        if !text.contains("\r\n\r\n") { text += text.hasSuffix("\r\n") ? "\r\n" : "\r\n\r\n" }
        let request = RawRequest(Bytes(text))
        let path = ScopeService.requestPath(of: request, target: target)
        let where_ = Self.url(target, path: path)
        guard request.parsed.warnings.isEmpty || !request.bytes[request.parsed.method].isEmpty else {
            return try await refuse(
                caller, "send_request", where_, "invalid_arguments",
                "raw is not an HTTP request (request line, headers, blank line).")
        }
        // ScopeGuard first (strict: an empty scope refuses everything), then the policy.
        let scopeGuard = session.scopeGuard
        do {
            try await scopeGuard.require(target, path: path)
        } catch {
            return try await refuse(
                caller, "send_request", where_, "out_of_scope",
                "\(where_) is outside the project's scope; Gulp refused to send it.", outcome: "refused",
                detail: "out of scope", extra: ["target": where_, "scope": await scopeGuard.current.summary])
        }
        switch policy {
        case .deny:
            return try await refuse(
                caller, "send_request", where_, "not_approved",
                "Active actions are disabled for agents in this project.", outcome: "refused",
                detail: "approval policy: deny")
        case .ask:
            let action = AgentAction(
                caller: caller, tool: "send_request", target: where_, preview: String(text.prefix(2_000)))
            guard let approver, await approver(action) else {
                return try await refuse(
                    caller, "send_request", where_, "not_approved", "The user did not approve this request.",
                    outcome: "refused", detail: "not approved")
            }
        case .inScope: break
        }
        var options = SendOptions(recordAs: source)
        options.updateContentLength = arguments["update_content_length"] as? Bool ?? true
        options.timeouts.total = .seconds((arguments["timeout_seconds"] as? NSNumber)?.intValue ?? 30)
        if arguments["follow_redirects"] as? Bool == true {
            options.followRedirects = RedirectPolicy(mode: .inScope)
            options.scope = await scopeGuard.current
        }
        let maxBytes = (arguments["max_bytes"] as? NSNumber)?.intValue ?? Self.defaultMaxBytes
        let started = ContinuousClock.now
        let sent = await session.http.send(request, to: target, options: options)
        let elapsed = ContinuousClock.now - started
        var value: [String: Any] = [
            "exchange_id": sent.exchange.id,
            "time_ms": Double(elapsed.components.seconds) * 1_000 + Double(elapsed.components.attoseconds)
                / 1e15,
        ]
        if let response = sent.exchange.response {
            value["status"] = response.parsed.statusCode
            value["response"] = Self.slice(response.wireBytes.rawBytes, offset: 0, max: maxBytes)
        }
        if !sent.redirectChain.isEmpty { value["redirect_exchange_ids"] = sent.redirectChain.map(\.id) }
        if let error = sent.error {
            value["error"] = ["code": error.code, "message": "\(error)"]
            try await audit(
                caller: caller, action: "send_request", target: where_, outcome: "error",
                detail: "#\(sent.exchange.id) \(error.code)")
            return try result(value, isError: true, sent: true)
        }
        try await audit(
            caller: caller, action: "send_request", target: where_, outcome: "allowed",
            detail: "#\(sent.exchange.id)")
        return try result(value, sent: true)
    }

    // MARK: rendering

    /// A window of a message as text (UTF-8, invalid bytes replaced; or base64 when binary).
    static func slice(_ bytes: [UInt8], offset: Int, max: Int) -> [String: Any] {
        let start = Swift.min(Swift.max(0, offset), bytes.count)
        let end = Swift.min(bytes.count, start + max)
        let window = Array(bytes[start..<end])
        var result: [String: Any] = [
            "total_bytes": bytes.count, "offset": start, "truncated": end < bytes.count,
        ]
        let binary =
            window.contains(0)
            || String(bytes: window, encoding: .utf8) == nil && window.count > 0
                && Double(window.filter { $0 < 9 || ($0 > 13 && $0 < 32) }.count) > Double(window.count) * 0.1
        if binary {
            result["base64"] = Data(window).base64EncodedString()
        } else {
            result["text"] = String(decoding: window, as: UTF8.self)
        }
        if end < bytes.count { result["next_offset"] = end }
        return result
    }

    /// The URL of `exchange` as tools and the audit log show it (default ports omitted).
    public static func url(of exchange: Exchange) -> String {
        let query = exchange.derived.query.map { "?" + $0 } ?? ""
        return url(exchange.target, path: (exchange.derived.path ?? "/") + query)
    }

    /// `target` + `path` as a URL (default ports omitted).
    public static func url(_ target: HTTPTarget, path: String) -> String {
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        return "\(target.scheme.rawValue)://\(target.host)\(standard ? "" : ":\(target.port)")\(path)"
    }
}
