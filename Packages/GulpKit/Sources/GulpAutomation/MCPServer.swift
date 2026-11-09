// GulpAutomation — the MCP server (F21 AUT-020…AUT-023): Gulp's project exposed to AI clients such
// as Claude Code over the Model Context Protocol (JSON-RPC 2.0). This file is the protocol; the
// stdio transport (one JSON message per line) is `MCPStdio`. The tools and resources are thin
// adapters over the same ProjectSession APIs the UI and CLI use.
//
// M6b surface: tools `list_exchanges`, `get_exchange`, `send_request`, `get_scope`; resources
// `gulp://sitemap`, `gulp://scope` and `gulp://exchange/{id}`.
//
// Safety (AUT-023): `send_request` is ScopeGuard-checked (an empty scope refuses everything) and
// goes through the approval policy; refusals come back as a structured tool error
// (`{"error": {"code": "out_of_scope", …}}`, `isError: true`) rather than a protocol error, so the
// model can read and act on them. Every tool call is written to the project's audit log with the
// client's name, and sends are recorded with source `automation`. Nothing is sent anywhere unless
// a client calls `send_request`; reads stay on this machine.

import Foundation
import GulpCore
import GulpHTTP
import GulpStore
import GulpWorkspace

/// How agent-initiated active actions are approved (AUT-023).
public enum ApprovalPolicy: String, Sendable, CaseIterable, Codable {
    /// In-scope actions run; out-of-scope ones are refused. Headless, this must be chosen
    /// explicitly (AUT-023).
    case inScope = "in-scope"
    /// Every active action needs a human yes from `approver` (the app); without one it is refused.
    case ask
    /// Active actions are always refused (read-only agent). The default.
    case deny
}

/// An active action an agent asked for, shown to the human who approves it.
public struct AgentAction: Sendable, Hashable {
    /// The client (`claude-code`, …).
    public var client: String
    /// The tool (`send_request`).
    public var tool: String
    /// What it touches (`https://host:443/path`).
    public var target: String
    /// The request text (for review), truncated.
    public var preview: String
}

/// The MCP server for one project session.
public actor MCPServer {
    /// MCP protocol versions this server speaks, newest first.
    public static let protocolVersions = ["2025-06-18", "2025-03-26", "2024-11-05"]
    /// Bodies longer than this are cut in tool results (with a continuation offset).
    public static let defaultMaxBytes = 16_384

    let session: ProjectSession
    let policy: ApprovalPolicy
    let approver: (@Sendable (AgentAction) async -> Bool)?
    let serverVersion: String
    private(set) var clientName = "unknown"
    private(set) var initialized = false

    /// A server for `session`. `approver` asks a human (the app) when `policy` is `.ask`.
    public init(
        session: ProjectSession, policy: ApprovalPolicy = .deny, serverVersion: String = "0.7.0",
        approver: (@Sendable (AgentAction) async -> Bool)? = nil
    ) {
        self.session = session
        self.policy = policy
        self.serverVersion = serverVersion
        self.approver = approver
    }

    // MARK: JSON-RPC

    /// Handle one JSON-RPC message; returns the response line, or nil for notifications.
    public func handle(_ line: Data) async -> Data? {
        guard let json = try? JSONSerialization.jsonObject(with: line) else {
            return Self.encode(Self.error(id: nil, code: -32700, message: "Parse error"))
        }
        if let batch = json as? [Any] {
            // JSON-RPC batches (older MCP revisions): answer each request, in order.
            var replies: [Any] = []
            for item in batch {
                if let reply = await handleMessage(item) { replies.append(reply) }
            }
            return replies.isEmpty ? nil : Self.encode(replies)
        }
        return await handleMessage(json).map(Self.encode)
    }

    func handleMessage(_ json: Any) async -> [String: Any]? {
        guard let message = json as? [String: Any], message["jsonrpc"] as? String == "2.0",
            let method = message["method"] as? String
        else {
            // A response from the client (we send no requests) or garbage.
            if let message = json as? [String: Any], message["result"] != nil || message["error"] != nil {
                return nil
            }
            return Self.error(id: (json as? [String: Any])?["id"], code: -32600, message: "Invalid request")
        }
        let id = message["id"]
        let params = message["params"] as? [String: Any] ?? [:]
        guard id != nil else {
            if method == "notifications/initialized" { initialized = true }
            return nil  // notifications get no reply
        }
        do {
            let result: [String: Any]
            switch method {
            case "initialize": result = initialize(params)
            case "ping": result = [:]
            case "tools/list": result = ["tools": Self.tools]
            case "tools/call": result = try await callTool(params)
            case "resources/list": result = try await listResources()
            case "resources/templates/list": result = ["resourceTemplates": Self.templates]
            case "resources/read": result = try await readResource(params)
            default: return Self.error(id: id, code: -32601, message: "Method not found: \(method)")
            }
            return ["jsonrpc": "2.0", "id": id as Any, "result": result]
        } catch let error as RPCError {
            return Self.error(id: id, code: error.code, message: error.message)
        } catch {
            return Self.error(id: id, code: -32603, message: "Internal error: \(error)")
        }
    }

    struct RPCError: Error {
        var code: Int
        var message: String
    }

    static func error(id: Any?, code: Int, message: String) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id ?? NSNull(), "error": ["code": code, "message": message]]
    }

    static func encode(_ value: Any) -> Data {
        (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]))
            ?? Data(#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"encoding failed"}}"#.utf8)
    }

    func initialize(_ params: [String: Any]) -> [String: Any] {
        if let info = params["clientInfo"] as? [String: Any], let name = info["name"] as? String,
            !name.isEmpty
        {
            clientName = name
        }
        let asked = params["protocolVersion"] as? String ?? ""
        let version = Self.protocolVersions.contains(asked) ? asked : Self.protocolVersions[0]
        return [
            "protocolVersion": version,
            "capabilities": [
                "tools": ["listChanged": false], "resources": ["listChanged": false, "subscribe": false],
            ],
            "serverInfo": ["name": "gulp", "title": "Gulp", "version": serverVersion],
            "instructions": """
            Gulp is a web-security testing proxy. Read its recorded HTTP history with list_exchanges and \
            get_exchange, check the engagement scope with get_scope, and send raw HTTP requests with \
            send_request (in-scope targets only; out-of-scope sends are refused). Large bodies are \
            truncated: pass the returned next_offset to get_exchange to read more.
            """,
        ]
    }

    // MARK: tools (AUT-021)

    static var tools: [[String: Any]] {
        [
            [
                "name": "list_exchanges", "title": "List HTTP history",
                "description":
                    "List recorded HTTP exchanges (newest last), with optional filters. Returns id, method, URL, "
                    + "status, length, MIME type and source; use get_exchange for the full messages.",
                "inputSchema": schema(
                    [
                        "text": ["type": "string", "description": "Substring of host or path."],
                        "in_scope_only": ["type": "boolean"],
                        "status_class": [
                            "type": "integer", "minimum": 1, "maximum": 5, "description": "1…5 for 1xx…5xx.",
                        ],
                        "method": ["type": "string"],
                        "source": [
                            "type": "string",
                            "enum": [
                                "proxy", "repeater", "fuzzer", "scanner", "crawler", "automation", "ai",
                            ],
                        ],
                        "offset": ["type": "integer", "minimum": 0, "default": 0],
                        "limit": ["type": "integer", "minimum": 1, "maximum": 100, "default": 20],
                    ], required: []),
                "annotations": ["readOnlyHint": true, "openWorldHint": false],
            ],
            [
                "name": "get_exchange", "title": "Get an exchange",
                "description":
                    "The raw request and response of one exchange as text. Messages longer than max_bytes are "
                    + "cut; call again with offset = next_offset to continue.",
                "inputSchema": schema(
                    [
                        "id": ["type": "integer", "minimum": 1],
                        "part": [
                            "type": "string", "enum": ["both", "request", "response"], "default": "both",
                        ],
                        "offset": ["type": "integer", "minimum": 0, "default": 0],
                        "max_bytes": [
                            "type": "integer", "minimum": 256, "maximum": 262_144, "default": defaultMaxBytes,
                        ],
                    ], required: ["id"]),
                "annotations": ["readOnlyHint": true, "openWorldHint": false],
            ],
            [
                "name": "send_request", "title": "Send a raw HTTP request",
                "description":
                    "Send raw HTTP/1.1 request text to a target URL (scheme://host[:port]) exactly as written and "
                    + "return the response. The target must be in the project's scope; out-of-scope sends are "
                    + "refused. The exchange is recorded in history.",
                "inputSchema": schema(
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
                "annotations": ["readOnlyHint": false, "destructiveHint": false, "openWorldHint": true],
            ],
            [
                "name": "get_scope", "title": "Get the scope",
                "description":
                    "The project's scope rules (last match wins; no match is out of scope) and a summary.",
                "inputSchema": schema([:], required: []),
                "annotations": ["readOnlyHint": true, "openWorldHint": false],
            ],
        ]
    }

    static func schema(_ properties: [String: Any], required: [String]) -> [String: Any] {
        ["type": "object", "properties": properties, "required": required, "additionalProperties": false]
    }

    func callTool(_ params: [String: Any]) async throws -> [String: Any] {
        guard let name = params["name"] as? String else {
            throw RPCError(code: -32602, message: "Missing tool name")
        }
        let arguments = params["arguments"] as? [String: Any] ?? [:]
        guard let tool = Self.tools.first(where: { $0["name"] as? String == name }) else {
            throw RPCError(code: -32602, message: "Unknown tool: \(name)")
        }
        if let problem = Self.validate(arguments, against: tool["inputSchema"] as? [String: Any] ?? [:]) {
            await audit(name, target: nil, outcome: "error", detail: problem)
            return Self.toolError("invalid_arguments", problem)
        }
        switch name {
        case "list_exchanges": return try await listExchanges(arguments)
        case "get_exchange": return try await getExchange(arguments)
        case "send_request": return try await sendRequest(arguments)
        default: return await getScope()
        }
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

    /// A tool result: the structured value, also as JSON text for clients that only read text.
    static func toolResult(_ value: [String: Any], isError: Bool = false) -> [String: Any] {
        let text = String(decoding: encode(value), as: UTF8.self)
        return ["content": [["type": "text", "text": text]], "structuredContent": value, "isError": isError]
    }

    static func toolError(_ code: String, _ message: String, extra: [String: Any] = [:]) -> [String: Any] {
        var error: [String: Any] = ["code": code, "message": message]
        error.merge(extra) { _, new in new }
        return toolResult(["error": error], isError: true)
    }

    func listExchanges(_ arguments: [String: Any]) async throws -> [String: Any] {
        var filter = HistoryFilter()
        filter.text = arguments["text"] as? String
        filter.inScopeOnly = arguments["in_scope_only"] as? Bool ?? false
        if let statusClass = (arguments["status_class"] as? NSNumber)?.intValue {
            filter.statusClasses = [statusClass]
        }
        if let method = arguments["method"] as? String { filter.methods = [method.uppercased()] }
        if let source = arguments["source"] as? String { filter.source = ToolSource(rawValue: source) }
        let offset = (arguments["offset"] as? NSNumber)?.intValue ?? 0
        let limit = min((arguments["limit"] as? NSNumber)?.intValue ?? 20, 100)
        let store = await session.store
        await store.writer.flush()
        let total = try await store.count(filter: filter)
        let rows = try await store.summaries(filter: filter, offset: offset, limit: limit)
        var result: [String: Any] = [
            "total": total, "offset": offset,
            "exchanges": rows.map { row -> [String: Any] in
                var item: [String: Any] = [
                    "id": row.id, "method": row.method ?? "", "url": row.url, "source": row.source.rawValue,
                    "time": ISO8601DateFormatter().string(from: row.createdAt),
                ]
                if let status = row.status { item["status"] = status }
                if let length = row.responseLength { item["length"] = length }
                if let mime = row.mime { item["mime"] = mime }
                if let comment = row.comment, !comment.isEmpty { item["comment"] = comment }
                return item
            },
        ]
        if offset + rows.count < total { result["next_offset"] = offset + rows.count }
        await audit("list_exchanges", target: nil, outcome: "read", detail: "\(rows.count) of \(total)")
        return Self.toolResult(result)
    }

    func getExchange(_ arguments: [String: Any]) async throws -> [String: Any] {
        let id = ExchangeID((arguments["id"] as? NSNumber)?.int64Value ?? 0)
        let part = arguments["part"] as? String ?? "both"
        let offset = (arguments["offset"] as? NSNumber)?.intValue ?? 0
        let maxBytes = (arguments["max_bytes"] as? NSNumber)?.intValue ?? Self.defaultMaxBytes
        let store = await session.store
        await store.writer.flush()
        guard let exchange = try await store.exchange(id: id) else {
            await audit("get_exchange", target: nil, outcome: "error", detail: "no exchange \(id)")
            return Self.toolError("not_found", "No exchange with id \(id).")
        }
        var result: [String: Any] = [
            "id": exchange.id, "url": Self.url(of: exchange), "source": exchange.source.rawValue,
            "http_version": exchange.httpVersion.rawValue,
        ]
        if let status = exchange.derived.status { result["status"] = status }
        if part != "response" {
            result["request"] = Self.slice(exchange.request.bytes.rawBytes, offset: offset, max: maxBytes)
        }
        if part != "request" {
            result["response"] =
                exchange.response.map { Self.slice($0.wireBytes.rawBytes, offset: offset, max: maxBytes) }
                ?? NSNull()
        }
        await audit("get_exchange", target: Self.url(of: exchange), outcome: "read", detail: "#\(id)")
        return Self.toolResult(result)
    }

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

    static func url(of exchange: Exchange) -> String {
        let target = exchange.target
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        let authority = standard ? target.host : "\(target.host):\(target.port)"
        let query = exchange.derived.query.map { "?" + $0 } ?? ""
        return "\(target.scheme.rawValue)://\(authority)\(exchange.derived.path ?? "/")\(query)"
    }

    func sendRequest(_ arguments: [String: Any]) async throws -> [String: Any] {
        let raw = arguments["raw"] as? String ?? ""
        let targetText = arguments["target"] as? String ?? ""
        guard let target = HTTPTarget(url: targetText) else {
            await audit("send_request", target: targetText, outcome: "error", detail: "bad target")
            return Self.toolError(
                "invalid_arguments", "target must be scheme://host[:port], e.g. https://example.com")
        }
        // Agents often write bare LF; HTTP needs CRLF. Normalize the header block only when it has no CR.
        var text = raw
        if !text.contains("\r\n") { text = text.replacingOccurrences(of: "\n", with: "\r\n") }
        if !text.contains("\r\n\r\n") { text += text.hasSuffix("\r\n") ? "\r\n" : "\r\n\r\n" }
        let request = RawRequest(Bytes(text))
        let path = Self.pathAndQuery(request)
        let where_ = SiteMapLabel.url(target, path: path)
        guard request.parsed.warnings.isEmpty || !request.bytes[request.parsed.method].isEmpty else {
            await audit("send_request", target: where_, outcome: "error", detail: "unparseable request")
            return Self.toolError(
                "invalid_arguments", "raw is not an HTTP request (request line, headers, blank line).")
        }
        // AUT-023: ScopeGuard first (strict: an empty scope refuses everything), then the policy.
        let scopeGuard = session.scopeGuard
        do {
            try await scopeGuard.require(target, path: path)
        } catch {
            let summary = await scopeGuard.current.summary
            await audit("send_request", target: where_, outcome: "refused", detail: "out of scope")
            return Self.toolError(
                "out_of_scope", "\(where_) is outside the project's scope; Gulp refused to send it.",
                extra: ["target": where_, "scope": summary])
        }
        switch policy {
        case .deny:
            await audit("send_request", target: where_, outcome: "refused", detail: "approval policy: deny")
            return Self.toolError("not_approved", "Active actions are disabled for agents in this project.")
        case .ask:
            let action = AgentAction(
                client: clientName, tool: "send_request", target: where_, preview: String(text.prefix(2_000)))
            guard let approver, await approver(action) else {
                await audit("send_request", target: where_, outcome: "refused", detail: "not approved")
                return Self.toolError("not_approved", "The user did not approve this request.")
            }
        case .inScope: break
        }
        var options = SendOptions(recordAs: .automation)
        options.updateContentLength = arguments["update_content_length"] as? Bool ?? true
        options.timeouts.total = .seconds((arguments["timeout_seconds"] as? NSNumber)?.intValue ?? 30)
        if arguments["follow_redirects"] as? Bool == true {
            options.followRedirects = RedirectPolicy(mode: .inScope)
            options.scope = await scopeGuard.current
        }
        let maxBytes = (arguments["max_bytes"] as? NSNumber)?.intValue ?? Self.defaultMaxBytes
        let started = ContinuousClock.now
        let result = await session.http.send(request, to: target, options: options)
        let elapsed = ContinuousClock.now - started
        var value: [String: Any] = [
            "exchange_id": result.exchange.id,
            "time_ms": Double(elapsed.components.seconds) * 1_000 + Double(elapsed.components.attoseconds)
                / 1e15,
        ]
        if let response = result.exchange.response {
            value["status"] = response.parsed.statusCode
            value["response"] = Self.slice(response.wireBytes.rawBytes, offset: 0, max: maxBytes)
        }
        if !result.redirectChain.isEmpty { value["redirect_exchange_ids"] = result.redirectChain.map(\.id) }
        if let error = result.error {
            value["error"] = ["code": error.code, "message": "\(error)"]
            await audit(
                "send_request", target: where_, outcome: "error",
                detail: "#\(result.exchange.id) \(error.code)")
            return Self.toolResult(value, isError: true)
        }
        await audit("send_request", target: where_, outcome: "allowed", detail: "#\(result.exchange.id)")
        return Self.toolResult(value)
    }

    static func pathAndQuery(_ request: RawRequest) -> String {
        let derived = DerivedFields(
            target: HTTPTarget(scheme: .http, host: "x"), request: request, response: nil)
        return (derived.path ?? "/") + (derived.query.map { "?" + $0 } ?? "")
    }

    func getScope() async -> [String: Any] {
        let scope = await session.scope()
        let rules = scope.rules.map { rule -> [String: Any] in
            [
                "kind": rule.kind.rawValue, "enabled": rule.enabled, "scheme": rule.scheme.rawValue,
                "host": rule.host,
                "host_is_regex": rule.hostIsRegex, "port": rule.port, "path": rule.path,
            ]
        }
        await audit("get_scope", target: nil, outcome: "read", detail: nil)
        return Self.toolResult(["rules": rules, "summary": scope.summary])
    }

    // MARK: resources (AUT-022)

    static var templates: [[String: Any]] {
        [
            [
                "uriTemplate": "gulp://exchange/{id}", "name": "exchange", "title": "An exchange",
                "description": "The raw request and response of one recorded exchange.",
                "mimeType": "text/plain",
            ]
        ]
    }

    func listResources() async throws -> [String: Any] {
        var resources: [[String: Any]] = [
            [
                "uri": "gulp://sitemap", "name": "sitemap", "title": "Site map",
                "description": "Hosts and paths seen (inferred nodes marked), with request counts.",
                "mimeType": "text/plain",
            ],
            [
                "uri": "gulp://scope", "name": "scope", "title": "Scope",
                "description": "The scope rules as a Gulp scope file.", "mimeType": "application/json",
            ],
        ]
        let store = await session.store
        let total = try await store.count()
        for row in try await store.summaries(offset: max(0, total - 50), limit: 50) {
            resources.append([
                "uri": "gulp://exchange/\(row.id)", "name": "exchange-\(row.id)",
                "title": "#\(row.id) \(row.method ?? "") \(row.url)", "mimeType": "text/plain",
            ])
        }
        return ["resources": resources]
    }

    func readResource(_ params: [String: Any]) async throws -> [String: Any] {
        guard let uri = params["uri"] as? String else { throw RPCError(code: -32602, message: "Missing uri") }
        let text: String
        var mime = "text/plain"
        if uri == "gulp://sitemap" {
            // Up to date with everything recorded so far (including this client's own sends).
            await session.store.writer.flush()
            await session.siteMap.catchUp()
            text = SiteMapLabel.render(await session.siteMap.snapshot)
        } else if uri == "gulp://scope" {
            text = String(decoding: try await session.exportScope(), as: UTF8.self)
            mime = "application/json"
        } else if uri.hasPrefix("gulp://exchange/"),
            let id = ExchangeID(uri.dropFirst("gulp://exchange/".count))
        {
            guard let exchange = try await session.store.exchange(id: id) else {
                throw RPCError(code: -32002, message: "Resource not found: \(uri)")
            }
            let request = exchange.request.bytes.rawBytes.prefix(65_536)
            let response = exchange.response.map { Array($0.wireBytes.rawBytes.prefix(65_536)) } ?? []
            text =
                "# \(Self.url(of: exchange))\n\n" + String(decoding: request, as: UTF8.self) + "\n\n"
                + String(decoding: response, as: UTF8.self)
        } else {
            throw RPCError(code: -32002, message: "Resource not found: \(uri)")
        }
        await audit("resources/read", target: uri, outcome: "read", detail: nil)
        return ["contents": [["uri": uri, "mimeType": mime, "text": text]]]
    }

    // MARK: audit (AUT-023)

    func audit(_ action: String, target: String?, outcome: String, detail: String?) async {
        let store = await session.store
        _ = try? await store.appendAudit(
            actor: "mcp:\(clientName)", action: action, target: target, outcome: outcome, detail: detail)
    }
}

/// Text renderings shared by the MCP site map resource.
enum SiteMapLabel {
    static func url(_ target: HTTPTarget, path: String) -> String {
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        return "\(target.scheme.rawValue)://\(target.host)\(standard ? "" : ":\(target.port)")\(path)"
    }

    /// The tree, one node per line, indented; `(inferred)`, `[in scope]` and request counts marked.
    static func render(_ map: SiteMap) -> String {
        var lines: [String] = []
        func walk(_ node: SiteMapNode, depth: Int) {
            var line = String(repeating: "  ", count: depth) + node.name
            if !node.exchanges.isEmpty { line += " ×\(node.exchanges.count)" }
            if !node.visited { line += " (inferred)" }
            if node.inScope { line += " [in scope]" }
            lines.append(line)
            for child in map.children(of: node.id) { walk(child, depth: depth + 1) }
        }
        for host in map.hosts { walk(host, depth: 0) }
        return lines.isEmpty ? "(empty)" : lines.joined(separator: "\n")
    }
}
