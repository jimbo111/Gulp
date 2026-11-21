// GulpAutomation — the MCP server (F21 AUT-020…AUT-023): Gulp's project exposed to AI clients such
// as Claude Code over the Model Context Protocol (JSON-RPC 2.0). This file is the protocol; the
// stdio transport (one JSON message per line) is `MCPStdio`.
//
// Tools are the shared agent tool surface (`APIGate`, GulpWorkspace; architecture §3 rule 6): this
// server lists them and forwards each call to the gate, which validates it, checks ScopeGuard and the
// approval policy for active tools, sends, and writes the audit log. Refusals come back as a
// structured tool error (`{"error": {"code": "out_of_scope", …}}`, `isError: true`) rather than a
// protocol error, so the model can read and act on them; a call whose audit write fails is a JSON-RPC
// error. Sends are recorded with source `automation` and audited as `mcp:<client name>`.
//
// Resources (MCP only): `gulp://sitemap`, `gulp://scope` and `gulp://exchange/{id}`; reads are
// audited through the same gate. Nothing is sent anywhere unless a client calls `send_request`;
// reads stay on this machine.

import Foundation
import GulpCore
import GulpWorkspace

/// The MCP server for one project session.
public actor MCPServer {
    /// MCP protocol versions this server speaks, newest first.
    public static let protocolVersions = ["2025-06-18", "2025-03-26", "2024-11-05"]

    let session: ProjectSession
    let gate: APIGate
    let serverVersion: String
    private(set) var clientName = "unknown"
    private(set) var initialized = false

    /// A server for `session`. `approver` asks a human (the app) when `policy` is `.ask`.
    public init(
        session: ProjectSession, policy: ApprovalPolicy = .deny, serverVersion: String = "0.7.0",
        approver: (@Sendable (AgentAction) async -> Bool)? = nil
    ) {
        self.session = session
        self.gate = APIGate(session: session, source: .automation, policy: policy, approver: approver)
        self.serverVersion = serverVersion
    }

    /// The audit log's actor for this client.
    var caller: String { "mcp:\(clientName)" }

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
            case "tools/list": result = ["tools": try Self.tools()]
            case "tools/call": result = try await callTool(params)
            case "resources/list": result = try await listResources()
            case "resources/templates/list": result = ["resourceTemplates": Self.templates]
            case "resources/read": result = try await readResource(params)
            default: return Self.error(id: id, code: -32601, message: "Method not found: \(method)")
            }
            return ["jsonrpc": "2.0", "id": id as Any, "result": result]
        } catch let error as RPCError {
            return Self.error(id: id, code: error.code, message: error.message)
        } catch APIGateError.unknownTool(let name) {
            return Self.error(id: id, code: -32602, message: "Unknown tool: \(name)")
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

    /// The gate's tools as MCP tool descriptors.
    static func tools() throws -> [[String: Any]] {
        try APIGate.tools.map { tool in
            [
                "name": tool.name, "title": tool.title, "description": tool.description,
                "inputSchema": try JSONSerialization.jsonObject(with: Data(tool.inputSchema.utf8)),
                "annotations": tool.isActive
                    ? ["readOnlyHint": false, "destructiveHint": false, "openWorldHint": true]
                    : ["readOnlyHint": true, "openWorldHint": false],
            ]
        }
    }

    func callTool(_ params: [String: Any]) async throws -> [String: Any] {
        guard let name = params["name"] as? String else {
            throw RPCError(code: -32602, message: "Missing tool name")
        }
        let arguments = try JSONSerialization.data(withJSONObject: params["arguments"] ?? [String: Any]())
        let result = try await gate.call(name, arguments: arguments, caller: caller)
        // The structured value, also as JSON text for clients that only read text.
        return [
            "content": [["type": "text", "text": String(decoding: result.json, as: UTF8.self)]],
            "structuredContent": try JSONSerialization.jsonObject(with: result.json),
            "isError": result.isError,
        ]
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
                "# \(APIGate.url(of: exchange))\n\n" + String(decoding: request, as: UTF8.self) + "\n\n"
                + String(decoding: response, as: UTF8.self)
        } else {
            throw RPCError(code: -32002, message: "Resource not found: \(uri)")
        }
        try await gate.audit(
            caller: caller, action: "resources/read", target: uri, outcome: "read", detail: nil)
        return ["contents": [["uri": uri, "mimeType": mime, "text": text]]]
    }
}

/// The text rendering of the MCP site map resource.
enum SiteMapLabel {
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
