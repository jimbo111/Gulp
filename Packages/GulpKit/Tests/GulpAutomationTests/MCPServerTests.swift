import Foundation
import GulpCore
import GulpWorkspace
import Testing

@testable import GulpAutomation
@testable import GulpStore

// F21 AUT-020…AUT-023: the MCP server's protocol, tools, resources and safety.

func mcpEnvironment() -> WorkspaceEnvironment {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("gulp-mcp-\(UUID().uuidString)")
    var environment = WorkspaceEnvironment(
        supportDirectory: root.appendingPathComponent("support"),
        cachesDirectory: root.appendingPathComponent("caches"))
    environment.caKeyType = .p256
    return environment
}

func mcpSession(_ name: String) async throws -> ProjectSession {
    let environment = mcpEnvironment()
    try FileManager.default.createDirectory(
        at: environment.supportDirectory, withIntermediateDirectories: true)
    return try await ProjectSession.open(
        at: environment.supportDirectory.appendingPathComponent("\(name).gulp"), environment: environment)
}

/// Send one request and decode the reply.
func call(_ server: MCPServer, _ id: Int, _ method: String, _ params: [String: Any] = [:]) async throws
    -> [String: Any]
{
    let message: [String: Any] = ["jsonrpc": "2.0", "id": id, "method": method, "params": params]
    let reply = try #require(await server.handle(try JSONSerialization.data(withJSONObject: message)))
    return try #require(try JSONSerialization.jsonObject(with: reply) as? [String: Any])
}

/// A tool call's structured result.
func tool(_ server: MCPServer, _ id: Int, _ name: String, _ arguments: [String: Any] = [:]) async throws
    -> (value: [String: Any], isError: Bool)
{
    let reply = try await call(server, id, "tools/call", ["name": name, "arguments": arguments])
    let result = try #require(reply["result"] as? [String: Any])
    let value = try #require(result["structuredContent"] as? [String: Any])
    // The text content carries the same JSON for clients that only read text.
    let text = try #require((result["content"] as? [[String: Any]])?.first?["text"] as? String)
    #expect(try JSONSerialization.jsonObject(with: Data(text.utf8)) is [String: Any])
    return (value, result["isError"] as? Bool ?? false)
}

@Suite("GulpAutomation — MCP server (AUT-020…AUT-023)", .serialized)
struct MCPServerTests {
    @Test(
        "AUT-020: initialize negotiates the version; notifications get no reply; errors are JSON-RPC errors")
    func test_AUT020_protocol() async throws {
        let session = try await mcpSession("protocol")
        let server = MCPServer(session: session)
        let initialize = try await call(
            server, 1, "initialize",
            [
                "protocolVersion": "2025-03-26", "capabilities": [:],
                "clientInfo": ["name": "claude-code", "version": "2"],
            ])
        let result = try #require(initialize["result"] as? [String: Any])
        #expect(result["protocolVersion"] as? String == "2025-03-26")
        #expect((result["serverInfo"] as? [String: Any])?["name"] as? String == "gulp")
        #expect((result["capabilities"] as? [String: Any])?["tools"] != nil)
        let future = try await call(server, 2, "initialize", ["protocolVersion": "2099-01-01"])
        #expect(
            (future["result"] as? [String: Any])?["protocolVersion"] as? String
                == MCPServer.protocolVersions[0])
        let note = try JSONSerialization.data(withJSONObject: [
            "jsonrpc": "2.0", "method": "notifications/initialized",
        ])
        #expect(await server.handle(note) == nil)
        #expect((try await call(server, 3, "ping"))["result"] != nil)
        let unknown = try await call(server, 4, "nope/nothing")
        #expect((unknown["error"] as? [String: Any])?["code"] as? Int == -32601)
        let parse = try #require(await server.handle(Data("{not json".utf8)))
        #expect(String(decoding: parse, as: UTF8.self).contains("-32700"))
        let tools = try #require((try await call(server, 5, "tools/list"))["result"] as? [String: Any])
        let names = (tools["tools"] as? [[String: Any]])?.compactMap { $0["name"] as? String }
        #expect(names == ["list_exchanges", "get_exchange", "send_request", "get_scope"])
        let badTool = try await call(server, 6, "tools/call", ["name": "rm_rf"])
        #expect((badTool["error"] as? [String: Any])?["code"] as? Int == -32602)
        try await session.close()
    }

    @Test("AUT-021: list_exchanges pages and filters; get_exchange truncates with a continuation; get_scope")
    func test_AUT021_readTools() async throws {
        let session = try await mcpSession("read")
        let target = HTTPTarget(scheme: .http, host: "lab", port: 8088)
        for i in 1...30 {
            let body = String(repeating: "x", count: i == 5 ? 1_000 : 10)
            let request = RawRequest(Bytes("GET /p/\(i) HTTP/1.1\r\nHost: lab:8088\r\n\r\n"))
            let response = RawResponse(
                Bytes("HTTP/1.1 \(i == 9 ? 404 : 200) OK\r\nContent-Length: \(body.count)\r\n\r\n\(body)"))
            _ = await session.store.writer.record(
                Exchange(
                    source: .proxy, target: target, request: request, response: response, state: .complete))
        }
        let server = MCPServer(session: session)
        let page = try await tool(server, 1, "list_exchanges", ["limit": 10, "offset": 5])
        #expect(page.value["total"] as? Int == 30 && page.value["next_offset"] as? Int == 15)
        let rows = try #require(page.value["exchanges"] as? [[String: Any]])
        #expect(rows.count == 10 && rows.first?["url"] as? String == "http://lab:8088/p/6")
        let notFound = try await tool(server, 2, "list_exchanges", ["status_class": 4])
        #expect(notFound.value["total"] as? Int == 1)
        let invalid = try await tool(server, 3, "list_exchanges", ["limit": 1_000])
        #expect(
            invalid.isError
                && ((invalid.value["error"] as? [String: Any])?["code"] as? String) == "invalid_arguments")
        let unknownArgument = try await tool(server, 4, "list_exchanges", ["sql": "1=1"])
        #expect(unknownArgument.isError)

        let big = try await tool(server, 5, "get_exchange", ["id": 5, "part": "response", "max_bytes": 256])
        let response = try #require(big.value["response"] as? [String: Any])
        #expect(response["truncated"] as? Bool == true && response["next_offset"] as? Int == 256)
        #expect(big.value["request"] == nil)
        let rest = try await tool(
            server, 6, "get_exchange", ["id": 5, "part": "response", "offset": 256, "max_bytes": 4_096])
        #expect((rest.value["response"] as? [String: Any])?["truncated"] as? Bool == false)
        let missing = try await tool(server, 7, "get_exchange", ["id": 999])
        #expect(missing.isError)

        try await session.addToScope(url: "http://lab:8088/p")
        let scope = try await tool(server, 8, "get_scope")
        #expect((scope.value["rules"] as? [[String: Any]])?.first?["host"] as? String == "lab")
        try await session.close()
    }

    @Test("AUT-023: out-of-scope (or no-scope) sends are refused with a structured error and audited")
    func test_AUT023_scopeGuard() async throws {
        let session = try await mcpSession("safety")
        let server = MCPServer(session: session, policy: .inScope)
        _ = try await call(
            server, 1, "initialize", ["protocolVersion": "2025-06-18", "clientInfo": ["name": "claude-code"]])
        let raw = "GET /in HTTP/1.1\nHost: 127.0.0.1:1\n\n"
        // No scope yet: active tools refuse everything (ADR-011 + doc 07).
        let noScope = try await tool(server, 2, "send_request", ["raw": raw, "target": "http://127.0.0.1:1"])
        #expect(
            noScope.isError
                && (noScope.value["error"] as? [String: Any])?["code"] as? String == "out_of_scope")
        try await session.addToScope(url: "http://127.0.0.1:1/in")
        let outside = try await tool(
            server, 3, "send_request",
            ["raw": "GET /out HTTP/1.1\nHost: 127.0.0.1:1\n\n", "target": "http://127.0.0.1:1"])
        #expect((outside.value["error"] as? [String: Any])?["target"] as? String == "http://127.0.0.1:1/out")
        // In scope: sent (port 1 refuses the connection, which comes back as a send error, recorded).
        let inside = try await tool(
            server, 4, "send_request", ["raw": raw, "target": "http://127.0.0.1:1", "timeout_seconds": 5])
        #expect(
            inside.isError
                && (inside.value["error"] as? [String: Any])?["code"] as? String == "connection_refused")
        let id = try #require(inside.value["exchange_id"] as? Int)
        await session.store.writer.flush()
        let stored = try #require(try await session.store.exchange(id: ExchangeID(id)))
        #expect(stored.source == .automation)
        // The agent's bare LF line endings were sent as CRLF.
        #expect(stored.request.bytes.string() == "GET /in HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
        // The default (deny) refuses even in scope.
        let readOnly = MCPServer(session: session)
        let denied = try await tool(
            readOnly, 5, "send_request", ["raw": raw, "target": "http://127.0.0.1:1"])
        #expect((denied.value["error"] as? [String: Any])?["code"] as? String == "not_approved")
        // The ask policy goes to the approver.
        let asking = MCPServer(session: session, policy: .ask) { action in
            action.target.hasSuffix("/in") == false
        }
        let notApproved = try await tool(
            asking, 6, "send_request", ["raw": raw, "target": "http://127.0.0.1:1"])
        #expect((notApproved.value["error"] as? [String: Any])?["code"] as? String == "not_approved")

        let log = try await session.store.auditLog()
        let sends = log.filter { $0.action == "send_request" }
        #expect(sends.map(\.outcome) == ["refused", "refused", "error", "refused", "refused"])
        #expect(sends.first?.actor == "mcp:claude-code" && sends[1].target == "http://127.0.0.1:1/out")
        try await session.close()
    }

    @Test("AUT-023: an allowed send whose audit write fails is a JSON-RPC error, not a success")
    func test_AUT023_auditFailureIsAnError() async throws {
        let session = try await mcpSession("audit-fails")
        try await session.addToScope(url: "http://127.0.0.1:1/in")
        let server = MCPServer(session: session, policy: .inScope)
        try await session.store.pool.write { db in
            try db.execute(
                sql: "CREATE TRIGGER off BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'offline'); END"
            )
        }
        let reply = try await call(
            server, 1, "tools/call",
            [
                "name": "send_request",
                "arguments": [
                    "raw": "GET /in HTTP/1.1\nHost: 127.0.0.1:1\n\n", "target": "http://127.0.0.1:1",
                    "timeout_seconds": 5,
                ],
            ])
        #expect(reply["result"] == nil)
        #expect((reply["error"] as? [String: Any])?["code"] as? Int == -32603)
        try await session.close()
    }

    @Test("AUT-022: resources — the site map, the scope and exchanges")
    func test_AUT022_resources() async throws {
        let session = try await mcpSession("resources")
        let request = RawRequest(Bytes("GET /shop/cart HTTP/1.1\r\nHost: lab\r\n\r\n"))
        let id = await session.store.writer.record(
            Exchange(
                source: .proxy, target: HTTPTarget(scheme: .http, host: "lab"), request: request,
                state: .complete))
        await session.store.writer.flush()
        await session.siteMap.catchUp()
        let server = MCPServer(session: session)
        let list = try #require((try await call(server, 1, "resources/list"))["result"] as? [String: Any])
        let uris = (list["resources"] as? [[String: Any]])?.compactMap { $0["uri"] as? String } ?? []
        #expect(uris.contains("gulp://sitemap") && uris.contains("gulp://exchange/\(id)"))
        let templates = try #require(
            (try await call(server, 2, "resources/templates/list"))["result"] as? [String: Any])
        #expect(
            (templates["resourceTemplates"] as? [[String: Any]])?.first?["uriTemplate"] as? String
                == "gulp://exchange/{id}")
        func read(_ uri: String) async throws -> String? {
            let reply = try await call(server, 3, "resources/read", ["uri": uri])
            return ((reply["result"] as? [String: Any])?["contents"] as? [[String: Any]])?.first?["text"]
                as? String
        }
        #expect(try await read("gulp://sitemap") == "http://lab:80\n  shop\n    cart ×1")
        #expect(try await read("gulp://exchange/\(id)")?.contains("GET /shop/cart HTTP/1.1") == true)
        #expect(try await read("gulp://scope")?.contains("gulp-scope") == true)
        let missing = try await call(server, 4, "resources/read", ["uri": "gulp://exchange/999"])
        #expect((missing["error"] as? [String: Any])?["code"] as? Int == -32002)
        try await session.close()
    }
}
