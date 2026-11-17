// gulp-cli — LLM/AI-feature security testing (F32). `llm inject` delivers the prompt-injection library
// at a target chat endpoint and classifies each reply (refusal / compliance / leak); `llm mcp`
// enumerates a target MCP server's tools and flags tool poisoning and missing authentication. The
// operator-supplied `--target` is the authorization, as for the other active CLI probes.

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpScanner

struct LLM: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "llm",
        abstract: "Test a target app's AI features: prompt injection and MCP tool poisoning (F32).",
        subcommands: [Inject.self, MCP.self])

    /// `gulp llm inject --target http://host --path /chat --leak-marker SECRET`
    struct Inject: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Deliver prompt-injection payloads at a chat endpoint and classify the replies.")
        @Option(help: "The AS/app base URL, e.g. http://127.0.0.1:8088.") var target: String
        @Option(help: "The chat endpoint path.") var path: String = "/chat"
        @Option(help: "JSON field the prompt goes in.") var field: String = "message"
        @Option(help: "A secret the model must never reveal (its presence = a leak).") var leakMarker: String?

        func run() async throws {
            guard let destination = HTTPTarget(url: target) else {
                throw ValidationError("Invalid --target \(target)")
            }
            let host = hostHeader(destination)
            let engine = NIOHTTPEngine()
            defer { Task { await engine.shutdown() } }
            let options = SendOptions(recordAs: .automation)

            var compliant = 0, leaked = 0, refused = 0
            for (name, payload) in LLMInjection.injectionPayloads(canary: "GULPCANARY7") {
                let json = "{\"\(field)\":\"\(escape(payload))\"}"
                let raw =
                    "POST \(path) HTTP/1.1\r\nHost: \(host)\r\nContent-Type: application/json\r\n"
                    + "Content-Length: \(json.utf8.count)\r\nConnection: close\r\n\r\n\(json)"
                let result = await engine.send(RawRequest(Bytes(raw)), to: destination, options: options)
                let reply = (try? result.exchange.response?.decodedBody())?.flatMap { $0 }?.string() ?? ""
                let verdict = LLMInjection.classify(
                    reply: reply, canary: "GULPCANARY7", systemPromptMarker: leakMarker)
                switch verdict {
                case .leak: leaked += 1
                case .compliance: compliant += 1
                case .refusal: refused += 1
                case .unknown: break
                }
                print("  [\(name)] \(verdict.rawValue)")
            }
            if leaked > 0 || compliant > 0 {
                print(
                    "llm inject: VULNERABLE to prompt injection (\(leaked) leak, \(compliant) compliance, \(refused) refusal)"
                )
            } else {
                print("llm inject: guarded (\(refused) refusal) — no injection obeyed")
            }
        }
    }

    /// `gulp llm mcp --target http://host --path /mcp`
    struct MCP: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Enumerate a target MCP server's tools and flag poisoning / missing auth.")
        @Option(help: "The MCP server base URL.") var target: String
        @Option(help: "The MCP HTTP endpoint path.") var path: String = "/mcp"

        func run() async throws {
            guard let destination = HTTPTarget(url: target) else {
                throw ValidationError("Invalid --target \(target)")
            }
            let host = hostHeader(destination)
            let engine = NIOHTTPEngine()
            defer { Task { await engine.shutdown() } }
            let options = SendOptions(recordAs: .automation)

            let rpc = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"
            let raw =
                "POST \(path) HTTP/1.1\r\nHost: \(host)\r\nContent-Type: application/json\r\n"
                + "Content-Length: \(rpc.utf8.count)\r\nConnection: close\r\n\r\n\(rpc)"
            let result = await engine.send(RawRequest(Bytes(raw)), to: destination, options: options)
            let status = result.exchange.response?.parsed.statusCode ?? 0
            let body = (try? result.exchange.response?.decodedBody())?.flatMap { $0 }?.string() ?? ""

            if status == 401 || status == 403 {
                print("llm mcp: authenticated (tools/list requires auth) — no unauthenticated enumeration")
                return
            }
            print("llm mcp: tools/list succeeded WITHOUT authentication (status \(status))")
            let tools = Self.parseTools(body)
            print("llm mcp: \(tools.count) tool(s) exposed")
            let poisoned = LLMInjection.poisonedTools(tools)
            for p in poisoned {
                print("  POISONED tool `\(p.tool)`: description contains steering instruction (`\(p.cue)`)")
            }
            if poisoned.isEmpty {
                print("llm mcp: no tool poisoning detected")
            } else {
                print("llm mcp: TOOL POISONING in \(poisoned.count) tool description(s)")
            }
        }

        /// Minimal parse of a JSON-RPC tools/list result into (name, description) pairs.
        static func parseTools(_ body: String) -> [LLMInjection.MCPTool] {
            guard let data = body.data(using: .utf8),
                let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let result = root["result"] as? [String: Any],
                let tools = result["tools"] as? [[String: Any]]
            else { return [] }
            return tools.compactMap { t in
                guard let name = t["name"] as? String else { return nil }
                return LLMInjection.MCPTool(name: name, description: t["description"] as? String ?? "")
            }
        }
    }
}

private func hostHeader(_ destination: HTTPTarget) -> String {
    let defaultPort = destination.scheme == .https ? 443 : 80
    return destination.port == defaultPort
        ? destination.host : "\(destination.host):\(destination.port)"
}

private func escape(_ s: String) -> String {
    s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\n", with: " ")
}
