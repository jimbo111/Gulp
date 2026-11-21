// gulp-cli — gRPC headless (F33, M10b): show a recorded call decoded (schema-less or named), manage
// the project's schemas (.proto, descriptor sets, server reflection), and call a method — from a
// recorded exchange or from scratch — with edited fields, sent from a Repeater tab.

import ArgumentParser
import Foundation
import GulpCodec
import GulpCore
import GulpWorkspace

/// `gulp-cli grpc …` (F33 GRP-001…GRP-004).
struct GRPCCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "grpc", abstract: "Decode gRPC calls, manage protobuf schemas, and send edited calls.",
        subcommands: [Show.self, Schemas.self, Call.self])

    struct Show: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Show a recorded exchange as an RPC call: messages, trailers and status.")
        @Option(help: "Project file.") var project: String
        @Argument(help: "Exchange id.") var id: Int64
        @Flag(help: "Also print each message as JSON (needs a schema).") var json = false

        func run() async throws {
            let session = try await openSession(project)
            guard let detail = try await session.rpcCall(id) else {
                try await session.close()
                throw ValidationError("Exchange \(id) isn't a gRPC, gRPC-Web or Connect call")
            }
            print(GRPCCommand.render(detail, json: json))
            try await session.close()
        }
    }

    struct Schemas: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List, import, fetch (reflection) or remove the project's protobuf schemas.",
            subcommands: [List.self, Import.self, Fetch.self, Remove.self], defaultSubcommand: List.self)

        struct List: AsyncParsableCommand {
            static let configuration = CommandConfiguration(abstract: "List schemas and their methods.")
            @Option(help: "Project file.") var project: String

            func run() async throws {
                let session = try await openSession(project)
                let schemas = session.grpcSchemas()
                print("schemas: \(schemas.count)")
                for schema in schemas {
                    print(
                        "\(schema.id.uuidString)\t\(schema.source)\t\(schema.services.joined(separator: ", "))"
                    )
                }
                for (path, method) in session.grpcSchemaSet().methods.sorted(by: { $0.key < $1.key }) {
                    let streaming =
                        method.clientStreaming || method.serverStreaming
                        ? " (\(method.clientStreaming ? "client" : "")\(method.clientStreaming && method.serverStreaming ? "+" : "")\(method.serverStreaming ? "server" : "") streaming)"
                        : ""
                    print("  \(path)\t\(method.inputType) → \(method.outputType)\(streaming)")
                }
                try await session.close()
            }
        }

        struct Import: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract:
                    "Import a .proto file (imports resolved next to it and from --import-path) or a descriptor set."
            )
            @Option(help: "Project file (created if missing).") var project: String
            @Option(help: "A .proto file.") var proto: String?
            @Option(help: "A folder to resolve imports from (repeatable).") var importPath: [String] = []
            @Option(help: "A FileDescriptorSet (protoc --descriptor_set_out).") var descriptorSet: String?

            func run() async throws {
                guard (proto == nil) != (descriptorSet == nil) else {
                    throw ValidationError("Give exactly one of --proto or --descriptor-set")
                }
                let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
                do {
                    let schema =
                        if let proto {
                            try await session.importProto(
                                at: URL(fileURLWithPath: proto),
                                importPaths: importPath.map { URL(fileURLWithPath: $0) })
                        } else {
                            try await session.importDescriptorSet(at: URL(fileURLWithPath: descriptorSet!))
                        }
                    print("imported \(schema.source): \(schema.services.joined(separator: ", "))")
                } catch let error as RPCServiceError {
                    try await session.close()
                    throw ValidationError(error.message)
                }
                try await session.close()
            }
        }

        struct Fetch: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Fetch the schema from the server's reflection service (v1, then v1alpha).")
            @Option(help: "Project file (created if missing).") var project: String
            @Option(help: "The server, e.g. https://localhost:8443.") var target: String
            @Flag(help: "Fetch even if the target is out of scope (the app's \"Send anyway\").")
            var allowOutOfScope = false

            func run() async throws {
                guard let destination = HTTPTarget(url: target) else {
                    throw ValidationError("Invalid --target \(target)")
                }
                let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
                do {
                    let schema = try await session.fetchGRPCSchema(
                        from: destination, allowOutOfScope: allowOutOfScope)
                    print("fetched \(schema.source): \(schema.services.joined(separator: ", "))")
                } catch let error as RPCServiceError {
                    try await session.close()
                    if error.outOfScope {
                        FileHandle.standardError.write(
                            Data("gulp-cli: Target is out of scope. Re-run with --allow-out-of-scope.\n".utf8)
                        )
                        throw ExitCode(3)
                    }
                    throw ValidationError(error.message)
                }
                try await session.close()
            }
        }

        struct Remove: AsyncParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Remove a schema by id.")
            @Option(help: "Project file.") var project: String
            @Argument(help: "Schema id (from list).") var id: String

            func run() async throws {
                guard let uuid = UUID(uuidString: id) else {
                    throw ValidationError("Invalid schema id \(id)")
                }
                let session = try await openSession(project)
                try await session.removeGRPCSchema(uuid)
                try await session.close()
            }
        }
    }

    struct Call: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract:
                "Send a call from a Repeater tab: a recorded exchange or a new request, with edited fields; prints the result."
        )
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "Where to send, e.g. https://localhost:8443 (default: the exchange's target).")
        var target: String?
        @Option(help: "Start from this recorded exchange.") var exchange: Int64?
        @Option(help: "Start from a request file (exact bytes).") var raw: String?
        @Option(help: "Or build a new request for this method path, e.g. /vulnlab.Echo/Say.") var path:
            String?
        @Option(help: "Protocol for a new request: grpc, grpc-web, grpc-web-text, connect or connect-unary.")
        var rpcProtocol = "grpc"
        @Option(
            help:
                "Set a field: path=value, the path by name (with a schema) or number, e.g. message=hi or 3.1=x (repeatable)."
        )
        var set: [String] = []
        @Option(help: "Replace the whole message with this JSON (needs a schema for protobuf bodies).")
        var json: String?
        @Option(help: "The message to edit (1-based) when the request carries several.") var message = 1
        @Flag(help: "Also print each message as JSON (needs a schema).") var printJSON = false
        @Flag(help: "Send even if the target is out of scope (the app's \"Send anyway\").")
        var allowOutOfScope = false

        func run() async throws {
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            do {
                try await send(session)
            } catch let error as RPCServiceError {
                try? await session.close()
                if error.outOfScope {
                    FileHandle.standardError.write(
                        Data(
                            "gulp-cli: Target is out of scope. Send anyway? Re-run with --allow-out-of-scope.\n"
                                .utf8))
                    throw ExitCode(3)
                }
                throw ValidationError(error.message)
            } catch {
                try? await session.close()
                throw error
            }
            try await session.close()
        }

        func send(_ session: ProjectSession) async throws {
            var request: RawRequest
            var destination = target.flatMap(HTTPTarget.init(url:))
            if target != nil, destination == nil { throw ValidationError("Invalid --target \(target!)") }
            if let exchange {
                guard let recorded = try await session.store.exchange(id: exchange) else {
                    throw ValidationError("No exchange \(exchange)")
                }
                request = recorded.request
                destination = destination ?? recorded.target
            } else if let raw {
                guard let data = FileManager.default.contents(atPath: raw) else {
                    throw ValidationError("Cannot read \(raw)")
                }
                request = RawRequest(Bytes([UInt8](data)))
            } else if let path {
                let protocols: [String: RPCProtocol] = [
                    "grpc": .grpc, "grpc-web": .grpcWeb, "grpc-web-text": .grpcWebText, "connect": .connect,
                    "connect-unary": .connectUnary,
                ]
                guard let chosen = protocols[rpcProtocol] else {
                    throw ValidationError("Unknown --rpc-protocol \(rpcProtocol)")
                }
                guard let destination else { throw ValidationError("A new request needs --target") }
                request = RPC.request(
                    path: path, host: Self.authority(destination), messages: [[]], chosen)
            } else {
                throw ValidationError("Give --exchange, --raw or --path")
            }
            guard let destination else { throw ValidationError("--target is required with --raw") }
            var fields: [(path: String, value: String)] = []
            for pair in set {
                let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                guard parts.count == 2 else { throw ValidationError("--set expects path=value") }
                fields.append((String(parts[0]), String(parts[1])))
            }
            if !fields.isEmpty || json != nil {
                request = try session.editRPCRequest(
                    request, message: message - 1, fields: fields, json: json)
            }
            let outcome = try await session.sendRPC(
                request, to: destination, allowOutOfScope: allowOutOfScope)
            print("tab \(outcome.tabID), exchange #\(outcome.exchange.id)")
            if let error = outcome.error { print("error: \(error)") }
            if let detail = outcome.detail { print(GRPCCommand.render(detail, json: printJSON)) }
        }

        static func authority(_ target: HTTPTarget) -> String {
            target.hostHeader
        }
    }

    /// A call as text: header line, each message with its envelope and decoded fields, trailers.
    static func render(_ detail: RPCCallDetail, json: Bool) -> String {
        let call = detail.call
        var lines = ["\(call.rpcProtocol.label) [\(call.rpcProtocol.rawValue)] \(call.path)"]
        if let status = call.status {
            lines[0] +=
                "  status \(status) \(call.statusName ?? "")"
                + (call.statusMessage.map { $0.isEmpty ? "" : ": \($0)" } ?? "")
        }
        func section(
            _ title: String, _ messages: [RPCMessage], _ texts: [String], _ jsons: [String], _ type: String?
        ) {
            for (index, message) in messages.enumerated() {
                let envelope =
                    call.rpcProtocol.enveloped
                    ? "envelope flags 0x\(String(format: "%02x", message.flags)), length \(message.framed.count)"
                    : "unary body, \(message.framed.count) bytes"
                lines.append(
                    "\(title) \(index + 1) (\(envelope)\(type.map { ", \($0.dropFirst())" } ?? "")):")
                lines += texts[index].split(separator: "\n", omittingEmptySubsequences: false).map {
                    "  \($0)"
                }
                if json, index < jsons.count {
                    lines += jsons[index].split(separator: "\n").map { "  json \($0)" }
                }
            }
        }
        section("request", call.requests, detail.requestTexts, detail.requestJSON, detail.inputType)
        section("response", call.responses, detail.responseTexts, detail.responseJSON, detail.outputType)
        if !call.trailers.isEmpty {
            lines.append("trailers:")
            lines += call.trailers.map { "  \($0.name): \($0.value)" }
        }
        lines += call.warnings.map { "warning: \($0)" }
        return lines.joined(separator: "\n")
    }
}
