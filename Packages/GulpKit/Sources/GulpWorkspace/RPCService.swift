// GulpWorkspace — gRPC in a project (F33 GRP-003…005): the project's imported schemas (stored as
// descriptor sets in project settings), fetching a schema from a server's reflection service,
// decoding a recorded exchange as an RPC call (named when a schema matches its path), editing a
// message by field path or JSON, and sending the edited call from a Repeater tab.

import Foundation
import GulpCodec
import GulpCore
import GulpHTTP
import GulpRepeater

/// The project's gRPC schemas (F33 GRP-003). Each import is kept as a serialized
/// `FileDescriptorSet` (base64 in the settings JSON), so `.proto` files, `protoc` output and
/// reflection results are all stored the same way.
public struct GRPCSchemaSettings: SettingsGroup {
    /// Storage key.
    public static let key = "grpcSchemas"
    /// No schemas.
    public static let defaultValue = GRPCSchemaSettings()

    /// One imported schema.
    public struct Schema: Sendable, Codable, Hashable, Identifiable {
        /// Identity.
        public var id: UUID
        /// Where it came from: a file or folder name, or `reflection <origin>`.
        public var source: String
        /// When it was imported.
        public var added: Date
        /// The services it defines (`pkg.Service`).
        public var services: [String]
        /// A serialized `FileDescriptorSet`.
        public var descriptorSet: Data

        /// The decoded files (nil if the stored bytes no longer decode).
        public var files: [ProtoFile]? { try? ProtoDescriptors.decodeSet(Array(descriptorSet)) }
    }

    /// Imported schemas, oldest first (later imports win for the same file name).
    public var schemas: [Schema] = []

    /// None.
    public init() {}
}

/// Why a gRPC action failed.
public struct RPCServiceError: Error, Sendable, Hashable, CustomStringConvertible {
    /// The reason.
    public var message: String
    /// The target is out of scope (TGT-023): ask "Send anyway?" and retry with the override.
    public var outOfScope = false

    /// An error.
    public init(_ message: String, outOfScope: Bool = false) {
        self.message = message
        self.outOfScope = outOfScope
    }

    /// A readable form of the error: its message.
    public var description: String { message }
}

/// An exchange decoded as an RPC call, with each message rendered for display (GRP-001…003).
public struct RPCCallDetail: Sendable {
    /// The decoded call (messages, trailers, status, warnings).
    public var call: RPCCall
    /// The request message type, when a schema knows the method.
    public var inputType: String?
    /// The response message type, when a schema knows the method.
    public var outputType: String?
    /// Each request message as text: named when the schema matches, else the schema-less tree.
    public var requestTexts: [String]
    /// Each response message as text.
    public var responseTexts: [String]
    /// Each request message as pretty JSON (empty without a schema).
    public var requestJSON: [String]
    /// Each response message as pretty JSON (empty without a schema).
    public var responseJSON: [String]

    /// Render `call` with `schema`.
    public init(call: RPCCall, schema: ProtoSchemaSet) {
        self.call = call
        let types = schema.types(for: call.path)
        inputType = types?.input
        outputType = types?.output
        requestTexts = call.requests.map { Self.text($0, type: types?.input, schema) }
        responseTexts = call.responses.map { Self.text($0, type: types?.output, schema) }
        requestJSON =
            types.map { t in call.requests.compactMap { Self.json($0, type: t.input, schema) } } ?? []
        responseJSON =
            types.map { t in call.responses.compactMap { Self.json($0, type: t.output, schema) } } ?? []
    }

    static func text(_ message: RPCMessage, type: String?, _ schema: ProtoSchemaSet) -> String {
        if message.json { return String(decoding: message.payload, as: UTF8.self) }
        if let type, schema.messages[type] != nil { return schema.text(message.payload, type: type) }
        if message.payload.isEmpty { return "(empty message)" }
        if let decoded = try? Protobuf.decode(message.payload) { return decoded.text() }
        return "<\(message.payload.count) bytes, not protobuf> "
            + message.payload.prefix(64).map { String(format: "%02x", $0) }.joined()
    }

    static func json(_ message: RPCMessage, type: String, _ schema: ProtoSchemaSet) -> String? {
        let object: Any
        if message.json {
            guard let parsed = try? JSONSerialization.jsonObject(with: Data(message.payload)) else {
                return nil
            }
            object = parsed
        } else {
            guard let parsed = schema.json(message.payload, type: type) else { return nil }
            object = parsed
        }
        guard
            let data = try? JSONSerialization.data(
                withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed])
        else { return nil }
        return String(decoding: data, as: UTF8.self)
    }
}

/// The outcome of sending an RPC call from Repeater (GRP-004).
public struct RPCSendOutcome: Sendable {
    /// The Repeater tab the call was sent from.
    public var tabID: Int64
    /// The recorded exchange.
    public var exchange: Exchange
    /// The decoded call (nil if the response couldn't be read as one).
    public var detail: RPCCallDetail?
    /// The network error, if the send failed.
    public var error: GulpNetworkError?
}

extension ProjectSession {
    // MARK: schemas

    /// The project's imported schemas.
    public nonisolated func grpcSchemas() -> [GRPCSchemaSettings.Schema] {
        settings.get(GRPCSchemaSettings.self).schemas
    }

    /// Every imported schema merged into one set (used to name calls by their path).
    public nonisolated func grpcSchemaSet() -> ProtoSchemaSet {
        var set = ProtoSchemaSet()
        for schema in grpcSchemas() {
            for file in schema.files ?? [] { set.add(file) }
        }
        return set
    }

    /// Store `descriptorSet` (a serialized `FileDescriptorSet`) as a schema.
    @discardableResult
    public func addGRPCSchema(descriptorSet: [UInt8], source: String) async throws
        -> GRPCSchemaSettings.Schema
    {
        let files: [ProtoFile]
        do { files = try ProtoDescriptors.decodeSet(descriptorSet) } catch {
            throw RPCServiceError("not a FileDescriptorSet: \(error)")
        }
        guard !files.isEmpty else { throw RPCServiceError("the descriptor set has no files") }
        let schema = GRPCSchemaSettings.Schema(
            id: UUID(), source: source, added: Date(), services: ProtoSchemaSet(files).services,
            descriptorSet: Data(descriptorSet))
        var stored = settings.get(GRPCSchemaSettings.self)
        stored.schemas.append(schema)
        try await settings.set(stored, scope: .project)
        return schema
    }

    /// Import a `.proto` file (GRP-003). Its imports are looked up next to it and in
    /// `importPaths`, recursively; `google/protobuf/*` imports are built in.
    @discardableResult
    public func importProto(at url: URL, importPaths: [URL] = []) async throws -> GRPCSchemaSettings.Schema {
        let sources = try Self.protoSources(url, importPaths: importPaths)
        let files: [ProtoFile]
        do { files = try ProtoParser.parse(sources) } catch {
            throw RPCServiceError("\(error)")
        }
        return try await addGRPCSchema(
            descriptorSet: ProtoDescriptors.encodeSet(files), source: url.lastPathComponent)
    }

    /// Import a compiled descriptor set (`protoc --descriptor_set_out`, GRP-003).
    @discardableResult
    public func importDescriptorSet(at url: URL) async throws -> GRPCSchemaSettings.Schema {
        guard let data = FileManager.default.contents(atPath: url.path) else {
            throw RPCServiceError("cannot read \(url.path)")
        }
        return try await addGRPCSchema(descriptorSet: Array(data), source: url.lastPathComponent)
    }

    /// Remove a schema.
    public func removeGRPCSchema(_ id: UUID) async throws {
        var stored = settings.get(GRPCSchemaSettings.self)
        stored.schemas.removeAll { $0.id == id }
        try await settings.set(stored, scope: .project)
    }

    /// The `.proto` sources `url` needs: the file itself and, transitively, its imports.
    static func protoSources(_ url: URL, importPaths: [URL]) throws -> [String: String] {
        let roots = [url.deletingLastPathComponent()] + importPaths
        guard let main = try? String(contentsOf: url, encoding: .utf8) else {
            throw RPCServiceError("cannot read \(url.path)")
        }
        var sources = [url.lastPathComponent: main]
        var pending = imports(of: main)
        while let name = pending.popLast() {
            guard sources[name] == nil, !name.hasPrefix("google/protobuf/") else { continue }
            let found = roots.lazy.compactMap {
                try? String(contentsOf: $0.appendingPathComponent(name), encoding: .utf8)
            }
            .first
            // Missing imports are left for the parser, which reports them with the importing line.
            guard let found else { continue }
            sources[name] = found
            pending += imports(of: found)
        }
        return sources
    }

    static func imports(of source: String) -> [String] {
        guard
            let regex = try? NSRegularExpression(
                pattern: #"(?m)^\s*import\s+(?:public\s+|weak\s+)?"([^"]+)""#)
        else { return [] }
        let range = NSRange(source.startIndex..., in: source)
        return regex.matches(in: source, range: range).compactMap {
            Range($0.range(at: 1), in: source).map { String(source[$0]) }
        }
    }

    // MARK: reflection

    /// Fetch the server's schema through gRPC server reflection (GRP-003): `list_services`, then
    /// `file_containing_symbol` per service and `file_by_filename` for missing dependencies;
    /// `grpc.reflection.v1` first, `v1alpha` when the server doesn't implement it. User-initiated,
    /// ScopeGuard-gated and recorded like a Repeater send.
    @discardableResult
    public func fetchGRPCSchema(from target: HTTPTarget, allowOutOfScope: Bool = false) async throws
        -> GRPCSchemaSettings.Schema
    {
        try await requireManualScope(target, path: GRPCReflection.v1Path, override: allowOutOfScope)
        var path = GRPCReflection.v1Path
        var listed: [GRPCReflection.Response]
        do {
            listed = try await reflect([.listServices], path: path, target: target)
        } catch let error as RPCServiceError
            where error.message.hasPrefix("UNIMPLEMENTED") || error.message.contains("HTTP 404")
        {
            path = GRPCReflection.v1alphaPath
            listed = try await reflect([.listServices], path: path, target: target)
        }
        let services = listed.flatMap(\.services).filter { !$0.hasPrefix("grpc.reflection.") }
        guard !services.isEmpty else { throw RPCServiceError("the server lists no services") }
        var files: [String: [UInt8]] = [:]
        var order: [String] = []
        func collect(_ responses: [GRPCReflection.Response]) {
            for bytes in responses.flatMap(\.files) {
                guard let file = try? ProtoDescriptors.decodeFile(bytes), files[file.name] == nil else {
                    continue
                }
                files[file.name] = bytes
                order.append(file.name)
            }
        }
        collect(try await reflect(services.map { .fileContainingSymbol($0) }, path: path, target: target))
        // Dependencies the server didn't send along (google/protobuf/* are built in).
        for _ in 0..<8 {
            let missing = Set(
                order.compactMap { files[$0] }.compactMap { try? ProtoDescriptors.decodeFile($0) }
                    .flatMap(\.dependencies)
            ).filter { files[$0] == nil && !$0.hasPrefix("google/protobuf/") }.sorted()
            guard !missing.isEmpty else { break }
            collect(try await reflect(missing.map { .fileByFilename($0) }, path: path, target: target))
            if missing.allSatisfy({ files[$0] == nil }) { break }
        }
        guard !order.isEmpty else { throw RPCServiceError("reflection returned no file descriptors") }
        let set = ProtoMessage(order.compactMap { files[$0] }.map { ProtoField(1, .bytes($0)) })
        return try await addGRPCSchema(
            descriptorSet: set.encoded,
            source: "reflection \(target.scheme.rawValue)://\(target.host):\(target.port)")
    }

    /// One reflection exchange: `requests` in one stream, the responses in order.
    func reflect(_ requests: [GRPCReflection.Request], path: String, target: HTTPTarget) async throws
        -> [GRPCReflection.Response]
    {
        let request = RPC.request(
            path: path, host: Self.authority(target), messages: requests.map { GRPCReflection.encode($0) },
            .grpc)
        var options = SendOptions(recordAs: .repeater)
        options.httpVersion = target.scheme == .https ? .http2 : .http2PriorKnowledge
        let result = await http.send(request, to: target, options: options)
        if let error = result.error { throw RPCServiceError("reflection failed: \(error)") }
        guard let response = result.exchange.response else {
            throw RPCServiceError("reflection: no response")
        }
        guard let call = RPC.parse(request: request, response: response) else {
            throw RPCServiceError("reflection: not a gRPC response")
        }
        let httpStatus = HTTP2Text.responseParts(response).status
        if call.status == nil, httpStatus != 200 { throw RPCServiceError("reflection: HTTP \(httpStatus)") }
        if let status = call.status, status != 0 {
            throw RPCServiceError(
                "\(RPC.statusName(status)): \(call.statusMessage ?? "") (reflection disabled?)")
        }
        let decoded = call.responses.compactMap { GRPCReflection.decodeResponse($0.payload) }
        if decoded.count == 1, let error = decoded[0].error, decoded[0].files.isEmpty,
            decoded[0].services.isEmpty
        {
            throw RPCServiceError("reflection: \(error)")
        }
        return decoded
    }

    /// TGT-023 for a user-initiated send: out of scope (with scope rules set) needs the override.
    func requireManualScope(_ target: HTTPTarget, path: String, override: Bool) async throws {
        guard !override, await scopeDecision(for: target, path: path) == .confirm else { return }
        throw RPCServiceError(
            "\(target.scheme.rawValue)://\(target.host):\(target.port)\(path) is out of scope",
            outOfScope: true)
    }

    /// `host[:port]` for a Host header (the port only when it isn't the scheme's default).
    static func authority(_ target: HTTPTarget) -> String {
        let host = target.host.contains(":") ? "[\(target.host)]" : target.host
        let defaultPort = target.scheme == .https ? 443 : 80
        return target.port == defaultPort ? host : "\(host):\(target.port)"
    }

    // MARK: calls

    /// A recorded exchange decoded as an RPC call, or nil if it isn't one (GRP-001…003).
    public func rpcCall(_ id: ExchangeID) async throws -> RPCCallDetail? {
        guard let exchange = try await store.exchange(id: id),
            let call = RPC.parse(request: exchange.request, response: exchange.response)
        else { return nil }
        return RPCCallDetail(call: call, schema: grpcSchemaSet())
    }

    /// `request` with message `message` edited (GRP-004): `fields` sets values by dotted path
    /// (names need a schema; numbers always work), keeping each field's wire type and every other
    /// byte; `json` replaces the whole message (needs a schema for protobuf bodies). The message is
    /// re-framed and Content-Length updated; nothing else in the request changes.
    public nonisolated func editRPCRequest(
        _ request: RawRequest, message index: Int = 0, fields: [(path: String, value: String)] = [],
        json: String? = nil
    ) throws -> RawRequest {
        guard let call = RPC.parse(request: request, response: nil) else {
            throw RPCServiceError("not a gRPC, gRPC-Web or Connect request")
        }
        guard call.requests.indices.contains(index) else {
            throw RPCServiceError("the request has no message \(index + 1)")
        }
        let original = call.requests[index]
        let schema = grpcSchemaSet()
        let type = schema.types(for: call.path)?.input
        var payload = original.payload
        if let json {
            if original.json {
                payload = Array(json.utf8)
            } else {
                guard let type else { throw RPCServiceError("JSON editing needs a schema for \(call.path)") }
                guard
                    let object = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any]
                else {
                    throw RPCServiceError("not a JSON object")
                }
                payload = try schema.encode(json: object, type: type)
            }
        }
        if !fields.isEmpty {
            guard !original.json else {
                throw RPCServiceError("this message is JSON; edit it with json instead")
            }
            var decoded: ProtoMessage
            do { decoded = try Protobuf.decode(payload) } catch {
                throw RPCServiceError("message \(index + 1) isn't protobuf: \(error)")
            }
            for (dotted, text) in fields {
                guard let path = schema.fieldPath(dotted, type: type) else {
                    throw RPCServiceError(
                        "unknown field \(dotted)" + (type == nil ? " (no schema; use field numbers)" : ""))
                }
                let def = Self.fieldDef(path, type: type, schema)
                let value: ProtoValue
                if def?.type == .enum, let enumType = def?.typeName.flatMap({ schema.enums[$0] }),
                    let number = enumType.values.first(where: { $0.name == text })?.number
                {
                    value = .varint(UInt64(bitPattern: Int64(number)))
                } else {
                    let wireType = decoded.value(at: path)?.wireType ?? def?.type.wireType ?? .lengthDelimited
                    value = ProtoValue.parsing(Array(text.utf8), as: wireType)
                }
                if let updated = decoded.setting(path, to: value) {
                    decoded = updated
                } else if path.count == 1 {
                    decoded.fields.append(ProtoField(path[0], value))
                } else {
                    throw RPCServiceError(
                        "field \(dotted) isn't in the message (only top-level fields can be added)")
                }
            }
            payload = decoded.encoded
        }
        guard let edited = RPC.replacingMessage(request, at: index, with: payload) else {
            throw RPCServiceError("could not re-encode the request")
        }
        return edited
    }

    static func fieldDef(_ path: [Int], type: String?, _ schema: ProtoSchemaSet) -> ProtoFieldDef? {
        var current = type.flatMap { schema.messages[$0] }
        var def: ProtoFieldDef?
        for number in path {
            def = current?.field(number)
            current = def?.typeName.flatMap { schema.messages[$0] }
        }
        return def
    }

    /// The Repeater options an RPC call needs: gRPC goes over HTTP/2 (h2c prior knowledge for
    /// `http`), gRPC-Web and Connect over whatever the server negotiates.
    public nonisolated func rpcRepeaterOptions(for request: RawRequest, target: HTTPTarget) -> RepeaterOptions
    {
        var options = RepeaterOptions()
        if RPC.detect(request) == .grpc {
            options.version = target.scheme == .https ? .http2 : .http2PriorKnowledge
        }
        options.transformTags = false
        return options
    }

    /// Send an RPC request from a new Repeater tab and decode the result (GRP-004). Out-of-scope
    /// targets are refused unless `allowOutOfScope` (the "Send anyway?" answer).
    public func sendRPC(
        _ request: RawRequest, to target: HTTPTarget, title: String? = nil, allowOutOfScope: Bool = false
    ) async throws -> RPCSendOutcome {
        let path = RPC.parse(request: request, response: nil)?.path ?? "/"
        try await requireManualScope(target, path: path, override: allowOutOfScope)
        let tab = await repeater.openTab(
            request: request, target: target,
            title: title ?? RPC.parse(request: request, response: nil)?.method,
            options: rpcRepeaterOptions(for: request, target: target))
        guard let result = await repeater.send(tab.id) else { throw RPCServiceError("the tab closed") }
        let detail = RPC.parse(request: result.exchange.request, response: result.exchange.response).map {
            RPCCallDetail(call: $0, schema: grpcSchemaSet())
        }
        return RPCSendOutcome(tabID: tab.id, exchange: result.exchange, detail: detail, error: result.error)
    }
}
