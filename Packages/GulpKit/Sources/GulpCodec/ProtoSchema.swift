// GulpCodec — protobuf schemas (F33 GRP-003). `descriptor.proto` is itself protobuf, so a compiled
// FileDescriptorSet (or reflection's FileDescriptorProtos) decodes with the wire codec into these
// hand-written models, and encodes back the same way. A schema set resolves type names and maps a
// call path (`/pkg.Service/Method`) to its input and output messages, which then decode with names
// (a text form and proto3 JSON) and encode from JSON. Fields whose wire type contradicts the schema
// are kept as unknown rather than mis-decoded (F33 §5).

import Foundation

/// A field's declared type (FieldDescriptorProto.Type).
public enum ProtoFieldType: Int, Sendable, Hashable, Codable {
    case double = 1, float, int64, uint64, int32, fixed64, fixed32, bool, string, group, message, bytes
    case uint32, `enum`, sfixed32, sfixed64, sint32, sint64

    /// The wire type values of this type use (unpacked).
    public var wireType: ProtoWireType {
        switch self {
        case .double, .fixed64, .sfixed64: .fixed64
        case .float, .fixed32, .sfixed32: .fixed32
        case .string, .bytes, .message: .lengthDelimited
        case .group: .startGroup
        default: .varint
        }
    }

    /// Scalar numeric types that proto3 packs when repeated.
    public var packable: Bool { wireType != .lengthDelimited && wireType != .startGroup }

    /// The `.proto` keyword.
    public static func keyword(_ name: String) -> ProtoFieldType? {
        [
            "double": .double, "float": .float, "int64": .int64, "uint64": .uint64, "int32": .int32,
            "fixed64": .fixed64, "fixed32": .fixed32, "bool": .bool, "string": .string, "bytes": .bytes,
            "uint32": .uint32, "sfixed32": .sfixed32, "sfixed64": .sfixed64, "sint32": .sint32,
            "sint64": .sint64,
        ][name]
    }
}

/// A field's label.
public enum ProtoLabel: Int, Sendable, Hashable, Codable {
    /// Optional (or proto3 singular).
    case optional = 1
    /// proto2 required.
    case required = 2
    /// Repeated.
    case repeated = 3
}

/// A field declaration.
public struct ProtoFieldDef: Sendable, Hashable {
    /// Name.
    public var name: String
    /// Number.
    public var number: Int
    /// Label.
    public var label: ProtoLabel
    /// Type.
    public var type: ProtoFieldType
    /// For messages and enums: the fully qualified name (`.pkg.Msg`).
    public var typeName: String?
    /// JSON name (lowerCamelCase by default).
    public var jsonName: String
    /// The oneof it belongs to.
    public var oneofIndex: Int?

    /// A field.
    public init(
        name: String, number: Int, label: ProtoLabel = .optional, type: ProtoFieldType,
        typeName: String? = nil,
        jsonName: String? = nil, oneofIndex: Int? = nil
    ) {
        self.name = name
        self.number = number
        self.label = label
        self.type = type
        self.typeName = typeName
        self.jsonName = jsonName ?? Self.camel(name)
        self.oneofIndex = oneofIndex
    }

    /// protoc's JSON name: underscores removed, the following letter uppercased.
    static func camel(_ name: String) -> String {
        var out = ""
        var upper = false
        for c in name {
            if c == "_" {
                upper = true
            } else {
                out.append(upper ? Character(c.uppercased()) : c)
                upper = false
            }
        }
        return out
    }
}

/// An enum value.
public struct ProtoEnumValue: Sendable, Hashable {
    /// Name.
    public var name: String
    /// Number.
    public var number: Int
}

/// An enum declaration.
public struct ProtoEnumType: Sendable, Hashable {
    /// Name.
    public var name: String
    /// Values.
    public var values: [ProtoEnumValue]
}

/// A message declaration.
public struct ProtoMessageType: Sendable, Hashable {
    /// Name.
    public var name: String
    /// Fields.
    public var fields: [ProtoFieldDef]
    /// Nested messages.
    public var nested: [ProtoMessageType]
    /// Nested enums.
    public var enums: [ProtoEnumType]
    /// Oneof names.
    public var oneofs: [String]
    /// A synthesized map entry (key = 1, value = 2).
    public var isMapEntry: Bool

    /// A message type.
    public init(
        name: String, fields: [ProtoFieldDef] = [], nested: [ProtoMessageType] = [],
        enums: [ProtoEnumType] = [],
        oneofs: [String] = [], isMapEntry: Bool = false
    ) {
        self.name = name
        self.fields = fields
        self.nested = nested
        self.enums = enums
        self.oneofs = oneofs
        self.isMapEntry = isMapEntry
    }

    /// The field numbered `number`.
    public func field(_ number: Int) -> ProtoFieldDef? { fields.first { $0.number == number } }
}

/// An RPC method.
public struct ProtoMethod: Sendable, Hashable {
    /// Name.
    public var name: String
    /// Fully qualified input message (`.pkg.Req`).
    public var inputType: String
    /// Fully qualified output message.
    public var outputType: String
    /// Client streaming.
    public var clientStreaming: Bool
    /// Server streaming.
    public var serverStreaming: Bool
}

/// A service.
public struct ProtoService: Sendable, Hashable {
    /// Name.
    public var name: String
    /// Methods.
    public var methods: [ProtoMethod]
}

/// One `.proto` file (FileDescriptorProto).
public struct ProtoFile: Sendable, Hashable {
    /// File name (`vulnlab/echo.proto`).
    public var name: String
    /// Package.
    public var package: String
    /// Imported files.
    public var dependencies: [String]
    /// Top-level messages.
    public var messages: [ProtoMessageType]
    /// Top-level enums.
    public var enums: [ProtoEnumType]
    /// Services.
    public var services: [ProtoService]
    /// `proto2` or `proto3`.
    public var syntax: String

    /// A file.
    public init(
        name: String, package: String = "", dependencies: [String] = [], messages: [ProtoMessageType] = [],
        enums: [ProtoEnumType] = [], services: [ProtoService] = [], syntax: String = "proto3"
    ) {
        self.name = name
        self.package = package
        self.dependencies = dependencies
        self.messages = messages
        self.enums = enums
        self.services = services
        self.syntax = syntax
    }
}

// MARK: - descriptor.proto ⇄ models

/// Encoding and decoding descriptors with the wire codec.
public enum ProtoDescriptors {
    /// Decode a FileDescriptorSet (`protoc --descriptor_set_out`).
    public static func decodeSet(_ bytes: [UInt8]) throws(ProtoDecodeError) -> [ProtoFile] {
        try Protobuf.decode(bytes).fields.filter { $0.number == 1 }.map { field throws(ProtoDecodeError) in
            guard case .bytes(let file) = field.value else {
                throw ProtoDecodeError(message: "file is not a message", offset: 0)
            }
            return try decodeFile(file)
        }
    }

    /// Encode files as a FileDescriptorSet.
    public static func encodeSet(_ files: [ProtoFile]) -> [UInt8] {
        Protobuf.encode(ProtoMessage(files.map { ProtoField(1, .bytes(encodeFile($0))) }))
    }

    static func string(_ field: ProtoField) -> String? {
        guard case .bytes(let b) = field.value else { return nil }
        return String(decoding: b, as: UTF8.self)
    }

    static func int(_ field: ProtoField) -> Int? {
        guard case .varint(let v) = field.value else { return nil }
        return Int(truncatingIfNeeded: Int64(bitPattern: v))
    }

    static func sub(_ field: ProtoField) throws(ProtoDecodeError) -> ProtoMessage {
        guard case .bytes(let b) = field.value else {
            throw ProtoDecodeError(message: "expected a message", offset: 0)
        }
        return try Protobuf.decode(b)
    }

    /// Decode one FileDescriptorProto.
    public static func decodeFile(_ bytes: [UInt8]) throws(ProtoDecodeError) -> ProtoFile {
        var file = ProtoFile(name: "", syntax: "proto2")
        for field in try Protobuf.decode(bytes).fields {
            switch field.number {
            case 1: file.name = string(field) ?? ""
            case 2: file.package = string(field) ?? ""
            case 3: file.dependencies.append(string(field) ?? "")
            case 4: file.messages.append(try decodeMessage(try sub(field)))
            case 5: file.enums.append(try decodeEnum(try sub(field)))
            case 6: file.services.append(try decodeService(try sub(field)))
            case 12: file.syntax = string(field) ?? "proto2"
            default: break
            }
        }
        return file
    }

    static func decodeMessage(_ message: ProtoMessage) throws(ProtoDecodeError) -> ProtoMessageType {
        var type = ProtoMessageType(name: "")
        for field in message.fields {
            switch field.number {
            case 1: type.name = string(field) ?? ""
            case 2: type.fields.append(try decodeField(try sub(field)))
            case 3: type.nested.append(try decodeMessage(try sub(field)))
            case 4: type.enums.append(try decodeEnum(try sub(field)))
            case 7: type.isMapEntry = (try sub(field)).field(7).flatMap(int) == 1
            case 8: type.oneofs.append((try sub(field)).field(1).flatMap(string) ?? "")
            default: break
            }
        }
        return type
    }

    static func decodeField(_ message: ProtoMessage) throws(ProtoDecodeError) -> ProtoFieldDef {
        var def = ProtoFieldDef(name: "", number: 0, type: .string)
        var jsonName: String?
        for field in message.fields {
            switch field.number {
            case 1: def.name = string(field) ?? ""
            case 3: def.number = int(field) ?? 0
            case 4: def.label = ProtoLabel(rawValue: int(field) ?? 1) ?? .optional
            case 5: def.type = ProtoFieldType(rawValue: int(field) ?? 9) ?? .bytes
            case 6: def.typeName = string(field)
            case 9: def.oneofIndex = int(field)
            case 10: jsonName = string(field)
            default: break
            }
        }
        def.jsonName = jsonName ?? ProtoFieldDef.camel(def.name)
        return def
    }

    static func decodeEnum(_ message: ProtoMessage) throws(ProtoDecodeError) -> ProtoEnumType {
        var type = ProtoEnumType(name: "", values: [])
        for field in message.fields {
            switch field.number {
            case 1: type.name = string(field) ?? ""
            case 2:
                let value = try sub(field)
                type.values.append(
                    ProtoEnumValue(
                        name: value.field(1).flatMap(string) ?? "", number: value.field(2).flatMap(int) ?? 0))
            default: break
            }
        }
        return type
    }

    static func decodeService(_ message: ProtoMessage) throws(ProtoDecodeError) -> ProtoService {
        var service = ProtoService(name: "", methods: [])
        for field in message.fields {
            switch field.number {
            case 1: service.name = string(field) ?? ""
            case 2:
                let m = try sub(field)
                service.methods.append(
                    ProtoMethod(
                        name: m.field(1).flatMap(string) ?? "", inputType: m.field(2).flatMap(string) ?? "",
                        outputType: m.field(3).flatMap(string) ?? "",
                        clientStreaming: m.field(5).flatMap(int) == 1,
                        serverStreaming: m.field(6).flatMap(int) == 1))
            default: break
            }
        }
        return service
    }

    static func s(_ number: Int, _ text: String) -> ProtoField {
        ProtoField(number, .bytes(Array(text.utf8)))
    }
    static func n(_ number: Int, _ value: Int) -> ProtoField {
        ProtoField(number, .varint(UInt64(bitPattern: Int64(value))))
    }
    static func m(_ number: Int, _ fields: [ProtoField]) -> ProtoField {
        ProtoField(number, .bytes(Protobuf.encode(ProtoMessage(fields))))
    }

    /// Encode one FileDescriptorProto.
    public static func encodeFile(_ file: ProtoFile) -> [UInt8] {
        var fields = [s(1, file.name)]
        if !file.package.isEmpty { fields.append(s(2, file.package)) }
        fields += file.dependencies.map { s(3, $0) }
        fields += file.messages.map { m(4, messageFields($0)) }
        fields += file.enums.map { m(5, enumFields($0)) }
        fields += file.services.map { service in
            m(
                6,
                [s(1, service.name)]
                    + service.methods.map { method in
                        var parts = [s(1, method.name), s(2, method.inputType), s(3, method.outputType)]
                        if method.clientStreaming { parts.append(n(5, 1)) }
                        if method.serverStreaming { parts.append(n(6, 1)) }
                        return m(2, parts)
                    })
        }
        if file.syntax != "proto2" { fields.append(s(12, file.syntax)) }
        return Protobuf.encode(ProtoMessage(fields))
    }

    static func messageFields(_ type: ProtoMessageType) -> [ProtoField] {
        var fields = [s(1, type.name)]
        fields += type.fields.map { def in
            var parts = [s(1, def.name), n(3, def.number), n(4, def.label.rawValue), n(5, def.type.rawValue)]
            if let typeName = def.typeName { parts.append(s(6, typeName)) }
            if let oneof = def.oneofIndex { parts.append(n(9, oneof)) }
            parts.append(s(10, def.jsonName))
            return m(2, parts)
        }
        fields += type.nested.map { m(3, messageFields($0)) }
        fields += type.enums.map { m(4, enumFields($0)) }
        if type.isMapEntry { fields.append(m(7, [n(7, 1)])) }
        fields += type.oneofs.map { m(8, [s(1, $0)]) }
        return fields
    }

    static func enumFields(_ type: ProtoEnumType) -> [ProtoField] {
        [s(1, type.name)] + type.values.map { m(2, [s(1, $0.name), n(2, $0.number)]) }
    }
}

// MARK: - the schema set

/// Imported files, with name resolution and named decoding.
public struct ProtoSchemaSet: Sendable, Hashable {
    /// The files.
    public private(set) var files: [ProtoFile] = []
    /// Fully qualified message name (`.pkg.Outer.Inner`) → type.
    public private(set) var messages: [String: ProtoMessageType] = [:]
    /// Fully qualified enum name → type.
    public private(set) var enums: [String: ProtoEnumType] = [:]
    /// `/pkg.Service/Method` → method.
    public private(set) var methods: [String: ProtoMethod] = [:]

    /// An empty set.
    public init() {}

    /// A set of `files`.
    public init(_ files: [ProtoFile]) {
        for file in files { add(file) }
    }

    /// Add (or replace by name) a file.
    public mutating func add(_ file: ProtoFile) {
        files.removeAll { $0.name == file.name }
        files.append(file)
        let prefix = file.package.isEmpty ? "" : "." + file.package
        func index(_ type: ProtoMessageType, _ scope: String) {
            let full = scope + "." + type.name
            messages[full] = type
            for e in type.enums { enums[full + "." + e.name] = e }
            for nested in type.nested { index(nested, full) }
        }
        for type in file.messages { index(type, prefix) }
        for e in file.enums { enums[prefix + "." + e.name] = e }
        for service in file.services {
            let qualified = (file.package.isEmpty ? "" : file.package + ".") + service.name
            for method in service.methods { methods["/\(qualified)/\(method.name)"] = method }
        }
    }

    /// Service names (`pkg.Service`).
    public var services: [String] {
        Array(Set(methods.keys.compactMap { $0.split(separator: "/").first.map(String.init) })).sorted()
    }

    /// The message types of a call: input for requests, output for responses.
    public func types(for path: String) -> (input: String, output: String)? {
        methods[path].map { ($0.inputType, $0.outputType) }
    }

    func valueText(_ value: ProtoValue, _ def: ProtoFieldDef) -> String? {
        switch (def.type, value) {
        case (.string, .bytes(let b)): return ProtoMessage.quote(String(decoding: b, as: UTF8.self))
        case (.bytes, .bytes(let b)): return "\"" + Data(b).base64EncodedString() + "\" (base64)"
        case (.bool, .varint(let v)): return v != 0 ? "true" : "false"
        case (.int32, .varint(let v)), (.int64, .varint(let v)): return String(Int64(bitPattern: v))
        case (.uint32, .varint(let v)), (.uint64, .varint(let v)): return String(v)
        case (.sint32, .varint(let v)), (.sint64, .varint(let v)): return String(Protobuf.zigzag(v))
        case (.enum, .varint(let v)):
            let number = Int(truncatingIfNeeded: Int64(bitPattern: v))
            return def.typeName.flatMap { enums[$0] }?.values.first { $0.number == number }?.name
                ?? String(number)
        case (.fixed32, .fixed32(let v)): return String(v)
        case (.sfixed32, .fixed32(let v)): return String(Int32(bitPattern: v))
        case (.float, .fixed32(let v)): return String(Float(bitPattern: v))
        case (.fixed64, .fixed64(let v)): return String(v)
        case (.sfixed64, .fixed64(let v)): return String(Int64(bitPattern: v))
        case (.double, .fixed64(let v)): return String(Double(bitPattern: v))
        default: return nil
        }
    }

    /// The named text form of `bytes` as message `type` (`message: "hi"`); fields the schema doesn't
    /// know, or whose wire type doesn't match it, are shown by number as `[unknown] 9: …`.
    public func text(_ bytes: [UInt8], type: String, indent: String = "", depth: Int = 0) -> String {
        guard let messageType = messages[type], let message = try? Protobuf.decode(bytes) else {
            return (try? Protobuf.decode(bytes))?.text(indent: indent) ?? "\(indent)<\(bytes.count) bytes>"
        }
        var lines: [String] = []
        for field in message.fields {
            guard let def = messageType.field(field.number) else {
                lines.append(indent + "[unknown] " + ProtoMessage([field]).text())
                continue
            }
            if case .bytes(let b) = field.value, def.label == .repeated, def.type.packable,
                let values = Protobuf.packedVarints(b), def.type.wireType == .varint
            {
                for v in values {
                    lines.append("\(indent)\(def.name): \(valueText(.varint(v), def) ?? String(v))")
                }
                continue
            }
            if def.type == .message, case .bytes(let b) = field.value, let typeName = def.typeName,
                depth < Protobuf.maxDepth
            {
                lines.append("\(indent)\(def.name) {")
                lines.append(text(b, type: typeName, indent: indent + "  ", depth: depth + 1))
                lines.append("\(indent)}")
            } else if let rendered = valueText(field.value, def) {
                lines.append("\(indent)\(def.name): \(rendered)")
            } else {
                lines.append(indent + "[unknown] " + ProtoMessage([field]).text())
            }
        }
        return lines.filter { !$0.isEmpty }.joined(separator: "\n")
    }

    func jsonValue(_ value: ProtoValue, _ def: ProtoFieldDef, depth: Int) -> Any? {
        switch (def.type, value) {
        case (.message, .bytes(let b)): return def.typeName.flatMap { json(b, type: $0, depth: depth + 1) }
        case (.string, .bytes(let b)): return String(decoding: b, as: UTF8.self)
        case (.bytes, .bytes(let b)): return Data(b).base64EncodedString()
        case (.bool, .varint(let v)): return v != 0
        case (.int32, .varint(let v)): return Int(Int32(truncatingIfNeeded: Int64(bitPattern: v)))
        case (.sint32, .varint(let v)): return Int(Protobuf.zigzag(v))
        case (.uint32, .varint(let v)): return Int(UInt32(truncatingIfNeeded: v))
        case (.int64, .varint(let v)): return String(Int64(bitPattern: v))
        case (.sint64, .varint(let v)): return String(Protobuf.zigzag(v))
        case (.uint64, .varint(let v)): return String(v)
        case (.enum, .varint(let v)):
            let number = Int(truncatingIfNeeded: Int64(bitPattern: v))
            return def.typeName.flatMap { enums[$0] }?.values.first { $0.number == number }?.name ?? number
        case (.fixed32, .fixed32(let v)): return Int(v)
        case (.sfixed32, .fixed32(let v)): return Int(Int32(bitPattern: v))
        case (.float, .fixed32(let v)): return Double(Float(bitPattern: v))
        case (.fixed64, .fixed64(let v)): return String(v)
        case (.sfixed64, .fixed64(let v)): return String(Int64(bitPattern: v))
        case (.double, .fixed64(let v)): return Double(bitPattern: v)
        default: return nil
        }
    }

    /// Proto3 JSON for `bytes` as message `type` (unknown fields left out), or nil.
    public func json(_ bytes: [UInt8], type: String, depth: Int = 0) -> [String: Any]? {
        guard depth < Protobuf.maxDepth, let messageType = messages[type],
            let message = try? Protobuf.decode(bytes)
        else { return nil }
        var object: [String: Any] = [:]
        for field in message.fields {
            guard let def = messageType.field(field.number) else { continue }
            // Packed repeated scalars.
            if def.label == .repeated, def.type.packable, case .bytes(let b) = field.value {
                var values: [Any] = []
                var index = 0
                while index < b.count {
                    switch def.type.wireType {
                    case .varint:
                        guard let v = try? Protobuf.varint(b, &index) else { index = b.count; continue }
                        values.append(jsonValue(.varint(v), def, depth: depth) ?? v)
                    case .fixed32 where index + 4 <= b.count:
                        values.append(
                            jsonValue(
                                .fixed32(UInt32(Protobuf.littleEndian(b[index..<(index + 4)]))), def,
                                depth: depth) as Any)
                        index += 4
                    case .fixed64 where index + 8 <= b.count:
                        values.append(
                            jsonValue(
                                .fixed64(Protobuf.littleEndian(b[index..<(index + 8)])), def, depth: depth)
                                as Any)
                        index += 8
                    default: index = b.count
                    }
                }
                object[def.jsonName] = ((object[def.jsonName] as? [Any]) ?? []) + values
                continue
            }
            guard let value = jsonValue(field.value, def, depth: depth) else { continue }
            if def.label == .repeated {
                if def.type == .message, let typeName = def.typeName, messages[typeName]?.isMapEntry == true,
                    let entry = value as? [String: Any]
                {
                    var map = (object[def.jsonName] as? [String: Any]) ?? [:]
                    map["\(entry["key"] ?? "")"] = entry["value"]
                    object[def.jsonName] = map
                } else {
                    object[def.jsonName] = ((object[def.jsonName] as? [Any]) ?? []) + [value]
                }
            } else {
                object[def.jsonName] = value
            }
        }
        return object
    }

    /// Encode a proto3 JSON object as message `type` (GRP-004 editing). Unknown keys are errors.
    public func encode(json object: [String: Any], type: String) throws(CodecError) -> [UInt8] {
        guard let messageType = messages[type] else { throw CodecError("unknown message type \(type)") }
        var fields: [ProtoField] = []
        for def in messageType.fields {
            guard let value = object[def.jsonName] ?? object[def.name], !(value is NSNull) else { continue }
            if def.label == .repeated {
                if def.type == .message, let typeName = def.typeName, let entry = messages[typeName],
                    entry.isMapEntry,
                    let map = value as? [String: Any]
                {
                    for key in map.keys.sorted() {
                        let entryBytes = try encode(
                            json: ["key": key, "value": map[key] as Any], type: typeName)
                        fields.append(ProtoField(def.number, .bytes(entryBytes)))
                    }
                    continue
                }
                guard let list = value as? [Any] else { throw CodecError("\(def.name) must be a list") }
                if def.type.packable {
                    var packed: [UInt8] = []
                    for item in list {
                        packed += Protobuf.encode(try scalar(item, def)).dropTagBytes(def.number)
                    }
                    fields.append(ProtoField(def.number, .bytes(packed)))
                } else {
                    for item in list { fields.append(try scalar(item, def)) }
                }
            } else {
                fields.append(try scalar(value, def))
            }
        }
        let known = Set(messageType.fields.flatMap { [$0.jsonName, $0.name] })
        if let stray = object.keys.first(where: { !known.contains($0) }) {
            throw CodecError("\(type) has no field \(stray)")
        }
        return Protobuf.encode(ProtoMessage(fields))
    }

    func scalar(_ value: Any, _ def: ProtoFieldDef) throws(CodecError) -> ProtoField {
        func number() throws(CodecError) -> Double {
            if let n = value as? NSNumber { return n.doubleValue }
            if let s = value as? String, let n = Double(s) { return n }
            throw CodecError("\(def.name) must be a number")
        }
        func integer() throws(CodecError) -> Int64 {
            if let n = value as? NSNumber { return n.int64Value }
            if let s = value as? String, let n = Int64(s) { return n }
            throw CodecError("\(def.name) must be an integer")
        }
        switch def.type {
        case .string:
            guard let s = value as? String else { throw CodecError("\(def.name) must be a string") }
            return ProtoField(def.number, .bytes(Array(s.utf8)))
        case .bytes:
            guard let s = value as? String, let data = Data(base64Encoded: s) else {
                throw CodecError("\(def.name) must be base64")
            }
            return ProtoField(def.number, .bytes([UInt8](data)))
        case .message:
            guard let object = value as? [String: Any], let typeName = def.typeName else {
                throw CodecError("\(def.name) must be an object")
            }
            return ProtoField(def.number, .bytes(try encode(json: object, type: typeName)))
        case .bool:
            guard let b = value as? Bool else { throw CodecError("\(def.name) must be true or false") }
            return ProtoField(def.number, .varint(b ? 1 : 0))
        case .enum:
            if let name = value as? String, let typeName = def.typeName,
                let match = enums[typeName]?.values.first(where: { $0.name == name })
            {
                return ProtoField(def.number, .varint(UInt64(bitPattern: Int64(match.number))))
            }
            return ProtoField(def.number, .varint(UInt64(bitPattern: try integer())))
        case .int32, .int64, .uint32, .uint64:
            return ProtoField(def.number, .varint(UInt64(bitPattern: try integer())))
        case .sint32, .sint64: return ProtoField(def.number, .varint(Protobuf.zigzag(try integer())))
        case .fixed32: return ProtoField(def.number, .fixed32(UInt32(truncatingIfNeeded: try integer())))
        case .sfixed32:
            return ProtoField(
                def.number, .fixed32(UInt32(bitPattern: Int32(truncatingIfNeeded: try integer()))))
        case .float: return ProtoField(def.number, .fixed32(Float(try number()).bitPattern))
        case .fixed64: return ProtoField(def.number, .fixed64(UInt64(bitPattern: try integer())))
        case .sfixed64: return ProtoField(def.number, .fixed64(UInt64(bitPattern: try integer())))
        case .double: return ProtoField(def.number, .fixed64(try number().bitPattern))
        case .group: throw CodecError("groups can't be edited as JSON")
        }
    }
}

extension Array where Element == UInt8 {
    /// An encoded field without its tag (for packing): the tag of field `number` is a varint.
    fileprivate func dropTagBytes(_ number: Int) -> [UInt8] {
        Array(dropFirst(Protobuf.varint(UInt64(number) << 3).count))
    }
}

extension ProtoSchemaSet {
    /// Resolve a dotted field path (`meta.cached`, `3.2`, or a mix) against message `type` to
    /// field numbers. Numbers pass through (also without a schema); names need the schema and every
    /// step but the last must be a message field. Nil when a name doesn't resolve.
    public func fieldPath(_ dotted: String, type: String?) -> [Int]? {
        var path: [Int] = []
        var current = type.flatMap { messages[$0] }
        for part in dotted.split(separator: ".", omittingEmptySubsequences: false).map(String.init) {
            let def: ProtoFieldDef?
            if let number = Int(part) {
                path.append(number)
                def = current?.field(number)
            } else {
                guard let found = current?.fields.first(where: { $0.name == part || $0.jsonName == part })
                else { return nil }
                path.append(found.number)
                def = found
            }
            current = def?.type == .message ? def?.typeName.flatMap { messages[$0] } : nil
        }
        return path.isEmpty ? nil : path
    }
}
