// GulpCodec — the gRPC server reflection protocol's messages (F33 GRP-003), for both sides: Gulp
// asks a server for its services and file descriptors, and VulnLab answers. Reflection is a
// bidirectional-streaming call; Gulp sends its requests in one body, half-closes, and reads the
// responses (one per request).

import Foundation

/// gRPC server reflection (`grpc.reflection.v1` and `v1alpha`, wire-identical).
public enum GRPCReflection {
    /// The v1 method path.
    public static let v1Path = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
    /// The older v1alpha path (same messages).
    public static let v1alphaPath = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"

    /// What a ServerReflectionRequest asks for.
    public enum Request: Sendable, Hashable {
        /// `list_services` (field 7).
        case listServices
        /// `file_containing_symbol` (field 4).
        case fileContainingSymbol(String)
        /// `file_by_filename` (field 3).
        case fileByFilename(String)
    }

    /// Encode a request.
    public static func encode(_ request: Request, host: String = "") -> [UInt8] {
        var fields: [ProtoField] = []
        if !host.isEmpty { fields.append(ProtoField(1, .bytes(Array(host.utf8)))) }
        switch request {
        case .listServices: fields.append(ProtoField(7, .bytes(Array("*".utf8))))
        case .fileContainingSymbol(let symbol): fields.append(ProtoField(4, .bytes(Array(symbol.utf8))))
        case .fileByFilename(let name): fields.append(ProtoField(3, .bytes(Array(name.utf8))))
        }
        return Protobuf.encode(ProtoMessage(fields))
    }

    /// Decode a request (the server side).
    public static func decodeRequest(_ bytes: [UInt8]) -> Request? {
        guard let message = try? Protobuf.decode(bytes) else { return nil }
        for field in message.fields {
            guard case .bytes(let b) = field.value else { continue }
            let text = String(decoding: b, as: UTF8.self)
            switch field.number {
            case 7: return .listServices
            case 4: return .fileContainingSymbol(text)
            case 3: return .fileByFilename(text)
            default: continue
            }
        }
        return nil
    }

    /// What a ServerReflectionResponse carried.
    public struct Response: Sendable, Hashable {
        /// Service names (`list_services_response`).
        public var services: [String] = []
        /// Serialized FileDescriptorProtos (`file_descriptor_response`).
        public var files: [[UInt8]] = []
        /// `error_response` (code, message).
        public var error: String?
    }

    /// Decode a response (the client side).
    public static func decodeResponse(_ bytes: [UInt8]) -> Response? {
        guard let message = try? Protobuf.decode(bytes) else { return nil }
        var response = Response()
        for field in message.fields {
            guard case .bytes(let b) = field.value, let inner = try? Protobuf.decode(b) else { continue }
            switch field.number {
            case 4:
                response.files += inner.fields.compactMap {
                    if case .bytes(let f) = $0.value, $0.number == 1 { f } else { nil }
                }
            case 6:
                for service in inner.fields where service.number == 1 {
                    if case .bytes(let s) = service.value, let name = try? Protobuf.decode(s).field(1),
                        case .bytes(let n) = name.value
                    {
                        response.services.append(String(decoding: n, as: UTF8.self))
                    }
                }
            case 7:
                let code =
                    inner.field(1).flatMap { if case .varint(let v) = $0.value { Int(v) } else { nil } } ?? 2
                let text = inner.field(2).flatMap {
                    if case .bytes(let t) = $0.value { String(decoding: t, as: UTF8.self) } else { nil }
                }
                response.error = "\(RPC.statusName(code)): \(text ?? "")"
            default: break
            }
        }
        return response
    }

    /// Encode a response listing `services` (the server side).
    public static func listServicesResponse(_ services: [String]) -> [UInt8] {
        let list = ProtoMessage(
            services.map {
                ProtoField(1, .bytes(Protobuf.encode(ProtoMessage([ProtoField(1, .bytes(Array($0.utf8)))]))))
            })
        return Protobuf.encode(ProtoMessage([ProtoField(6, .bytes(list.encoded))]))
    }

    /// Encode a response carrying file descriptors (the server side).
    public static func fileDescriptorResponse(_ files: [[UInt8]]) -> [UInt8] {
        let list = ProtoMessage(files.map { ProtoField(1, .bytes($0)) })
        return Protobuf.encode(ProtoMessage([ProtoField(4, .bytes(list.encoded))]))
    }

    /// Encode an error response (the server side).
    public static func errorResponse(code: Int, message: String) -> [UInt8] {
        let error = ProtoMessage([
            ProtoField(1, .varint(UInt64(code))), ProtoField(2, .bytes(Array(message.utf8))),
        ])
        return Protobuf.encode(ProtoMessage([ProtoField(7, .bytes(error.encoded))]))
    }
}
