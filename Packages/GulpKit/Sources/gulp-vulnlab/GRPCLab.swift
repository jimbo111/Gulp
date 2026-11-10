// gulp-vulnlab — gRPC services (doc 06 §3, F33): on the HTTPS listener (:8443, HTTP/2) as gRPC with
// HTTP/2 trailers, and on :8088 as gRPC-Web (binary and text) and Connect (streaming and unary).
//
//   vulnlab.Echo/Say        echoes `message` (`times` times); INVALID_ARGUMENT if the body isn't an
//                           EchoRequest — so a fuzzer's re-encoded payloads prove they parse
//   vulnlab.Echo/Stream     `times` replies (default 3), server-streaming
//   vulnlab.Orders/Get      a planted SQL injection in `id` (an SQLite error leaks; `' OR '1'='1`
//                           returns an order) — for the Scanner's gRPC insertion points (M11c)
//   vulnlab.SafeOrders/Get  the parameterized twin
//   grpc.reflection.v1(alpha).ServerReflection/ServerReflectionInfo   server reflection
//
// The schema below is Tests/Fixtures/grpc/vulnlab.proto, verbatim.

import Foundation
import GulpCodec
import GulpCore

enum GRPCLab {
    static let proto = #"""
        // VulnLab's gRPC services (doc 06 §3, F33). The same text is compiled into gulp-vulnlab, which
        // serves it through server reflection; keep the two in sync.
        syntax = "proto3";

        package vulnlab;

        // Says back what it's told.
        service Echo {
          rpc Say (EchoRequest) returns (EchoReply);
          rpc Stream (EchoRequest) returns (stream EchoReply);
        }

        enum Mood {
          MOOD_UNSPECIFIED = 0;
          HAPPY = 1;
          GRUMPY = 2;
        }

        message EchoRequest {
          string message = 1;
          int32 times = 2;
          Mood mood = 3;
          map<string, string> labels = 4;
          repeated int32 numbers = 5;
        }

        message EchoReply {
          message Meta {
            int64 served_at = 1;
            bool cached = 2;
          }
          string message = 1;
          int32 length = 2;
          Meta meta = 3;
          Mood mood = 4;
        }

        // Orders/Get has a planted SQL injection in `id` (M11c); SafeOrders/Get is its parameterized twin.
        service Orders {
          rpc Get (OrderRequest) returns (Order);
        }

        service SafeOrders {
          rpc Get (OrderRequest) returns (Order);
        }

        message OrderRequest {
          string id = 1;
        }

        message Order {
          string id = 1;
          string item = 2;
          double total = 3;
        }
        """#

    static let file: ProtoFile = {
        guard let parsed = try? ProtoParser.parse(["vulnlab.proto": proto]).first else {
            preconditionFailure("VulnLab's embedded vulnlab.proto doesn't parse")
        }
        return parsed
    }()
    static let schema = ProtoSchemaSet([file])
    static let descriptor = ProtoDescriptors.encodeFile(file)
    static let services = [
        "vulnlab.Echo", "vulnlab.Orders", "vulnlab.SafeOrders", "grpc.reflection.v1.ServerReflection",
    ]
    static let orders = ["1": ("Gulp T-shirt", 25.0), "2": ("Gulp mug", 12.5)]

    /// A call's outcome: reply messages and a status.
    struct Outcome {
        var replies: [[UInt8]]
        var status = 0
        var message = ""
    }

    /// The RPC reply for `request`, or nil when it isn't an RPC to one of VulnLab's services.
    static func respond(_ request: RawRequest, path: String) -> VulnReply? {
        guard path.hasPrefix("/vulnlab.") || path.hasPrefix("/grpc.reflection."),
            let call = RPC.parse(request: request, response: nil)
        else { return nil }
        let json = call.requests.first?.json ?? false
        var payloads = call.requests.map(\.payload)
        if json, let first = payloads.first, let type = schema.types(for: path)?.input,
            let object = (try? JSONSerialization.jsonObject(with: Data(first))) as? [String: Any]
        {
            payloads = [(try? schema.encode(json: object, type: type)) ?? []]
        }
        var outcome = dispatch(path, payloads)
        if json, let type = schema.types(for: path)?.output {
            outcome.replies = outcome.replies.map { reply in
                (try? JSONSerialization.data(
                    withJSONObject: schema.json(reply, type: type) ?? [:], options: [.sortedKeys]))
                    .map { [UInt8]($0) } ?? []
            }
        }
        return reply(outcome, call.rpcProtocol, json: json)
    }

    static func string(_ message: ProtoMessage, _ number: Int) -> String {
        if case .bytes(let b)? = message.field(number)?.value { return String(decoding: b, as: UTF8.self) }
        return ""
    }

    static func int(_ message: ProtoMessage, _ number: Int) -> Int {
        if case .varint(let v)? = message.field(number)?.value {
            return Int(truncatingIfNeeded: Int64(bitPattern: v))
        }
        return 0
    }

    static func dispatch(_ path: String, _ payloads: [[UInt8]]) -> Outcome {
        let first = payloads.first ?? []
        switch path {
        case "/vulnlab.Echo/Say", "/vulnlab.Echo/Stream":
            guard let request = try? Protobuf.decode(first) else {
                return Outcome(replies: [], status: 3, message: "cannot parse EchoRequest")
            }
            let text = string(request, 1)
            let times = max(1, int(request, 2))
            let mood = int(request, 3)
            if path.hasSuffix("/Say") {
                let message = Array(repeating: text, count: min(times, 10)).joined(separator: " ")
                return Outcome(replies: [echoReply(message, mood: mood)])
            }
            let count = int(request, 2) == 0 ? 3 : min(times, 50)
            return Outcome(replies: (1...count).map { echoReply("\(text) #\($0)", mood: mood) })
        case "/vulnlab.Orders/Get", "/vulnlab.SafeOrders/Get":
            guard let request = try? Protobuf.decode(first) else {
                return Outcome(replies: [], status: 3, message: "cannot parse OrderRequest")
            }
            let id = string(request, 1)
            if path.hasPrefix("/vulnlab.Orders/") {
                // Planted: the id is pasted into SQL.
                if id.lowercased().contains("' or '1'='1") { return Outcome(replies: [order("1")]) }
                if id.contains("'") {
                    return Outcome(
                        replies: [], status: 13,
                        message:
                            "SQLite error: unrecognized token: \"'\(id.split(separator: "'").last ?? "")\" in SELECT * FROM orders WHERE id = '\(id)'"
                    )
                }
            }
            guard orders[id] != nil else { return Outcome(replies: [], status: 5, message: "no order \(id)") }
            return Outcome(replies: [order(id)])
        case GRPCReflection.v1Path, GRPCReflection.v1alphaPath:
            return Outcome(replies: payloads.map(reflect))
        default:
            return Outcome(replies: [], status: 12, message: "unknown method \(path)")
        }
    }

    static func echoReply(_ message: String, mood: Int) -> [UInt8] {
        let meta = ProtoMessage([ProtoField(1, .varint(1_700_000_000)), ProtoField(2, .varint(0))])
        var fields = [
            ProtoField(1, .bytes(Array(message.utf8))), ProtoField(2, .varint(UInt64(message.utf8.count))),
            ProtoField(3, .bytes(meta.encoded)),
        ]
        if mood != 0 { fields.append(ProtoField(4, .varint(UInt64(bitPattern: Int64(mood))))) }
        return ProtoMessage(fields).encoded
    }

    static func order(_ id: String) -> [UInt8] {
        let (item, total) = orders[id] ?? ("?", 0)
        return ProtoMessage([
            ProtoField(1, .bytes(Array(id.utf8))), ProtoField(2, .bytes(Array(item.utf8))),
            ProtoField(3, .fixed64(total.bitPattern)),
        ]).encoded
    }

    static func reflect(_ payload: [UInt8]) -> [UInt8] {
        switch GRPCReflection.decodeRequest(payload) {
        case .listServices?: return GRPCReflection.listServicesResponse(services)
        case .fileContainingSymbol(let symbol)?:
            return symbol.hasPrefix("vulnlab.")
                ? GRPCReflection.fileDescriptorResponse([descriptor])
                : GRPCReflection.errorResponse(code: 5, message: "symbol not found: \(symbol)")
        case .fileByFilename(let name)?:
            return name == "vulnlab.proto"
                ? GRPCReflection.fileDescriptorResponse([descriptor])
                : GRPCReflection.errorResponse(code: 5, message: "file not found: \(name)")
        case nil: return GRPCReflection.errorResponse(code: 3, message: "unsupported reflection request")
        }
    }

    static let connectCodes = [
        3: ("invalid_argument", 400), 5: ("not_found", 404), 12: ("unimplemented", 404),
        13: ("internal", 500),
    ]

    /// The HTTP reply for an outcome in the caller's protocol.
    static func reply(_ outcome: Outcome, _ rpcProtocol: RPCProtocol, json: Bool) -> VulnReply {
        let frames = outcome.replies.flatMap { RPC.frame($0) }
        let message =
            outcome.message.addingPercentEncoding(
                withAllowedCharacters: .alphanumerics.union(.init(charactersIn: " -_.:/"))) ?? ""
        switch rpcProtocol {
        case .grpc:
            // HTTP/2 trailers are written as a chunked body's trailer section (HTTP2Text).
            var head =
                "HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\n\r\n"
            if !frames.isEmpty { head += String(frames.count, radix: 16) + "\r\n" }
            var bytes = Array(head.utf8) + frames
            if !frames.isEmpty { bytes += Array("\r\n".utf8) }
            bytes += Array("0\r\ngrpc-status: \(outcome.status)\r\ngrpc-message: \(message)\r\n\r\n".utf8)
            return VulnReply(bytes: bytes)
        case .grpcWeb, .grpcWebText:
            let trailer = RPC.frame(
                Array("grpc-status:\(outcome.status)\r\ngrpc-message:\(message)\r\n".utf8), flags: 0x80)
            var body = frames + trailer
            let text = rpcProtocol == .grpcWebText
            if text { body = Array(Data(body).base64EncodedString().utf8) }
            let type = text ? "application/grpc-web-text+proto" : "application/grpc-web+proto"
            return VulnReply(bytes: VulnLab.response(200, body: body, type: type))
        case .connect:
            let end: String
            if outcome.status == 0 {
                end = "{}"
            } else {
                end =
                    #"{"error":{"code":"\#(connectCodes[outcome.status]?.0 ?? "unknown")","message":"\#(outcome.message)"}}"#
            }
            let body = frames + RPC.frame(Array(end.utf8), flags: 0x02)
            return VulnReply(bytes: VulnLab.response(200, body: body, type: "application/connect+proto"))
        case .connectUnary:
            guard outcome.status == 0 else {
                let (code, http) = connectCodes[outcome.status] ?? ("unknown", 500)
                let error = #"{"code":"\#(code)","message":"\#(outcome.message)"}"#
                return VulnReply(
                    bytes: VulnLab.response(http, body: Array(error.utf8), type: "application/json"))
            }
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: outcome.replies.first ?? [],
                    type: json ? "application/json" : "application/proto"))
        }
    }
}
