// GulpCodec — gRPC, gRPC-Web and Connect framing (F33 GRP-001). Bodies are split into their
// messages (1 flag byte, 4-byte big-endian length, payload), compressed messages are inflated for
// display, and the call's outcome is read from wherever the protocol keeps it: HTTP/2 trailers
// (gRPC; Gulp stores them as a chunked body's trailer section), the in-body trailer message (gRPC-Web,
// flag bit 7), Connect's end-of-stream message (flag bit 1) or, for Connect unary, the HTTP status
// and a JSON error body. Nothing here changes stored bytes.

import Foundation
import GulpCore

/// Which RPC protocol an exchange speaks.
public enum RPCProtocol: String, Sendable, Hashable, Codable, CaseIterable {
    /// gRPC over HTTP/2 (`application/grpc`).
    case grpc
    /// gRPC-Web, binary (`application/grpc-web`).
    case grpcWeb = "grpc-web"
    /// gRPC-Web, base64 text (`application/grpc-web-text`).
    case grpcWebText = "grpc-web-text"
    /// Connect streaming (`application/connect+proto`).
    case connect
    /// Connect unary (`application/proto` with `Connect-Protocol-Version`).
    case connectUnary = "connect-unary"

    /// The label in History ("gRPC", "gRPC-Web", "Connect").
    public var label: String {
        switch self {
        case .grpc: "gRPC"
        case .grpcWeb, .grpcWebText: "gRPC-Web"
        case .connect, .connectUnary: "Connect"
        }
    }

    /// The request `Content-Type` for protobuf payloads.
    public var contentType: String {
        switch self {
        case .grpc: "application/grpc"
        case .grpcWeb: "application/grpc-web+proto"
        case .grpcWebText: "application/grpc-web-text+proto"
        case .connect: "application/connect+proto"
        case .connectUnary: "application/proto"
        }
    }

    /// Messages carry the 5-byte envelope.
    public var enveloped: Bool { self != .connectUnary }
}

/// One message of a call.
public struct RPCMessage: Sendable, Hashable {
    /// The flag byte (0 for Connect unary).
    public var flags: UInt8
    /// The payload as framed (possibly compressed).
    public var framed: [UInt8]
    /// The payload to decode (inflated when it was compressed and the encoding is supported).
    public var payload: [UInt8]
    /// The payload is JSON (`+json` content types), not protobuf.
    public var json: Bool
    /// Why it couldn't be inflated, if it couldn't.
    public var warning: String?

    /// Compressed on the wire.
    public var compressed: Bool { flags & 0x01 != 0 }
}

/// A decoded RPC call (GRP-001).
public struct RPCCall: Sendable, Hashable {
    /// The protocol.
    public var rpcProtocol: RPCProtocol
    /// `/package.Service/Method`.
    public var path: String
    /// Request messages.
    public var requests: [RPCMessage]
    /// Response messages (trailer/end-stream messages excluded).
    public var responses: [RPCMessage]
    /// Trailer fields (lowercased names), wherever the protocol carried them.
    public var trailers: [(name: String, value: String)]
    /// The gRPC status code (0 = OK), nil when absent.
    public var status: Int?
    /// The status message (percent-decoded).
    public var statusMessage: String?
    /// Things the user should know ("no gRPC status", "unsupported encoding").
    public var warnings: [String]

    /// `package.Service`.
    public var service: String { path.split(separator: "/").first.map(String.init) ?? "" }
    /// `Method`.
    public var method: String { path.split(separator: "/").last.map(String.init) ?? "" }

    /// `OK`, `INVALID_ARGUMENT`…
    public var statusName: String? { status.map(RPC.statusName) }

    public static func == (a: RPCCall, b: RPCCall) -> Bool {
        a.rpcProtocol == b.rpcProtocol && a.path == b.path && a.requests == b.requests
            && a.responses == b.responses
            && a.trailers.map { "\($0.name)=\($0.value)" } == b.trailers.map { "\($0.name)=\($0.value)" }
            && a.status == b.status && a.statusMessage == b.statusMessage && a.warnings == b.warnings
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(path)
        hasher.combine(status)
        hasher.combine(requests)
    }
}

/// gRPC/gRPC-Web/Connect framing and recognition.
public enum RPC {
    static let statusNames = [
        "OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS",
        "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE",
        "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED",
    ]

    /// The gRPC name of a status code.
    public static func statusName(_ code: Int) -> String {
        statusNames.indices.contains(code) ? statusNames[code] : "CODE_\(code)"
    }

    /// Connect's lowercase code names → gRPC codes.
    static func connectCode(_ name: String) -> Int {
        statusNames.firstIndex(of: name.uppercased()) ?? 2
    }

    /// The protocol of a request (by `Content-Type`, and `Connect-Protocol-Version` for unary).
    public static func detect(_ request: RawRequest) -> RPCProtocol? {
        let type =
            request.headerValue("content-type")?.string().lowercased()
            .split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
        if type.hasPrefix("application/grpc-web-text") { return .grpcWebText }
        if type.hasPrefix("application/grpc-web") { return .grpcWeb }
        if type == "application/grpc" || type.hasPrefix("application/grpc+") { return .grpc }
        if type.hasPrefix("application/connect+") { return .connect }
        if type == "application/proto" || type == "application/json",
            request.headerValue("connect-protocol-version") != nil
        {
            return .connectUnary
        }
        return nil
    }

    /// Frame payloads with the 5-byte envelope.
    public static func frame(_ payload: [UInt8], flags: UInt8 = 0) -> [UInt8] {
        let n = UInt32(payload.count)
        return [
            flags, UInt8(n >> 24), UInt8(truncatingIfNeeded: n >> 16), UInt8(truncatingIfNeeded: n >> 8),
            UInt8(truncatingIfNeeded: n),
        ] + payload
    }

    /// Split an enveloped body into (flags, payload) frames; leftover bytes (a truncated frame) are
    /// returned separately.
    public static func split(_ body: [UInt8]) -> (frames: [(flags: UInt8, payload: [UInt8])], rest: [UInt8]) {
        var frames: [(UInt8, [UInt8])] = []
        var index = 0
        while index + 5 <= body.count {
            let length =
                Int(body[index + 1]) << 24 | Int(body[index + 2]) << 16 | Int(body[index + 3]) << 8
                | Int(body[index + 4])
            guard index + 5 + length <= body.count else { break }
            frames.append((body[index], Array(body[(index + 5)..<(index + 5 + length)])))
            index += 5 + length
        }
        return (frames, Array(body[index...]))
    }

    /// gRPC-Web text: the body is base64, possibly several padded chunks back to back (one per
    /// HTTP chunk) — decode each padded segment separately.
    public static func decodeText(_ body: [UInt8]) -> [UInt8]? {
        let text = body.filter { !($0 == 0x0D || $0 == 0x0A || $0 == 0x20) }
        var out: [UInt8] = []
        var segment: [UInt8] = []
        func flush() -> Bool {
            guard !segment.isEmpty else { return true }
            guard let data = Data(base64Encoded: Data(segment)) else { return false }
            out += data
            segment = []
            return true
        }
        var index = 0
        while index < text.count {
            let group = Array(text[index..<min(index + 4, text.count)])
            segment += group
            index += 4
            if group.contains(0x3D) {  // "=": this segment ends here
                guard flush() else { return nil }
            }
        }
        guard flush() else { return nil }
        return out
    }

    /// The `name:value\r\n` lines of a gRPC-Web trailer message.
    public static func parseTrailerBlock(_ payload: [UInt8]) -> [(name: String, value: String)] {
        // `\.isNewline`, not "\r"/"\n": in a Swift String, "\r\n" is one Character.
        String(decoding: payload, as: UTF8.self).split(whereSeparator: \.isNewline).compactMap { line in
            guard let colon = line.firstIndex(of: ":") else { return nil }
            return (
                line[..<colon].trimmingCharacters(in: .whitespaces).lowercased(),
                line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            )
        }
    }

    /// Inflate a compressed message with `encoding` (gzip/deflate), or report why not.
    static func inflate(_ payload: [UInt8], _ encoding: String?) -> ([UInt8], String?) {
        switch encoding?.lowercased() {
        case "gzip"?: return ((try? Compression.decompress(payload, .gzip)) ?? payload, nil)
        case "deflate"?: return ((try? Compression.decompress(payload, .zlib)) ?? payload, nil)
        case let other?: return (payload, "unsupported encoding \(other)")
        case nil: return (payload, "compressed flag set but no encoding declared")
        }
    }

    static func messages(
        _ body: [UInt8], _ rpcProtocol: RPCProtocol, encoding: String?, json: Bool
    ) -> (messages: [RPCMessage], trailer: (flags: UInt8, payload: [UInt8])?, warnings: [String]) {
        var warnings: [String] = []
        var bytes = body
        if rpcProtocol == .grpcWebText {
            guard let decoded = decodeText(body) else {
                return ([], nil, ["the gRPC-Web text body isn't valid base64"])
            }
            bytes = decoded
        }
        guard rpcProtocol.enveloped else {
            return ([RPCMessage(flags: 0, framed: bytes, payload: bytes, json: json, warning: nil)], nil, [])
        }
        let (frames, rest) = split(bytes)
        if !rest.isEmpty { warnings.append("\(rest.count) trailing byte(s) don't form a complete message") }
        var messages: [RPCMessage] = []
        var trailer: (UInt8, [UInt8])?
        for (flags, payload) in frames {
            let isTrailer =
                (rpcProtocol == .grpcWeb || rpcProtocol == .grpcWebText)
                ? flags & 0x80 != 0
                : rpcProtocol == .connect ? flags & 0x02 != 0 : false
            if isTrailer {
                trailer = (flags, payload)
                continue
            }
            var message = RPCMessage(
                flags: flags, framed: payload, payload: payload, json: json, warning: nil)
            if message.compressed {
                let (plain, warning) = inflate(payload, encoding)
                message.payload = plain
                message.warning = warning
                if let warning { warnings.append(warning) }
            }
            messages.append(message)
        }
        return (messages, trailer, warnings)
    }

    /// Decode an exchange as an RPC call, or nil when it isn't one.
    public static func parse(request: RawRequest, response: RawResponse?) -> RPCCall? {
        guard let rpcProtocol = detect(request) else { return nil }
        let target = request.bytes[request.parsed.target].string()
        var path = String(target.split(separator: "?", maxSplits: 1).first ?? "")
        if let scheme = path.range(of: "://"), let slash = path[scheme.upperBound...].firstIndex(of: "/") {
            path = String(path[slash...])
        }
        let requestType = request.headerValue("content-type")?.string().lowercased() ?? ""
        let json = requestType.contains("json")
        let requestEncoding =
            (rpcProtocol == .connect
            ? request.headerValue("connect-content-encoding") : request.headerValue("grpc-encoding"))?
            .string()
        let requestBody = Array(request.bytes.rawBytes[request.parsed.body])
        let (requests, _, requestWarnings) = messages(
            requestBody, rpcProtocol, encoding: requestEncoding, json: json)
        var call = RPCCall(
            rpcProtocol: rpcProtocol, path: path, requests: requests, responses: [], trailers: [],
            status: nil,
            statusMessage: nil, warnings: requestWarnings)
        guard let response else { return call }
        let parts = HTTP2Text.responseParts(response)
        let body = parts.body
        let responseEncoding =
            (rpcProtocol == .connect
            ? response.headerValue("connect-content-encoding") : response.headerValue("grpc-encoding"))?
            .string()
        let (responses, trailer, responseWarnings) = messages(
            body, rpcProtocol, encoding: responseEncoding, json: json)
        call.responses = responses
        call.warnings += responseWarnings
        var trailers = parts.trailers.map { (name: $0.name.lowercased(), value: $0.value) }
        switch rpcProtocol {
        case .grpc:
            // Trailers-only responses put grpc-status in the headers.
            if !trailers.contains(where: { $0.name == "grpc-status" }) {
                trailers += parts.headers.filter { $0.name.lowercased().hasPrefix("grpc-") }
                    .map { (name: $0.name.lowercased(), value: $0.value) }
            }
        case .grpcWeb, .grpcWebText:
            if let trailer { trailers += parseTrailerBlock(trailer.payload) }
            if !trailers.contains(where: { $0.name == "grpc-status" }) {
                trailers += parts.headers.filter { $0.name.lowercased().hasPrefix("grpc-") }
                    .map { (name: $0.name.lowercased(), value: $0.value) }
            }
        case .connect:
            if let trailer {
                let object =
                    (try? JSONSerialization.jsonObject(with: Data(trailer.payload))) as? [String: Any]
                if let error = object?["error"] as? [String: Any] {
                    trailers.append(
                        ("grpc-status", String(connectCode(error["code"] as? String ?? "unknown"))))
                    trailers.append(("grpc-message", error["message"] as? String ?? ""))
                } else {
                    trailers.append(("grpc-status", "0"))
                }
            }
        case .connectUnary:
            if parts.status == 200 {
                trailers.append(("grpc-status", "0"))
            } else {
                let object = (try? JSONSerialization.jsonObject(with: Data(body))) as? [String: Any]
                trailers.append(("grpc-status", String(connectCode(object?["code"] as? String ?? "unknown"))))
                trailers.append(("grpc-message", object?["message"] as? String ?? ""))
                call.responses = []
            }
        }
        call.trailers = trailers
        call.status = trailers.last { $0.name == "grpc-status" }.flatMap { Int($0.value) }
        call.statusMessage = trailers.last { $0.name == "grpc-message" }.map {
            $0.value.removingPercentEncoding ?? $0.value
        }
        if call.status == nil { call.warnings.append("no gRPC status (missing trailers)") }
        return call
    }

    /// A request body for `messages` in `rpcProtocol` (uncompressed).
    public static func body(_ messages: [[UInt8]], _ rpcProtocol: RPCProtocol) -> [UInt8] {
        switch rpcProtocol {
        case .connectUnary: return messages.first ?? []
        case .grpcWebText: return Array(Data(messages.flatMap { frame($0) }).base64EncodedString().utf8)
        default: return messages.flatMap { frame($0) }
        }
    }

    /// The headers a request in `rpcProtocol` needs besides Host and Content-Length.
    public static func headers(_ rpcProtocol: RPCProtocol) -> [String] {
        switch rpcProtocol {
        case .grpc: ["Content-Type: application/grpc", "TE: trailers"]
        case .grpcWeb, .grpcWebText: ["Content-Type: \(rpcProtocol.contentType)", "X-Grpc-Web: 1"]
        case .connect: ["Content-Type: application/connect+proto", "Connect-Protocol-Version: 1"]
        case .connectUnary: ["Content-Type: application/proto", "Connect-Protocol-Version: 1"]
        }
    }

    /// A complete HTTP/1-text request calling `path` with `messages` (the engine sends gRPC over
    /// HTTP/2 when asked; the text form is how Gulp stores and edits requests).
    public static func request(
        path: String, host: String, messages: [[UInt8]], _ rpcProtocol: RPCProtocol
    ) -> RawRequest {
        let body = body(messages, rpcProtocol)
        let head =
            (["POST \(path) HTTP/1.1", "Host: \(host)"] + headers(rpcProtocol) + [
                "Content-Length: \(body.count)"
            ])
            .joined(separator: "\r\n")
        return RawRequest(Bytes(Array((head + "\r\n\r\n").utf8) + body))
    }

    /// `request` with message `index` replaced by `payload` (re-framed, Content-Length updated).
    public static func replacingMessage(_ request: RawRequest, at index: Int, with payload: [UInt8])
        -> RawRequest?
    {
        guard let rpcProtocol = detect(request) else { return nil }
        let body = Array(request.bytes.rawBytes[request.parsed.body])
        var payloads: [[UInt8]]
        if rpcProtocol.enveloped {
            let decoded = rpcProtocol == .grpcWebText ? (decodeText(body) ?? []) : body
            payloads = split(decoded).frames.map(\.payload)
        } else {
            payloads = [body]
        }
        guard payloads.indices.contains(index) else { return nil }
        payloads[index] = payload
        let newBody = self.body(payloads, rpcProtocol)
        var head = Array(request.bytes.rawBytes[0..<request.parsed.headerBlockEnd])
        let text = String(decoding: head, as: UTF8.self)
        if let range = text.range(of: #"(?im)^content-length:[ \t]*\d+"#, options: .regularExpression) {
            let replaced = text.replacingCharacters(in: range, with: "Content-Length: \(newBody.count)")
            head = Array(replaced.utf8)
        }
        return RawRequest(Bytes(head + newBody))
    }
}
