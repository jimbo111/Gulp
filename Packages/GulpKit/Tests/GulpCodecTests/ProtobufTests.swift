import Foundation
import GulpCore
import Testing

@testable import GulpCodec

// F33 GRP-001/002: the protobuf wire codec and RPC framing.

/// `1: "hello"`, `2: 150`, `3 { 1: -2 (sint) }`, `4: 0x40490fdb (float 3.1415927)`.
let sample: [UInt8] = [
    0x0A, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,  // 1: "hello"
    0x10, 0x96, 0x01,  // 2: 150
    0x1A, 0x02, 0x08, 0x03,  // 3 { 1: 3 } (zigzag -2)
    0x25, 0xDB, 0x0F, 0x49, 0x40,  // 4: fixed32 float pi
]

@Suite("Protobuf wire codec (GRP-002)")
struct ProtobufTests {
    @Test("Decoding then encoding reproduces the bytes exactly; values and readings")
    func test_GRP002_roundTrip() throws {
        let message = try Protobuf.decode(sample)
        #expect(message.encoded == sample)
        #expect(message.fields.map(\.number) == [1, 2, 3, 4])
        #expect(message.field(2)?.value == .varint(150))
        #expect(message.value(at: [3, 1]) == .varint(3))
        #expect(Protobuf.zigzag(UInt64(3)) == -2 && Protobuf.zigzag(Int64(-2)) == 3)
        guard case .fixed32(let bits) = message.field(4)?.value else {
            Issue.record("fixed32 expected")
            return
        }
        #expect(abs(Float(bitPattern: bits) - Float.pi) < 0.0001)
        #expect(
            message.text() == """
                1: "hello"
                2: 150
                3 {
                  1: 3  (sint -2)
                }
                4: 0x40490fdb (fixed32; float 3.1415927)
                """)
        // Non-minimal varints and unknown fields survive untouched.
        let odd: [UInt8] = [0x08, 0x81, 0x80, 0x00, 0xF8, 0xFF, 0xFF, 0xFF, 0x07, 0x01]
        #expect(try Protobuf.decode(odd).encoded == odd)
    }

    @Test("Editing one nested field re-encodes only it and the enclosing lengths")
    func test_GRP004_edit() throws {
        let message = try Protobuf.decode(sample)
        let edited = try #require(message.setting([1], to: .bytes(Array("hi there".utf8))))
        #expect(edited.encoded.starts(with: [0x0A, 0x08] + Array("hi there".utf8)))
        #expect(Array(edited.encoded.dropFirst(10)) == Array(sample.dropFirst(7)))
        let nested = try #require(message.setting([3, 1], to: .varint(300)))
        #expect(nested.value(at: [3, 1]) == .varint(300))
        #expect(Array(nested.encoded[10..<15]) == [0x1A, 0x03, 0x08, 0xAC, 0x02])
        #expect(message.setting([9], to: .varint(1)) == nil)
        #expect(message.setting([2, 1], to: .varint(1)) == nil)  // 2 is a varint, not a message
    }

    @Test("Ambiguous length-delimited values: text, nested message, packed, bytes")
    func test_GRP002_readings() {
        #expect(Protobuf.readings(Array("hi".utf8)).first == .string("hi"))
        let readingsOfNested = Protobuf.readings([0x08, 0x96, 0x01])
        guard case .message(let inner) = readingsOfNested.first else {
            Issue.record("nested expected, got \(readingsOfNested)")
            return
        }
        #expect(inner.field(1)?.value == .varint(150))
        #expect(Protobuf.readings([0x96, 0x01, 0x05]).first == .packedVarints([150, 5]))
        #expect(Protobuf.readings([0xFF]).first == .bytes([0xFF]))
    }

    @Test("Malformed input is rejected with an offset; groups decode")
    func test_GRP002_malformed() throws {
        #expect(throws: ProtoDecodeError.self) { try Protobuf.decode([0x0A, 0x09, 0x01]) }  // length past end
        #expect(throws: ProtoDecodeError.self) { try Protobuf.decode([0x08]) }  // truncated varint
        #expect(throws: ProtoDecodeError.self) { try Protobuf.decode([0x07, 0x00]) }  // wire type 7
        let group: [UInt8] = [0x0B, 0x10, 0x01, 0x0C]  // 1 (group) { 2: 1 }
        let message = try Protobuf.decode(group)
        #expect(message.field(1)?.value == .group([ProtoField(2, .varint(1), raw: [0x10, 0x01])]))
        #expect(message.encoded == group)
    }
}

@Suite("RPC framing (GRP-001)")
struct RPCTests {
    let hello: [UInt8] = [0x0A, 0x05] + Array("hello".utf8)

    func request(_ type: String, _ body: [UInt8], extra: String = "") -> RawRequest {
        RawRequest(
            Bytes(
                Array(
                    "POST /vulnlab.Echo/Say HTTP/2\r\nHost: localhost\r\nContent-Type: \(type)\r\n\(extra)Content-Length: \(body.count)\r\n\r\n"
                        .utf8) + body))
    }

    @Test("gRPC over HTTP/2: messages from the body, status from the trailers")
    func test_GRP001_grpc() throws {
        let response = HTTP2Text.response(
            H2ResponseParts(
                status: 200, headers: [H2Header("content-type", "application/grpc")],
                body: RPC.frame([0x0A, 0x02, 0x68, 0x69]),
                trailers: [H2Header("grpc-status", "0"), H2Header("grpc-message", "")]))
        let call = try #require(
            RPC.parse(request: request("application/grpc", RPC.frame(hello)), response: response))
        #expect(call.rpcProtocol == .grpc && call.service == "vulnlab.Echo" && call.method == "Say")
        #expect(
            call.requests.map(\.payload) == [hello]
                && call.responses.map(\.payload) == [[0x0A, 0x02, 0x68, 0x69]])
        #expect(call.status == 0 && call.statusName == "OK" && call.warnings.isEmpty)
        // Trailers-only error responses carry grpc-status in the headers.
        let error = HTTP2Text.response(
            H2ResponseParts(
                status: 200,
                headers: [H2Header("grpc-status", "3"), H2Header("grpc-message", "bad%20id")], body: []))
        let failed = try #require(
            RPC.parse(request: request("application/grpc", RPC.frame(hello)), response: error))
        #expect(
            failed.status == 3 && failed.statusName == "INVALID_ARGUMENT" && failed.statusMessage == "bad id")
        // No status anywhere: a warning, not success.
        let broken = RawResponse(Bytes("HTTP/2 200\r\ncontent-type: application/grpc\r\n\r\n"))
        #expect(
            RPC.parse(request: request("application/grpc", []), response: broken)?.warnings == [
                "no gRPC status (missing trailers)"
            ])
    }

    @Test("gRPC-Web binary and text (several base64 chunks), with the in-body trailer message")
    func test_GRP001_grpcWeb() throws {
        let body =
            RPC.frame([0x0A, 0x02, 0x68, 0x69])
            + RPC.frame(Array("grpc-status:0\r\ngrpc-message:\r\n".utf8), flags: 0x80)
        let web = RawResponse(
            Bytes(
                Array(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: \(body.count)\r\n\r\n"
                        .utf8) + body))
        let call = try #require(
            RPC.parse(request: request("application/grpc-web+proto", RPC.frame(hello)), response: web))
        #expect(call.rpcProtocol == .grpcWeb && call.responses.count == 1 && call.status == 0)
        // Text mode: each part base64-encoded separately (as servers do per HTTP chunk).
        let text =
            Array(Data(RPC.frame([0x0A, 0x02, 0x68, 0x69])).base64EncodedString().utf8)
            + Array(
                Data(RPC.frame(Array("grpc-status:5\r\ngrpc-message:gone\r\n".utf8), flags: 0x80))
                    .base64EncodedString().utf8)
        let textResponse = RawResponse(
            Bytes(
                Array(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web-text\r\nContent-Length: \(text.count)\r\n\r\n"
                        .utf8) + text))
        let textRequest = request("application/grpc-web-text", RPC.body([hello], .grpcWebText))
        let decoded = try #require(RPC.parse(request: textRequest, response: textResponse))
        #expect(decoded.rpcProtocol == .grpcWebText && decoded.requests.map(\.payload) == [hello])
        #expect(decoded.responses.map(\.payload) == [[0x0A, 0x02, 0x68, 0x69]] && decoded.status == 5)
        #expect(decoded.statusMessage == "gone")
    }

    @Test("Connect streaming (end-of-stream JSON) and unary (HTTP status, JSON errors)")
    func test_GRP001_connect() throws {
        let stream = RPC.frame([0x0A, 0x02, 0x68, 0x69]) + RPC.frame(Array("{}".utf8), flags: 0x02)
        let ok = RawResponse(
            Bytes(
                Array(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/connect+proto\r\nContent-Length: \(stream.count)\r\n\r\n"
                        .utf8) + stream))
        let streaming = try #require(
            RPC.parse(request: request("application/connect+proto", RPC.frame(hello)), response: ok))
        #expect(streaming.rpcProtocol == .connect && streaming.responses.count == 1 && streaming.status == 0)
        let unaryRequest = request("application/proto", hello, extra: "Connect-Protocol-Version: 1\r\n")
        let unaryOK = RawResponse(
            Bytes(
                Array("HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: 4\r\n\r\n".utf8)
                    + [0x0A, 0x02, 0x68, 0x69]))
        let unary = try #require(RPC.parse(request: unaryRequest, response: unaryOK))
        #expect(
            unary.rpcProtocol == .connectUnary && unary.requests.map(\.payload) == [hello]
                && unary.status == 0)
        let errorBody = #"{"code":"not_found","message":"no such order"}"#
        let unaryError = RawResponse(
            Bytes(
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: \(errorBody.utf8.count)\r\n\r\n\(errorBody)"
            ))
        let failed = try #require(RPC.parse(request: unaryRequest, response: unaryError))
        #expect(failed.status == 5 && failed.statusMessage == "no such order" && failed.responses.isEmpty)
        #expect(RPC.detect(request("application/proto", hello)) == nil)  // no Connect-Protocol-Version
    }

    @Test("Compressed messages are inflated for display; unknown encodings warn")
    func test_GRP002_compressed() throws {
        let gz = try Compression.compress(hello, .gzip)
        let call = try #require(
            RPC.parse(
                request: request(
                    "application/grpc", RPC.frame(gz, flags: 1), extra: "grpc-encoding: gzip\r\n"),
                response: nil))
        #expect(call.requests.first?.compressed == true && call.requests.first?.payload == hello)
        let odd = try #require(
            RPC.parse(
                request: request(
                    "application/grpc", RPC.frame([1, 2], flags: 1), extra: "grpc-encoding: snappy\r\n"),
                response: nil))
        #expect(odd.warnings == ["unsupported encoding snappy"])
    }

    @Test("GRP-004: building a request and replacing a message re-frames and fixes Content-Length")
    func test_GRP004_build() throws {
        let built = RPC.request(path: "/vulnlab.Echo/Say", host: "localhost:8443", messages: [hello], .grpc)
        #expect(
            built.headerValue("te")?.string() == "trailers"
                && built.headerValue("content-length")?.string() == "12")
        let edited = try #require(RPC.replacingMessage(built, at: 0, with: [0x0A, 0x03] + Array("bye".utf8)))
        #expect(
            Array(edited.bytes.rawBytes[edited.parsed.body]) == RPC.frame([0x0A, 0x03] + Array("bye".utf8)))
        #expect(edited.headerValue("content-length")?.string() == "10")
        let text = RPC.request(path: "/vulnlab.Echo/Say", host: "h", messages: [hello], .grpcWebText)
        let replaced = try #require(RPC.replacingMessage(text, at: 0, with: [0x0A, 0x01, 0x78]))
        #expect(RPC.parse(request: replaced, response: nil)?.requests.map(\.payload) == [[0x0A, 0x01, 0x78]])
    }
}

@Suite("CRLF is one Character: separators and CSV quoting")
struct CRLFRegressionTests {
    @Test("Hex decoding skips CRLF separators; CSV quotes fields with CRLF")
    func test_crlf() throws {
        #expect(try Hex.decode(Array("de ad\r\nbe ef\r\n".utf8)) == [0xDE, 0xAD, 0xBE, 0xEF])
        #expect(HAR.quote("line one\r\nline two") == "\"line one\r\nline two\"")
        #expect(HAR.quote("plain") == "plain")
    }
}
