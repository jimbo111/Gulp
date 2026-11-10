import Foundation
import GulpCodec
import GulpCore
import Testing

@testable import GulpFuzzer

// F33 GRP-005: Fuzzer positions inside protobuf messages.

@Suite("Protobuf field positions (GRP-005)")
struct RPCPositionTests {
    /// EchoRequest-like: 1 message (string), 2 times (varint), 3 meta { 1: "inner" }, 9 unknown.
    func request(_ rpcProtocol: RPCProtocol = .grpc) -> [UInt8] {
        let meta = ProtoMessage([ProtoField(1, .bytes(Array("inner".utf8)))])
        let message = ProtoMessage([
            ProtoField(1, .bytes(Array("hello".utf8))), ProtoField(2, .varint(2)),
            ProtoField(3, .bytes(meta.encoded)), ProtoField(9, .fixed32(7)),
        ])
        return RPC.request(path: "/vulnlab.Echo/Say", host: "lab", messages: [message.encoded], rpcProtocol)
            .bytes.rawBytes
    }

    func decoded(_ bytes: [UInt8]) throws -> (ProtoMessage, RawRequest) {
        let raw = RawRequest(Bytes(bytes))
        let call = try #require(RPC.parse(request: raw, response: nil))
        return (try Protobuf.decode(try #require(call.requests.first).payload), raw)
    }

    @Test("Payloads replace a field's value; lengths, envelope and Content-Length are recomputed")
    func test_GRP005_render() throws {
        let positions = try RPCPositions(request: request(), paths: [[1], [2], [3, 1]])
        let template = FuzzTemplate(rpc: positions)
        #expect(template.positionCount == 3)
        #expect(template.baseValues.map { String(decoding: $0, as: UTF8.self) } == ["hello", "2", "inner"])
        let payload = "' OR 1=1-- <script>alert(1)</script>"
        let bytes = template.render([
            Array(payload.utf8), Array("-1".utf8), Array("a much longer inner value".utf8),
        ])
        let (message, raw) = try decoded(bytes)
        #expect(message.value(at: [1]) == .bytes(Array(payload.utf8)))
        #expect(message.value(at: [2]) == .varint(UInt64.max))  // -1 as two's complement
        #expect(message.value(at: [3, 1]) == .bytes(Array("a much longer inner value".utf8)))
        #expect(message.field(9)?.value == .fixed32(7))  // untouched fields keep their place
        #expect(message.fields.map(\.number) == [1, 2, 3, 9])
        let body = Array(raw.bytes.rawBytes[raw.parsed.body])
        #expect(raw.headerValue("content-length")?.string() == String(body.count))
        #expect(Int(body[1]) << 24 | Int(body[2]) << 16 | Int(body[3]) << 8 | Int(body[4]) == body.count - 5)
        // No payloads: the base message.
        #expect(try decoded(template.base).0 == (try decoded(request()).0))
    }

    @Test("Text in a number field is sent as bytes (type confusion); gRPC-Web text mode re-encodes too")
    func test_GRP005_typesAndProtocols() throws {
        let positions = try RPCPositions(request: request(.grpcWebText), paths: [[2]])
        let bytes = positions.render([Array("abc".utf8)])
        #expect(try decoded(bytes).0.value(at: [2]) == .bytes(Array("abc".utf8)))
        let raw = RawRequest(Bytes(bytes))
        #expect(RPC.detect(raw) == .grpcWebText)
    }

    @Test("Bad templates are refused with a reason")
    func test_GRP005_errors() {
        #expect(throws: FuzzTemplateError.self) {
            try RPCPositions(request: Array("GET / HTTP/1.1\r\nHost: a\r\n\r\n".utf8), paths: [[1]])
        }
        #expect(throws: FuzzTemplateError.self) { try RPCPositions(request: request(), paths: [[4]]) }
        #expect(throws: FuzzTemplateError.self) { try RPCPositions(request: request(), paths: []) }
        let json = RPC.request(
            path: "/vulnlab.Echo/Say", host: "lab", messages: [Array(#"{"message":"x"}"#.utf8)], .connectUnary
        ).bytes.rawBytes
        let jsonRequest = String(decoding: json, as: UTF8.self)
            .replacingOccurrences(of: "application/proto", with: "application/json")
        #expect(throws: FuzzTemplateError.self) {
            try RPCPositions(request: Array(jsonRequest.utf8), paths: [[1]])
        }
    }

    @Test("An attack config with rpcFields plans over the fields; older saved configs still decode")
    func test_GRP005_config() throws {
        let config = FuzzAttackConfig(
            name: "grpc", target: HTTPTarget(scheme: .https, host: "lab", port: 8443), request: request(),
            attackType: .sniper, sets: [PayloadSet(.list(["a", "b", "c"]))], rpcFields: [[1]])
        let plan = try config.plan()
        #expect(plan.template.positionCount == 1)
        let items = Array(plan.items())
        #expect(items.count == 3)
        #expect(try decoded(plan.request(for: items[1])).0.value(at: [1]) == .bytes(Array("b".utf8)))
        var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(config)) as! [String: Any]
        json.removeValue(forKey: "rpcFields")
        let old = try JSONDecoder().decode(
            FuzzAttackConfig.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(old.rpcFields == nil)
    }
}

@Suite("Grep sees trailers (F33)")
struct TrailerGrepTests {
    @Test("FUZ-016 with gRPC: grep-match reads a chunked response's trailers (grpc-status)")
    func test_GRP005_grepTrailers() throws {
        let response = RawResponse(
            Bytes(
                "HTTP/2 200\r\ncontent-type: application/grpc\r\ntransfer-encoding: chunked\r\n\r\n"
                    + "5\r\nhello\r\n0\r\ngrpc-status: 3\r\ngrpc-message: bad\r\n\r\n"))
        let analyzer = try ResponseAnalyzer(
            matches: [GrepMatch("grpc-status: 3"), GrepMatch("hello"), GrepMatch("grpc-status: 0")],
            extracts: [])
        #expect(analyzer.analyze(response, payloads: []).matches == [true, true, false])
    }
}
