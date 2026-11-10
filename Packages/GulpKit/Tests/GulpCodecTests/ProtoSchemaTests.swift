import Foundation
import Testing

@testable import GulpCodec

// F33 GRP-003: `.proto` parsing, descriptor sets, named decoding, JSON, reflection messages.

let fixtureProto: String = {
    let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Fixtures/grpc/vulnlab.proto")
    return (try? String(contentsOf: url, encoding: .utf8)) ?? ""
}()

@Suite("Protobuf schemas (GRP-003)")
struct ProtoSchemaTests {
    func schema() throws -> ProtoSchemaSet {
        ProtoSchemaSet(try ProtoParser.parse(["vulnlab.proto": fixtureProto]))
    }

    @Test("The fixture parses: services, methods, nested types, enums, map entries, resolved names")
    func test_GRP003_parse() throws {
        let set = try schema()
        #expect(set.services == ["vulnlab.Echo", "vulnlab.Orders", "vulnlab.SafeOrders"])
        #expect(set.types(for: "/vulnlab.Echo/Say")?.input == ".vulnlab.EchoRequest")
        #expect(set.methods["/vulnlab.Echo/Stream"]?.serverStreaming == true)
        let request = try #require(set.messages[".vulnlab.EchoRequest"])
        #expect(request.fields.map(\.name) == ["message", "times", "mood", "labels", "numbers"])
        #expect(request.field(3)?.type == .enum && request.field(3)?.typeName == ".vulnlab.Mood")
        #expect(request.field(4)?.typeName == ".vulnlab.EchoRequest.LabelsEntry")
        #expect(set.messages[".vulnlab.EchoRequest.LabelsEntry"]?.isMapEntry == true)
        #expect(set.messages[".vulnlab.EchoReply"]?.field(3)?.typeName == ".vulnlab.EchoReply.Meta")
        #expect(set.messages[".vulnlab.EchoReply.Meta"]?.field(1)?.jsonName == "servedAt")
    }

    @Test("Descriptor sets: encode and decode back to the same models")
    func test_GRP003_descriptorSet() throws {
        let files = try ProtoParser.parse(["vulnlab.proto": fixtureProto])
        let bytes = ProtoDescriptors.encodeSet(files)
        #expect(try ProtoDescriptors.decodeSet(bytes) == files)
    }

    @Test("Named decoding: text with enum names, maps, packed numbers, nested messages; JSON both ways")
    func test_GRP003_named() throws {
        let set = try schema()
        let object: [String: Any] = [
            "message": "hello", "times": 2, "mood": "GRUMPY", "labels": ["a": "1"], "numbers": [1, 300],
        ]
        let bytes = try set.encode(json: object, type: ".vulnlab.EchoRequest")
        #expect(
            set.text(bytes, type: ".vulnlab.EchoRequest") == """
                message: "hello"
                times: 2
                mood: GRUMPY
                labels {
                  key: "a"
                  value: "1"
                }
                numbers: 1
                numbers: 300
                """)
        let json = try #require(set.json(bytes, type: ".vulnlab.EchoRequest"))
        #expect(json["message"] as? String == "hello" && json["mood"] as? String == "GRUMPY")
        #expect(json["labels"] as? [String: String] == ["a": "1"] && json["numbers"] as? [Int] == [1, 300])
        // Round trip through JSON.
        #expect(try set.encode(json: json, type: ".vulnlab.EchoRequest") == bytes)
        let reply = try set.encode(
            json: ["message": "hi", "meta": ["servedAt": "1700000000", "cached": true]],
            type: ".vulnlab.EchoReply")
        #expect(
            set.json(reply, type: ".vulnlab.EchoReply")?["meta"] as? [String: AnyHashable] == [
                "servedAt": "1700000000", "cached": true,
            ])
        #expect(throws: CodecError.self) { try set.encode(json: ["nope": 1], type: ".vulnlab.EchoRequest") }
    }

    @Test("§5: fields the schema doesn't know, or with the wrong wire type, show as unknown")
    func test_GRP003_mismatch() throws {
        let set = try schema()
        // message as a varint (wrong wire type) and an unknown field 9.
        let bytes: [UInt8] = [0x08, 0x05, 0x48, 0x01]
        #expect(
            set.text(bytes, type: ".vulnlab.EchoRequest")
                == "[unknown] 1: 5  (sint -3)\n[unknown] 9: 1  (sint -1)")
    }

    @Test("Parse errors carry the file and line; missing imports are errors except google/protobuf")
    func test_GRP003_errors() {
        func error(_ files: [String: String]) -> ProtoParseError? {
            do {
                _ = try ProtoParser.parse(files)
                return nil
            } catch { return error }
        }
        #expect(error(["a.proto": "syntax = \"proto3\";\nmessage A {\n  string x = ;\n}"])?.line == 3)
        #expect(error(["a.proto": "import \"b.proto\";"])?.message == "import not found: b.proto")
        let wkt =
            "syntax = \"proto3\";\nimport \"google/protobuf/timestamp.proto\";\nmessage A { google.protobuf.Timestamp at = 1; }"
        #expect(error(["a.proto": wkt]) == nil)
    }

    @Test("Reflection messages encode and decode on both sides")
    func test_GRP003_reflection() throws {
        #expect(GRPCReflection.decodeRequest(GRPCReflection.encode(.listServices)) == .listServices)
        #expect(
            GRPCReflection.decodeRequest(GRPCReflection.encode(.fileContainingSymbol("vulnlab.Echo")))
                == .fileContainingSymbol("vulnlab.Echo"))
        let services = GRPCReflection.decodeResponse(
            GRPCReflection.listServicesResponse(["vulnlab.Echo", "x.Y"]))
        #expect(services?.services == ["vulnlab.Echo", "x.Y"])
        let file = ProtoDescriptors.encodeFile(try ProtoParser.parse(["vulnlab.proto": fixtureProto])[0])
        let files = GRPCReflection.decodeResponse(GRPCReflection.fileDescriptorResponse([file]))
        #expect(files?.files == [file])
        #expect(
            GRPCReflection.decodeResponse(GRPCReflection.errorResponse(code: 5, message: "no"))?.error
                == "NOT_FOUND: no")
    }
}

@Suite("Field paths and typed edits (GRP-004/005)")
struct ProtoEditTests {
    @Test("Dotted paths resolve by name, JSON name or number; numbers work without a schema")
    func test_GRP004_fieldPath() throws {
        let set = ProtoSchemaSet(try ProtoParser.parse(["vulnlab.proto": fixtureProto]))
        #expect(set.fieldPath("message", type: ".vulnlab.EchoRequest") == [1])
        #expect(set.fieldPath("meta.servedAt", type: ".vulnlab.EchoReply") == [3, 1])
        #expect(set.fieldPath("meta.served_at", type: ".vulnlab.EchoReply") == [3, 1])
        #expect(set.fieldPath("3.cached", type: ".vulnlab.EchoReply") == [3, 2])
        #expect(set.fieldPath("nope", type: ".vulnlab.EchoRequest") == nil)
        #expect(ProtoSchemaSet().fieldPath("3.1", type: nil) == [3, 1])
        #expect(ProtoSchemaSet().fieldPath("message", type: nil) == nil)
    }

    @Test("Text becomes a value of the field's wire type, or bytes when it doesn't parse")
    func test_GRP005_parsing() {
        #expect(ProtoValue.parsing(Array("300".utf8), as: .varint) == .varint(300))
        #expect(ProtoValue.parsing(Array("-2".utf8), as: .varint) == .varint(UInt64(bitPattern: -2)))
        #expect(ProtoValue.parsing(Array("true".utf8), as: .varint) == .varint(1))
        #expect(ProtoValue.parsing(Array("1.5".utf8), as: .fixed64) == .fixed64((1.5 as Double).bitPattern))
        #expect(ProtoValue.parsing(Array("1.5".utf8), as: .fixed32) == .fixed32((1.5 as Float).bitPattern))
        #expect(ProtoValue.parsing(Array("x".utf8), as: .varint) == .bytes(Array("x".utf8)))
        #expect(ProtoValue.parsing(Array("12".utf8), as: .lengthDelimited) == .bytes(Array("12".utf8)))
        #expect(
            ProtoValue.varint(7).editableText == "7"
                && ProtoValue.bytes(Array("hi".utf8)).editableText == "hi")
    }
}
