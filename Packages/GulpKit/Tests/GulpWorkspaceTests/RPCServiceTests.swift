import Foundation
import GulpCodec
import GulpCore
import Testing

@testable import GulpWorkspace

// F33 GRP-003…004 in a project: stored schemas, decoding recorded calls, editing messages, scope.

let workspaceFixtureProto: URL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .deletingLastPathComponent().appendingPathComponent("Fixtures/grpc/vulnlab.proto")

@Suite("gRPC in a project (GRP-003, GRP-004)")
struct RPCServiceTests {
    func say(_ message: String, mood: Int? = nil) -> RawRequest {
        var fields = [ProtoField(1, .bytes(Array(message.utf8))), ProtoField(2, .varint(2))]
        if let mood { fields.append(ProtoField(3, .varint(UInt64(mood)))) }
        return RPC.request(
            path: "/vulnlab.Echo/Say", host: "lab", messages: [ProtoMessage(fields).encoded], .grpcWeb)
    }

    func message(_ request: RawRequest) throws -> ProtoMessage {
        try Protobuf.decode(try #require(RPC.parse(request: request, response: nil)?.requests.first).payload)
    }

    @Test("Schemas: a .proto with imports from an import path, a descriptor set; both persist")
    func test_GRP003_importAndPersist() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "grpc-schemas")
        let folder = environment.supportDirectory.appendingPathComponent("protos")
        let common = folder.appendingPathComponent("include/common")
        try FileManager.default.createDirectory(at: common, withIntermediateDirectories: true)
        try "syntax = \"proto3\";\npackage common;\nmessage Ping { string note = 1; }\n".write(
            to: common.appendingPathComponent("ping.proto"), atomically: true, encoding: .utf8)
        let main = folder.appendingPathComponent("api.proto")
        try """
        syntax = "proto3";
        package api;
        import "common/ping.proto";
        import "google/protobuf/empty.proto";
        service Health { rpc Check(common.Ping) returns (common.Ping); }
        """.write(to: main, atomically: true, encoding: .utf8)
        let imported = try await session.importProto(
            at: main, importPaths: [folder.appendingPathComponent("include")])
        #expect(imported.services == ["api.Health"] && imported.source == "api.proto")
        #expect(session.grpcSchemaSet().types(for: "/api.Health/Check")?.input == ".common.Ping")
        // Missing imports are a parse error naming the file.
        await #expect(throws: RPCServiceError.self) { try await session.importProto(at: main) }

        let descriptor = environment.supportDirectory.appendingPathComponent("vulnlab.pb")
        let files = try ProtoParser.parse([
            "vulnlab.proto": String(contentsOf: workspaceFixtureProto, encoding: .utf8)
        ])
        try Data(ProtoDescriptors.encodeSet(files)).write(to: descriptor)
        try await session.importDescriptorSet(at: descriptor)
        await #expect(throws: RPCServiceError.self) {
            try await session.addGRPCSchema(descriptorSet: [0xFF, 0xFF], source: "junk")
        }
        try await session.close()

        let reopened = try await open(environment, "grpc-schemas")
        #expect(reopened.grpcSchemas().map(\.source) == ["api.proto", "vulnlab.pb"])
        #expect(
            reopened.grpcSchemaSet().services == [
                "api.Health", "vulnlab.Echo", "vulnlab.Orders", "vulnlab.SafeOrders",
            ])
        try await reopened.removeGRPCSchema(try #require(reopened.grpcSchemas().first).id)
        #expect(reopened.grpcSchemas().map(\.source) == ["vulnlab.pb"])
        try await reopened.close()
    }

    @Test("A recorded call decodes schema-less, then with names and JSON once a schema is imported")
    func test_GRP003_rpcCall() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "grpc-call")
        let reply = ProtoMessage([ProtoField(1, .bytes(Array("hi hi".utf8))), ProtoField(2, .varint(5))])
            .encoded
        let trailer = Array("grpc-status: 0\r\ngrpc-message: \r\n".utf8)
        let body = RPC.frame(reply) + RPC.frame(trailer, flags: 0x80)
        let response = RawResponse(
            Bytes(
                Array(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: \(body.count)\r\n\r\n"
                        .utf8)
                    + body))
        let id = await session.store.writer.record(
            Exchange(
                source: .proxy, target: HTTPTarget(scheme: .https, host: "lab", port: 8443),
                request: say("hi"),
                response: response, state: .complete))
        await session.store.writer.flush()
        let plain = try #require(try await session.rpcCall(id))
        #expect(
            plain.call.rpcProtocol == .grpcWeb && plain.call.status == 0
                && plain.call.path == "/vulnlab.Echo/Say")
        #expect(
            plain.requestTexts == ["1: \"hi\"\n2: 2"] && plain.inputType == nil && plain.requestJSON.isEmpty)
        #expect(plain.responseTexts == ["1: \"hi hi\"\n2: 5  (sint -3)"])

        try await session.importProto(at: workspaceFixtureProto)
        let named = try #require(try await session.rpcCall(id))
        #expect(named.inputType == ".vulnlab.EchoRequest" && named.outputType == ".vulnlab.EchoReply")
        #expect(named.requestTexts == ["message: \"hi\"\ntimes: 2"])
        #expect(named.responseTexts == ["message: \"hi hi\"\nlength: 5"])
        #expect(named.responseJSON.first?.contains("\"message\" : \"hi hi\"") == true)
        #expect(try await session.rpcCall(await NotebookTests().record(session, "GET", "/", .proxy)) == nil)
        try await session.close()
    }

    @Test("Editing: by name, number, enum name or JSON; other bytes kept; framing and length fixed")
    func test_GRP004_edit() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "grpc-edit")
        // Without a schema: numbers work, names don't.
        let byNumber = try session.editRPCRequest(say("hi"), fields: [("1", "edited"), ("2", "7")])
        #expect(try message(byNumber).value(at: [1]) == .bytes(Array("edited".utf8)))
        #expect(try message(byNumber).value(at: [2]) == .varint(7))
        let body = byNumber.bytes.rawBytes[byNumber.parsed.body]
        #expect(byNumber.headerValue("content-length")?.string() == String(body.count))
        #expect(throws: RPCServiceError.self) {
            try session.editRPCRequest(say("hi"), fields: [("message", "x")])
        }
        #expect(throws: RPCServiceError.self) { try session.editRPCRequest(say("hi"), json: "{}") }

        try await session.importProto(at: workspaceFixtureProto)
        let named = try session.editRPCRequest(
            say("hi", mood: 0), fields: [("message", "edited"), ("mood", "GRUMPY")])
        let decoded = try message(named)
        #expect(
            decoded.value(at: [1]) == .bytes(Array("edited".utf8)) && decoded.value(at: [3]) == .varint(2))
        #expect(decoded.value(at: [2]) == .varint(2))  // untouched
        // A field that isn't there yet is appended.
        #expect(
            try message(session.editRPCRequest(say("hi"), fields: [("mood", "HAPPY")])).value(at: [3])
                == .varint(1))
        let json = try session.editRPCRequest(say("hi"), json: #"{"message":"from json","times":3}"#)
        #expect(try message(json).fields.map(\.value) == [.bytes(Array("from json".utf8)), .varint(3)])
        #expect(throws: RPCServiceError.self) {
            try session.editRPCRequest(say("hi"), fields: [("nope", "x")])
        }
        #expect(throws: RPCServiceError.self) {
            try session.editRPCRequest(RawRequest(Bytes("GET / HTTP/1.1\r\n\r\n")), fields: [("1", "x")])
        }
        // gRPC goes over HTTP/2 from Repeater; gRPC-Web keeps the default.
        let grpc = RPC.request(path: "/vulnlab.Echo/Say", host: "lab", messages: [[]], .grpc)
        #expect(
            session.rpcRepeaterOptions(for: grpc, target: HTTPTarget(scheme: .https, host: "lab")).version
                == .http2)
        #expect(
            session.rpcRepeaterOptions(for: grpc, target: HTTPTarget(scheme: .http, host: "lab")).version
                == .http2PriorKnowledge)
        #expect(
            session.rpcRepeaterOptions(for: say("x"), target: HTTPTarget(scheme: .https, host: "lab")).version
                == .auto)
        try await session.close()
    }

    @Test("TGT-023: reflection and RPC sends to an out-of-scope target need the override")
    func test_GRP003_scope() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "grpc-scope")
        try await session.addToScope(url: "https://lab:8443/")
        let other = HTTPTarget(scheme: .https, host: "other", port: 8443)
        do {
            try await session.fetchGRPCSchema(from: other)
            Issue.record("expected out of scope")
        } catch let error as RPCServiceError { #expect(error.outOfScope) }
        do {
            _ = try await session.sendRPC(say("x"), to: other)
            Issue.record("expected out of scope")
        } catch let error as RPCServiceError { #expect(error.outOfScope) }
        #expect(await session.repeater.allTabs.isEmpty)  // nothing was opened or sent
        try await session.close()
    }
}
