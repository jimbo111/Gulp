import Testing

@testable import GulpCodec

@Suite("WebSocket sub-protocol decoding (F01 §2.4, WSX-006)")
struct WSSubprotocolTests {
    private func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }

    @Test("socket.io: the numeric prefix splits from the JSON payload, round-trips exactly")
    func test_WSX006_socketIO() {
        let wire = #"42["chat message","hi there"]"#
        let decoded = WSSubprotocolCodec.decode(bytes(wire))
        #expect(decoded.subprotocol == .socketIO)
        #expect(decoded.envelopePrefix == "42")
        #expect(decoded.payload == #"["chat message","hi there"]"#)
        #expect(WSSubprotocolCodec.encode(decoded) == bytes(wire))
    }

    @Test("socket.io with a namespace and ack id")
    func test_WSX006_socketIONamespace() {
        let wire = #"42/chat,7["event",{"a":1}]"#
        let decoded = WSSubprotocolCodec.decode(bytes(wire))
        #expect(decoded.subprotocol == .socketIO)
        #expect(decoded.envelopePrefix == "42/chat,7")
        #expect(WSSubprotocolCodec.encode(decoded) == bytes(wire))
    }

    @Test("graphql-ws is detected by its type field")
    func test_WSX006_graphqlWS() {
        let wire = #"{"id":"1","type":"subscribe","payload":{"query":"{ me }"}}"#
        let decoded = WSSubprotocolCodec.decode(bytes(wire))
        #expect(decoded.subprotocol == .graphqlWS)
        #expect(decoded.envelopePrefix.isEmpty && decoded.envelopeSuffix.isEmpty)
        #expect(WSSubprotocolCodec.encode(decoded) == bytes(wire))
    }

    @Test("SignalR: the 0x1e separator is the envelope suffix, round-trips exactly")
    func test_WSX006_signalR() {
        let wire = "{\"type\":1,\"target\":\"Send\",\"arguments\":[\"hi\"]}\u{1e}"
        let decoded = WSSubprotocolCodec.decode(bytes(wire))
        #expect(decoded.subprotocol == .signalR)
        #expect(decoded.envelopeSuffix == "\u{1e}")
        #expect(!decoded.payload.hasSuffix("\u{1e}"))
        #expect(WSSubprotocolCodec.encode(decoded) == bytes(wire))
    }

    @Test("a STOMP frame is recognised by its command and header separator")
    func test_WSX006_stomp() {
        let wire = "SEND\ndestination:/queue/a\n\nhello\u{00}"
        let decoded = WSSubprotocolCodec.decode(bytes(wire))
        #expect(decoded.subprotocol == .stomp)
        #expect(WSSubprotocolCodec.encode(decoded) == bytes(wire))
    }

    @Test("bare JSON and plain text are distinguished")
    func test_WSX006_jsonAndRaw() {
        #expect(WSSubprotocolCodec.detect(bytes(#"{"a":1}"#)) == .json)
        #expect(WSSubprotocolCodec.detect(bytes("hello from VulnLab")) == .raw)
    }

    @Test("non-UTF-8 bytes fall back to raw hex and round-trip is not attempted as text")
    func test_WSX006_binaryRaw() {
        let decoded = WSSubprotocolCodec.decode([0xff, 0xfe, 0x00])
        #expect(decoded.subprotocol == .raw)
        #expect(decoded.payload == "fffe00")
    }

    @Test("WSX-007: auto insertion points mark JSON values, not keys or the envelope")
    func test_WSX007_autoInsertionPoints() {
        let decoded = WSSubprotocolCodec.decode(bytes(#"{"user":"bob","age":30}"#))
        #expect(WSSubprotocolCodec.autoInsertionPoints(decoded) == #"{"user":§"bob"§,"age":§30§}"#)
    }

    @Test("WSX-007: the socket.io envelope is preserved and only payload values are marked")
    func test_WSX007_socketIOInsertionPoints() {
        let decoded = WSSubprotocolCodec.decode(bytes(#"42["event",{"id":"x"}]"#))
        #expect(WSSubprotocolCodec.autoInsertionPoints(decoded) == #"42[§"event"§,{"id":§"x"§}]"#)
    }

    @Test("WSX-007: a non-JSON payload marks the whole payload once")
    func test_WSX007_rawInsertionPoints() {
        let decoded = WSSubprotocolCodec.decode(bytes("ping"))
        #expect(WSSubprotocolCodec.autoInsertionPoints(decoded) == "§ping§")
    }
}
