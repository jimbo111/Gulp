import Testing

@testable import GulpCore

// F01 PRX-030/PRX-031: WebSocket framing (RFC 6455 examples).

@Suite("GulpCore — WebSocket framing (PRX-030, PRX-031)")
struct WebSocketTests {
    @Test("RFC 6455 §1.3: the accept value for the example key")
    func acceptValue() {
        let accept = WebSocketWire.accept(forKey: "dGhlIHNhbXBsZSBub25jZQ==")
        #expect(accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        let digest = SHA1.digest(Array("abc".utf8))
        let hex = digest.map { ($0 < 16 ? "0" : "") + String($0, radix: 16) }.joined()
        #expect(hex == "a9993e364706816aba3e25717850c26c9cd0d89d")
    }

    @Test("RFC 6455 §5.7: unmasked and masked 'Hello', split and joined input")
    func parsing() {
        let unmasked: [UInt8] = [0x81, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F]
        let masked: [UInt8] = [0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58]
        var parser = WSFrameParser()
        #expect(parser.feed(Array(masked[0..<4])).isEmpty)  // incomplete
        let frames = parser.feed(Array(masked[4...]) + unmasked)
        #expect(frames.count == 2)
        #expect(frames.allSatisfy { $0.payload == Array("Hello".utf8) && $0.fin && $0.opcode == 1 })
        #expect(frames[0].maskKey == [0x37, 0xFA, 0x21, 0x3D])
        #expect(frames[1].maskKey == nil)
        #expect(frames[0].wireLength == 11)
    }

    @Test("Fragmented message with a ping in the middle; 16-bit and 64-bit lengths")
    func assembly() {
        let first: [UInt8] = [0x01, 0x03, 0x48, 0x65, 0x6C]  // text, not FIN: "Hel"
        let ping: [UInt8] = [0x89, 0x00]
        let last: [UInt8] = [0x80, 0x02, 0x6C, 0x6F]  // continuation, FIN: "lo"
        var parser = WSFrameParser()
        var assembler = WSMessageAssembler()
        let messages = parser.feed(first + ping + last).compactMap { assembler.add($0) }
        #expect(messages.map(\.opcode) == [9, 1])
        #expect(messages[1].payload == Array("Hello".utf8))
        #expect(messages[1].frames.map(\.length) == [3, 2])

        let medium = [UInt8](repeating: 0x61, count: 300)
        let large = [UInt8](repeating: 0x62, count: 70_000)
        let encoded =
            WebSocketWire.frame(opcode: .binary, payload: medium)
            + WebSocketWire.frame(opcode: .binary, payload: large, mask: [1, 2, 3, 4])
        let decoded = parser.feed(encoded)
        #expect(decoded.map(\.payload.count) == [300, 70_000])
        #expect(decoded[1].payload == large)
    }

    @Test("PRX-031: continuation frames can't grow a message past the cap; control frames still pass")
    func test_PRX031_assembledMessageCap() {
        var assembler = WSMessageAssembler(maxMessage: 10)
        let piece = [UInt8](repeating: 0x61, count: 4)
        var frames = [WSFrame(fin: false, rsv: 0, opcode: 1, maskKey: nil, payload: piece, wireLength: 6)]
        frames += (0..<5).map { _ in
            WSFrame(fin: false, rsv: 0, opcode: 0, maskKey: nil, payload: piece, wireLength: 6)
        }
        #expect(frames.compactMap { assembler.add($0) }.isEmpty)
        #expect(assembler.failed)
        let ping = WSFrame(fin: true, rsv: 0, opcode: 9, maskKey: nil, payload: [], wireLength: 2)
        #expect(assembler.add(ping)?.opcode == 9)
        let text = WSFrame(fin: true, rsv: 0, opcode: 1, maskKey: nil, payload: piece, wireLength: 6)
        #expect(assembler.add(text) == nil)
    }
}
