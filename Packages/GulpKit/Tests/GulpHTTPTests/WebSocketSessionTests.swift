import GulpCore
import Testing

@testable import GulpHTTP

// F06 REP-012: a message-level WebSocket session over the engine (the WebSocket Repeater's engine).

@Suite("GulpHTTP — WebSocket sessions (REP-012)", .serialized)
struct WebSocketSessionTests {
    /// A scripted server: the upgrade gets a 101 and a greeting; each client frame comes back
    /// (unmasked) as `echo: <payload>`; a close is answered with a close.
    static func echoServer() async throws -> TestServer {
        try await TestServer.start { received, _ in
            let text = String(decoding: received, as: UTF8.self)
            if text.hasPrefix("GET ") {
                guard headersComplete(received) else { return nil }
                let accept = WebSocketWire.accept(forKey: "dGhlIHNhbXBsZSBub25jZQ==")
                let head =
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Accept: \(accept)\r\n\r\n"
                let greeting = WebSocketWire.frame(opcode: .text, payload: Array("hi".utf8))
                return Self.reply(Array(head.utf8) + greeting)
            }
            var parser = WSFrameParser()
            let frames = parser.feed(received)
            guard !frames.isEmpty else { return nil }
            var out: [UInt8] = []
            for frame in frames {
                if frame.opcode == WSOpcode.close.rawValue {
                    out += WebSocketWire.frame(opcode: .close, payload: frame.payload)
                } else {
                    out += WebSocketWire.frame(opcode: .text, payload: Array("echo: ".utf8) + frame.payload)
                }
            }
            return Self.reply(out)
        }
    }

    /// A reply of exact bytes (frames are binary; a String would mangle them).
    static func reply(_ bytes: [UInt8]) -> ServerReply {
        var reply = ServerReply("")
        reply.bytes = bytes
        return reply
    }

    @Test("REP-012: open, receive the greeting, send and get the echo, close")
    func test_REP012_session() async throws {
        let server = try await Self.echoServer()
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        var options = SendOptions(recordAs: .repeater)
        options.timeouts.total = .seconds(10)
        let upgrade = RawRequest(
            Bytes(
                "GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"))
        let session = try await engine.openWebSocket(upgrade, to: target, options: options)
        #expect(session.upgrade.response?.parsed.statusCode == 101)
        let timeout = Task {
            try await Task.sleep(for: .seconds(10))
            await session.close()  // a hung test ends the stream instead of waiting forever
        }
        defer { timeout.cancel() }
        var iterator = session.messages.makeAsyncIterator()
        let greeting = await iterator.next()
        #expect(greeting.map { String(decoding: $0.payload, as: UTF8.self) } == "hi")
        let written = try await session.send(.text, Array("ping?".utf8))
        #expect(written[1] & 0x80 != 0)  // client frames are masked
        let echo = await iterator.next()
        #expect(echo.map { String(decoding: $0.payload, as: UTF8.self) } == "echo: ping?")
        await session.close()
        #expect(!session.isOpen)
        await engine.shutdown()
        await server.stop()
    }

    @Test("REP-012: a refused upgrade throws with the status")
    func test_REP012_refused() async throws {
        let server = try await TestServer.start { received, _ in
            headersComplete(received) ? ok("no ws here") : nil
        }
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        let upgrade = RawRequest(
            Bytes("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
        await #expect(throws: GulpError.self) {
            _ = try await engine.openWebSocket(upgrade, to: target, options: SendOptions(recordAs: .repeater))
        }
        await engine.shutdown()
        await server.stop()
    }
}
