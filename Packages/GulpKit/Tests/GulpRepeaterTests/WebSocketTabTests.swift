import Foundation
import GulpCore
import GulpHTTP
import NIOCore
import NIOPosix
import Testing

@testable import GulpRepeater

// F06 REP-012: a WebSocket tab — connect with the draft as the upgrade, send, log both directions.

/// A WebSocket echo origin: 101 plus a "welcome" text, then `echo: <payload>` for each message.
final class EchoOrigin: Sendable {
    let channel: any Channel
    var port: Int { channel.localAddress?.port ?? 0 }

    private init(channel: any Channel) {
        self.channel = channel
    }

    static func start() async throws -> EchoOrigin {
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(EchoHandler())
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return EchoOrigin(channel: channel)
    }

    func stop() async { try? await channel.close().get() }
}

final class EchoHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private var buffer: [UInt8] = []
    private var parser: WSFrameParser?

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let bytes = Array(unwrapInboundIn(data).readableBytesView)
        var out: [UInt8] = []
        if parser == nil {
            buffer += bytes
            let (end, terminator) = HTTP1.headerBlockEnd(buffer)
            guard terminator != 0 else { return }
            let key =
                RawRequest(Bytes(Array(buffer[..<end]))).headerValue("sec-websocket-key")?.string() ?? ""
            parser = WSFrameParser()
            out += Array(
                ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Accept: \(WebSocketWire.accept(forKey: key))\r\n\r\n").utf8)
            out += WebSocketWire.frame(opcode: .text, payload: Array("welcome".utf8))
        } else {
            for frame in parser?.feed(bytes) ?? [] where frame.opcode == WSOpcode.text.rawValue {
                out += WebSocketWire.frame(opcode: .text, payload: Array("echo: ".utf8) + frame.payload)
            }
        }
        if !out.isEmpty {
            context.writeAndFlush(NIOAny(context.channel.allocator.buffer(bytes: out)), promise: nil)
        }
    }
}

@Suite("GulpRepeater — WebSocket tabs (REP-012)", .serialized)
struct WebSocketTabTests {
    @Test("REP-012: connect, see the greeting, send and see the echo; the log keeps both directions")
    func test_REP012_tab() async throws {
        let origin = try await EchoOrigin.start()
        let engine = NIOHTTPEngine()
        let repeater = RepeaterService(engine: engine)
        var options = RepeaterOptions()
        options.isWebSocket = true
        let upgrade = RawRequest(
            Bytes(
                "GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"))
        let tab = await repeater.openTab(
            request: upgrade, target: HTTPTarget(scheme: .http, host: "127.0.0.1", port: origin.port),
            options: options)
        let entries = try await repeater.connectWebSocket(tab.id)
        #expect(await repeater.isWebSocketOpen(tab.id))
        var iterator = entries.makeAsyncIterator()
        #expect(await iterator.next().map { String(decoding: $0.payload, as: UTF8.self) } == "welcome")
        try await repeater.sendWebSocket(tab.id, .text, Array("hello".utf8))
        let sent = await iterator.next()
        #expect(sent?.direction == .toServer && sent?.payload == Array("hello".utf8))
        #expect(await iterator.next().map { String(decoding: $0.payload, as: UTF8.self) } == "echo: hello")
        #expect(await repeater.webSocketLog(tab.id).map(\.direction) == [.toClient, .toServer, .toClient])
        await repeater.disconnectWebSocket(tab.id)
        #expect(!(await repeater.isWebSocketOpen(tab.id)))
        await #expect(throws: GulpError.self) { try await repeater.sendWebSocket(tab.id, .text, [1]) }
        await engine.shutdown()
        await origin.stop()
    }

    @Test("REP-012: options saved by older versions still decode (new fields default)")
    func test_REP012_optionsDecode() throws {
        let old = #"{"version":"http2","updateContentLength":false,"redirects":"onSite","maxRedirects":3}"#
        let decoded = try JSONDecoder().decode(RepeaterOptions.self, from: Data(old.utf8))
        #expect(decoded.version == .http2 && !decoded.updateContentLength && decoded.maxRedirects == 3)
        #expect(!decoded.isWebSocket && decoded.webSocketMessage.isEmpty && decoded.timeoutSeconds == 60)
    }
}
