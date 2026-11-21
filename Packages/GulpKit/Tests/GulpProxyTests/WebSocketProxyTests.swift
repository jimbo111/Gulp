import Foundation
import GulpCore
import GulpHTTP
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import Testing

@testable import GulpProxy

// F01 PRX-030/PRX-031: WebSocket upgrades through the proxy are relayed byte for byte and recorded
// as messages; a declined upgrade leaves the connection speaking HTTP.

/// An origin with `/chat` (WebSocket echo, greeting sent together with the 101) and, for any other
/// path, `403` to an upgrade.
final class WSEchoOrigin: Sendable {
    let channel: any Channel

    private init(channel: any Channel) {
        self.channel = channel
    }

    var port: Int { channel.localAddress?.port ?? 0 }

    static func start() async throws -> WSEchoOrigin {
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(WSEchoHandler())
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return WSEchoOrigin(channel: channel)
    }

    func stop() async { try? await channel.close().get() }
}

final class WSEchoHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private var received: [UInt8] = []
    private var parser: WSFrameParser?

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let bytes = Array(unwrapInboundIn(data).readableBytesView)
        if parser != nil {
            echo(bytes, context: context)
            return
        }
        received += bytes
        while true {
            let (end, terminator) = HTTP1.headerBlockEnd(received)
            guard terminator != 0 else { return }
            let request = RawRequest(Bytes(Array(received[..<end])))
            received.removeFirst(end)
            let path = request.bytes[request.parsed.target].string()
            guard path == "/chat", let key = request.headerValue("sec-websocket-key")?.string() else {
                let reply = "HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno"
                context.writeAndFlush(NIOAny(context.channel.allocator.buffer(string: reply)), promise: nil)
                continue
            }
            parser = WSFrameParser()
            let head =
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                + "Sec-WebSocket-Accept: \(WebSocketWire.accept(forKey: key))\r\n\r\n"
            let greeting = WebSocketWire.frame(opcode: .text, payload: Array("welcome".utf8))
            let out = context.channel.allocator.buffer(bytes: Array(head.utf8) + greeting)
            context.writeAndFlush(NIOAny(out), promise: nil)
            let rest = received
            received = []
            if !rest.isEmpty { echo(rest, context: context) }
            return
        }
    }

    private func echo(_ bytes: [UInt8], context: ChannelHandlerContext) {
        guard let frames = parser?.feed(bytes) else { return }
        for frame in frames {
            let reply: [UInt8]
            if frame.opcode == WSOpcode.close.rawValue {
                reply = WebSocketWire.frame(opcode: .close, payload: frame.payload)
                let channel = context.channel
                channel.writeAndFlush(channel.allocator.buffer(bytes: reply)).whenComplete { _ in
                    channel.close(promise: nil)
                }
                return
            } else {
                reply = WebSocketWire.frame(opcode: .text, payload: Array("echo: ".utf8) + frame.payload)
            }
            context.writeAndFlush(NIOAny(context.channel.allocator.buffer(bytes: reply)), promise: nil)
        }
    }
}

/// Records what the proxy reports.
actor WSRecorded: WebSocketRecorder {
    var opened: [(upgrade: ExchangeID?, url: String)] = []
    var messages: [(WSDirection, WSMessage)] = []
    var edits: [(original: [UInt8]?, dropped: Bool)] = []
    var closed: [Int?] = []

    func webSocketOpened(upgradeExchangeID: ExchangeID?, url: String) -> Int64? {
        opened.append((upgradeExchangeID, url))
        return Int64(opened.count)
    }

    func webSocketMessage(
        _ connection: Int64, direction: WSDirection, message: WSMessage, original: [UInt8]?, dropped: Bool
    ) {
        messages.append((direction, message))
        edits.append((original, dropped))
    }

    func webSocketClosed(_ connection: Int64, code: Int?) {
        closed.append(code)
    }
}

/// Collects a raw client connection's bytes.
final class ByteSink: ChannelInboundHandler, Sendable {
    typealias InboundIn = ByteBuffer
    let bytes = NIOLockedValueBox<[UInt8]>([])

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let chunk = Array(unwrapInboundIn(data).readableBytesView)
        bytes.withLockedValue { $0 += chunk }
    }

    var text: String { String(decoding: bytes.withLockedValue { $0 }, as: UTF8.self) }

    func wait(for needle: String) async throws {
        for _ in 0..<300 where !text.contains(needle) { try await Task.sleep(for: .milliseconds(10)) }
    }
}

@Suite("GulpProxy — WebSockets through the proxy (PRX-030, PRX-031)", .serialized)
struct WebSocketProxyTests {
    func connect(to port: Int, sink: ByteSink) async throws -> any Channel {
        try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(sink) }
            }
            .connect(host: "127.0.0.1", port: port).get()
    }

    @Test("PRX-030/031: frames relay both ways (the greeting rides with the 101) and are recorded")
    func test_PRX030_relayAndRecord() async throws {
        let origin = try await WSEchoOrigin.start()
        let recorded = Recorded()
        let sockets = WSRecorded()
        let proxy = ProxyServer(engine: NIOHTTPEngine(recorder: recorded), webSockets: sockets)
        let port = try await proxy.start(ProxyListenerConfig(port: 0))
        let sink = ByteSink()
        let client = try await connect(to: port, sink: sink)
        let mask: [UInt8] = [1, 2, 3, 4]
        let upgrade =
            "GET http://127.0.0.1:\(origin.port)/chat HTTP/1.1\r\nHost: 127.0.0.1:\(origin.port)\r\n"
            + "Upgrade: websocket\r\nConnection: Upgrade\r\nProxy-Connection: keep-alive\r\n"
            + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        // The first frame goes out right behind the upgrade request, before the 101 is back.
        let hello = WebSocketWire.frame(opcode: .text, payload: Array("hi".utf8), mask: mask)
        try await client.writeAndFlush(client.allocator.buffer(bytes: Array(upgrade.utf8) + hello))
        try await sink.wait(for: "echo: hi")
        #expect(sink.text.hasPrefix("HTTP/1.1 101 Switching Protocols\r\n"))
        #expect(sink.text.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="))
        #expect(sink.text.contains("welcome"))

        let close = WebSocketWire.frame(opcode: .close, payload: [0x03, 0xE8], mask: mask)
        try await client.writeAndFlush(client.allocator.buffer(bytes: close))
        try await client.closeFuture.get()  // the origin closes; the proxy closes the client

        for _ in 0..<200 where await sockets.closed.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        let opened = await sockets.opened
        #expect(opened.count == 1)
        #expect(opened.first?.url == "ws://127.0.0.1:\(origin.port)/chat")
        #expect(opened.first?.upgrade == 1)
        let messages = await sockets.messages
        let summary = messages.map { "\($0.0 == .toServer ? ">" : "<")\($0.1.opcode)" }
        #expect(summary == [">1", "<1", "<1", ">8", "<8"] || summary == ["<1", ">1", "<1", ">8", "<8"])
        let texts = messages.filter { $0.1.opcode == 1 }.map { String(decoding: $0.1.payload, as: UTF8.self) }
        #expect(Set(texts) == ["hi", "welcome", "echo: hi"])
        #expect(await sockets.closed == [1000])
        let exchanges = await recorded.exchanges
        #expect(exchanges.first?.response?.parsed.statusCode == 101)
        // The upgrade went upstream in origin-form with Upgrade kept and Proxy-Connection dropped.
        let sent = exchanges.first?.request.bytes.string() ?? ""
        #expect(sent.hasPrefix("GET /chat HTTP/1.1\r\n"))
        #expect(sent.contains("Upgrade: websocket\r\n") && !sent.contains("Proxy-Connection"))
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-030: a declined upgrade is answered as HTTP and the connection keeps working")
    func test_PRX030_declined() async throws {
        let origin = try await WSEchoOrigin.start()
        let proxy = ProxyServer(engine: NIOHTTPEngine(recorder: Recorded()), webSockets: WSRecorded())
        let port = try await proxy.start(ProxyListenerConfig(port: 0))
        let sink = ByteSink()
        let client = try await connect(to: port, sink: sink)
        let upgrade =
            "GET http://127.0.0.1:\(origin.port)/denied HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
            + "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        try await client.writeAndFlush(client.allocator.buffer(string: upgrade))
        try await sink.wait(for: "\r\n\r\nno")
        #expect(sink.text.hasPrefix("HTTP/1.1 403 Forbidden\r\n"))
        // Still HTTP: a plain request on the same connection goes through.
        let plain = "GET http://127.0.0.1:\(origin.port)/other HTTP/1.1\r\nHost: x\r\n\r\n"
        try await client.writeAndFlush(client.allocator.buffer(string: plain))
        for _ in 0..<300 where sink.text.components(separatedBy: "403 Forbidden").count < 3 {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(sink.text.components(separatedBy: "403 Forbidden").count == 3)
        try? await client.close()
        await proxy.stopAll()
        await origin.stop()
    }

    /// Open a WebSocket to `origin` through `proxy` (the upgrade only).
    func open(_ origin: WSEchoOrigin, via port: Int, sink: ByteSink) async throws -> any Channel {
        let client = try await connect(to: port, sink: sink)
        let upgrade =
            "GET http://127.0.0.1:\(origin.port)/chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
            + "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        try await client.writeAndFlush(client.allocator.buffer(string: upgrade))
        try await sink.wait(for: "\r\n\r\n")
        return client
    }

    func send(_ text: String, on client: any Channel) async throws {
        let frame = WebSocketWire.frame(opcode: .text, payload: Array(text.utf8), mask: [9, 8, 7, 6])
        try await client.writeAndFlush(client.allocator.buffer(bytes: frame))
    }

    @Test("PRX-020/031: a WebSocket Match & Replace rule rewrites messages; the original is recorded")
    func test_PRX020_webSocketRule() async throws {
        let origin = try await WSEchoOrigin.start()
        let sockets = WSRecorded()
        let rule = MatchReplaceRule(
            kind: .webSocketToServer, match: "token=\\w+", replace: "token=X", isRegex: true)
        let proxy = ProxyServer(
            engine: NIOHTTPEngine(recorder: Recorded()), matchReplace: MatchReplaceHook(rules: [rule]),
            webSockets: sockets)
        let port = try await proxy.start(ProxyListenerConfig(port: 0))
        let sink = ByteSink()
        let client = try await open(origin, via: port, sink: sink)
        try await send("token=abc&x=1", on: client)
        try await sink.wait(for: "echo: token=X&x=1")
        #expect(sink.text.contains("echo: token=X&x=1"))
        try await send("untouched", on: client)
        try await sink.wait(for: "echo: untouched")
        try? await client.close()
        for _ in 0..<200 where await sockets.closed.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        let messages = await sockets.messages
        let edits = await sockets.edits
        let sent = messages.indices.filter { messages[$0].0 == .toServer }
        #expect(sent.count == 2)
        #expect(sent.first.map { messages[$0].1.payload } == Array("token=X&x=1".utf8))
        #expect(sent.first.map { edits[$0].original } == Array("token=abc&x=1".utf8))
        #expect(sent.last.map { edits[$0].original == nil } == true)
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-033: held WebSocket messages are edited or dropped; a dropped one never arrives")
    func test_PRX033_interceptWebSocket() async throws {
        let origin = try await WSEchoOrigin.start()
        let sockets = WSRecorded()
        let queue = InterceptQueue()
        await queue.setInterceptingWebSockets(true)
        let proxy = ProxyServer(
            engine: NIOHTTPEngine(recorder: Recorded()), intercept: queue, webSockets: sockets)
        let port = try await proxy.start(ProxyListenerConfig(port: 0))
        let sink = ByteSink()
        let client = try await open(origin, via: port, sink: sink)
        // Decide held items as they show up: server messages go on unchanged, ours are edited/dropped.
        let decider = Task {
            for _ in 0..<500 {
                for item in await queue.items {
                    let text = String(decoding: item.webSocketPayload ?? [], as: UTF8.self)
                    switch (item.kind, text) {
                    case (.webSocket(.toServer), "secret"):
                        await queue.decide(item.id, .forward(Bytes("changed")))
                    case (.webSocket(.toServer), "drop me"): await queue.decide(item.id, .drop)
                    default: await queue.decide(item.id, .forward(nil))
                    }
                }
                try? await Task.sleep(for: .milliseconds(10))
            }
        }
        try await sink.wait(for: "welcome")
        #expect(sink.text.contains("welcome"))
        try await send("drop me", on: client)
        try await send("secret", on: client)
        try await sink.wait(for: "echo: changed")
        #expect(sink.text.contains("echo: changed"))
        #expect(!sink.text.contains("drop me") && !sink.text.contains("secret"))
        decider.cancel()
        try? await client.close()
        for _ in 0..<200 where await sockets.closed.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        let messages = await sockets.messages
        let edits = await sockets.edits
        let toServer = messages.indices.filter { messages[$0].0 == .toServer }
        #expect(toServer.map { edits[$0].dropped } == [true, false])
        #expect(toServer.last.map { edits[$0].original } == Array("secret".utf8))
        #expect(toServer.last.map { messages[$0].1.payload } == Array("changed".utf8))
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-033: a message held when the client disconnects is dropped and the relay ends")
    func test_PRX033_clientGoneWhileHeld() async throws {
        let origin = try await WSEchoOrigin.start()
        let sockets = WSRecorded()
        let queue = InterceptQueue()
        await queue.setInterceptingWebSockets(true)
        let proxy = ProxyServer(
            engine: NIOHTTPEngine(recorder: Recorded()), intercept: queue, webSockets: sockets)
        let port = try await proxy.start(ProxyListenerConfig(port: 0))
        let sink = ByteSink()
        let client = try await open(origin, via: port, sink: sink)
        try await send("held", on: client)
        var waited = 0
        while await !queue.items.contains(where: { $0.kind == .webSocket(.toServer) }), waited < 300 {
            try await Task.sleep(for: .milliseconds(10))
            waited += 1
        }
        #expect(await queue.items.contains { $0.kind == .webSocket(.toServer) })
        try await client.close()
        for _ in 0..<300 where await sockets.closed.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        #expect(await sockets.closed.count == 1)  // the relay finished (and closed the upstream)
        #expect(await !queue.items.contains { $0.kind == .webSocket(.toServer) })
        await queue.decideAll(.forward(nil))
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("PRX-020/034: request Match & Replace applies to the upgrade (the compression preset works)")
    func test_PRX034_upgradeMatchReplace() async throws {
        let origin = try await WSEchoOrigin.start()
        let recorded = Recorded()
        var preset = try #require(
            MatchReplaceRule.presets.first { $0.match.contains("Sec-WebSocket-Extensions") })
        preset.enabled = true
        let proxy = ProxyServer(
            engine: NIOHTTPEngine(recorder: recorded), matchReplace: MatchReplaceHook(rules: [preset]),
            webSockets: WSRecorded())
        let port = try await proxy.start(ProxyListenerConfig(port: 0))
        let sink = ByteSink()
        let client = try await connect(to: port, sink: sink)
        let upgrade =
            "GET http://127.0.0.1:\(origin.port)/chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
            + "Connection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\n"
            + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        try await client.writeAndFlush(client.allocator.buffer(string: upgrade))
        try await sink.wait(for: "welcome")
        let exchange = await recorded.exchanges.first
        #expect(exchange?.response?.parsed.statusCode == 101)
        #expect(exchange?.request.bytes.string().contains("Sec-WebSocket-Extensions") == false)
        #expect(exchange?.edited?.originalRequest?.bytes.string().contains("permessage-deflate") == true)
        try? await client.close()
        await proxy.stopAll()
        await origin.stop()
    }

    @Test("ws URLs: origin-form, absolute-form and non-default ports")
    func webSocketURLs() {
        func request(_ target: String) -> RawRequest {
            RawRequest(Bytes(Array("GET \(target) HTTP/1.1\r\nHost: h\r\n\r\n".utf8)))
        }
        let plain = HTTPTarget(scheme: .http, host: "h", port: 80)
        let tls = HTTPTarget(scheme: .https, host: "h", port: 8443)
        #expect(ProxyWebSocket.webSocketURL(request("/a?b"), target: plain) == "ws://h/a?b")
        #expect(ProxyWebSocket.webSocketURL(request("/s"), target: tls) == "wss://h:8443/s")
        #expect(ProxyWebSocket.webSocketURL(request("http://h:81/x"), target: plain) == "ws://h:81/x")
    }
}
