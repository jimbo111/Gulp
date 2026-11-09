import GulpCore
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import Testing

@testable import GulpHTTP

// F03 HTTP-011: pipelining — N requests written back to back on one connection, N responses read in
// order (the framing of each decides where the next begins).

/// Answers every complete request on a connection, in order: `/chunked` gets a chunked reply, HEAD
/// gets headers only, `/close` makes the server close after `closeAfter` replies.
final class PipelineServer: Sendable {
    let channel: any Channel
    let connections = NIOLockedValueBox(0)

    private init(channel: any Channel) {
        self.channel = channel
    }

    var port: Int { channel.localAddress?.port ?? 0 }

    static func start(closeAfter: Int = .max) async throws -> PipelineServer {
        let box = NIOLockedValueBox<PipelineServer?>(nil)
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                box.withLockedValue { $0?.connections.withLockedValue { $0 += 1 } }
                return channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(PipelineHandler(closeAfter: closeAfter))
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        let server = PipelineServer(channel: channel)
        box.withLockedValue { $0 = server }
        return server
    }

    func stop() async { try? await channel.close().get() }
}

final class PipelineHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private var buffer: [UInt8] = []
    private var replies = 0
    let closeAfter: Int

    init(closeAfter: Int) {
        self.closeAfter = closeAfter
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        buffer += unwrapInboundIn(data).readableBytesView
        var out = ""
        while true {
            let (end, terminator) = HTTP1.headerBlockEnd(buffer)
            guard terminator != 0 else { break }
            let head = String(decoding: buffer[..<end], as: UTF8.self)
            buffer.removeFirst(end)
            let line = head.split(separator: " ")
            let (method, path) = (String(line[0]), String(line[1]))
            switch (method, path) {
            case ("HEAD", _): out += "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"
            case (_, "/chunked"):
                out += "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                out += "4\r\nchun\r\n2\r\nk!\r\n0\r\n\r\n"
            default: out += "HTTP/1.1 200 OK\r\nContent-Length: \(path.utf8.count)\r\n\r\n\(path)"
            }
            replies += 1
            if replies == closeAfter {
                context.writeAndFlush(NIOAny(context.channel.allocator.buffer(string: out)))
                    .whenComplete { [channel = context.channel] _ in channel.close(promise: nil) }
                return
            }
        }
        if !out.isEmpty {
            context.writeAndFlush(NIOAny(context.channel.allocator.buffer(string: out)), promise: nil)
        }
    }
}

@Suite("GulpHTTP — pipelining (HTTP-011)", .serialized)
struct PipelineTests {
    func options() -> SendOptions {
        var options = SendOptions(recordAs: .fuzzer)
        options.timeouts.total = .seconds(10)
        return options
    }

    func get(_ path: String, method: String = "GET") -> RawRequest {
        RawRequest(Bytes("\(method) \(path) HTTP/1.1\r\nHost: x\r\n\r\n"))
    }

    @Test("HTTP-011: one connection, responses in order whatever their framing")
    func test_HTTP011_inOrder() async throws {
        let server = try await PipelineServer.start()
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        let requests = [get("/a"), get("/chunked"), get("/x", method: "HEAD"), get("/bbbb"), get("/c")]
        let results = await engine.sendPipelined(requests, to: target, options: options())
        #expect(server.connections.withLockedValue { $0 } == 1)
        #expect(results.allSatisfy { $0.error == nil })
        let bodies = results.map { result -> String in
            let parts = (result.exchange.response?.bytes.string() ?? "").components(separatedBy: "\r\n\r\n")
            return parts.dropFirst().joined(separator: "\r\n\r\n")  // everything after the header block
        }
        #expect(bodies == ["/a", "4\r\nchun\r\n2\r\nk!\r\n0\r\n\r\n", "", "/bbbb", "/c"])
        #expect(results.map { $0.exchange.request } == requests)
        #expect(Set(results.map(\.exchange.connectionID)).count == 1)
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTP-011: when the server closes early, the unanswered requests fail")
    func test_HTTP011_earlyClose() async throws {
        let server = try await PipelineServer.start(closeAfter: 2)
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        let requests = (1...4).map { get("/\($0)") }
        let results = await engine.sendPipelined(requests, to: target, options: options())
        #expect(results.count == 4)
        #expect(results.prefix(2).allSatisfy { $0.error == nil })
        #expect(results.suffix(2).allSatisfy { $0.error == .connectionReset })
        await engine.shutdown()
        await server.stop()
    }
}
