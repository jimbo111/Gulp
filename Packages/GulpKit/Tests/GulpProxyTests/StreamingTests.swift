import GulpCore
import GulpHTTP
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import Testing

@testable import GulpProxy

// F01 PRX-050 / F05 HIS-007: responses stream through the proxy as they arrive and are recorded as
// pending, then completed in place.

/// An origin that answers with one chunk at once and the rest after `delay`.
final class SlowChunkOrigin: Sendable {
    let channel: any Channel

    private init(channel: any Channel) {
        self.channel = channel
    }

    var port: Int { channel.localAddress?.port ?? 0 }

    static func start(delay: TimeAmount) async throws -> SlowChunkOrigin {
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(SlowChunkHandler(delay: delay))
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return SlowChunkOrigin(channel: channel)
    }

    func stop() async { try? await channel.close().get() }
}

final class SlowChunkHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    let delay: TimeAmount
    private var received: [UInt8] = []

    init(delay: TimeAmount) {
        self.delay = delay
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        received += unwrapInboundIn(data).readableBytesView
        guard HTTP1.headerBlockEnd(received).terminator != 0 else { return }
        received = []
        let channel = context.channel
        let first =
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n"
            + "\r\n7\r\ndata: 1\r\n"
        channel.writeAndFlush(channel.allocator.buffer(string: first), promise: nil)
        context.eventLoop.scheduleTask(in: delay) {
            let rest = channel.allocator.buffer(string: "7\r\ndata: 2\r\n0\r\n\r\n")
            channel.writeAndFlush(rest, promise: nil)
        }
    }
}

/// A raw client that records when bytes arrive.
final class ArrivalRecorder: ChannelInboundHandler, Sendable {
    typealias InboundIn = ByteBuffer
    let arrivals = NIOLockedValueBox<[(ContinuousClock.Instant, String)]>([])

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let text = String(decoding: unwrapInboundIn(data).readableBytesView, as: UTF8.self)
        arrivals.withLockedValue { $0.append((.now, text)) }
    }

    var text: String { arrivals.withLockedValue { $0.map(\.1).joined() } }
}

@Suite("GulpProxy — streaming responses (PRX-050, HIS-007)", .serialized)
struct StreamingTests {
    @Test("PRX-050: the first chunk reaches the client before the origin finishes; HIS-007 pending")
    func test_PRX050_streaming() async throws {
        let origin = try await SlowChunkOrigin.start(delay: .milliseconds(800))
        let recorded = Recorded()
        let (proxy, proxyTarget) = try await startProxy(recorder: recorded)
        let recorder = ArrivalRecorder()
        let client = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(recorder)
                }
            }
            .connect(host: "127.0.0.1", port: proxyTarget.port).get()
        let request = "GET http://127.0.0.1:\(origin.port)/sse HTTP/1.1\r\nHost: x\r\n\r\n"
        let sentAt = ContinuousClock.now
        try await client.writeAndFlush(client.allocator.buffer(string: request))

        // The first event arrives long before the origin's 800 ms pause ends.
        var firstSeen: ContinuousClock.Instant?
        for _ in 0..<100 where firstSeen == nil {
            if recorder.text.contains("data: 1") { firstSeen = .now }
            try await Task.sleep(for: .milliseconds(10))
        }
        let first = try #require(firstSeen)
        #expect(first - sentAt < .milliseconds(600))
        #expect(!recorder.text.contains("data: 2"))
        let pending = await recorded.exchanges
        #expect(pending.count == 1)
        #expect(pending.first?.state == .pending)  // HIS-007: the row exists while streaming

        for _ in 0..<200 where !recorder.text.contains("0\r\n\r\n") {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(recorder.text.hasSuffix("7\r\ndata: 2\r\n0\r\n\r\n"))
        try await Task.sleep(for: .milliseconds(100))
        let done = await recorded.exchanges
        #expect(done.count == 1)
        #expect(done.first?.state == .complete)
        #expect(done.first?.response?.bytes.string().hasSuffix("data: 2\r\n0\r\n\r\n") == true)
        try? await client.close()
        await proxy.stopAll()
        await origin.stop()
    }
}
