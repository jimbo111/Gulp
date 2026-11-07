// gulp-vulnlab — two raw SwiftNIO listeners on 127.0.0.1 only:
//   :8088  the HTTP fixtures (keep-alive, routed by `VulnLab.respond`)
//   :8089  `/echo-raw`: writes back exactly the bytes it received, then closes (close-delimited)
//   :8443  the same fixtures over TLS, with a certificate from a throwaway CA (F02 acceptance #4:
//          "upstream to VulnLab's self-signed :8443")

import GulpCore
import GulpTLS
import NIOCore
import NIOPosix
import NIOSSL

/// The running listeners.
struct VulnLabServer: Sendable {
    let app: any Channel
    let raw: any Channel
    let tls: any Channel

    static func start(appPort: Int, rawPort: Int, tlsPort: Int) async throws -> VulnLabServer {
        let app = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture(withResultOf: {
                    try channel.pipeline.syncOperations.addHandler(AppHandler())
                })
            }
            .bind(host: "127.0.0.1", port: appPort).get()
        let raw = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture(withResultOf: {
                    try channel.pipeline.syncOperations.addHandler(RawEchoHandler())
                })
            }
            .bind(host: "127.0.0.1", port: rawPort).get()
        // Not signed by anything a client trusts: a stand-in for a staging server's certificate.
        let minter = try LeafMinter(authority: CertificateAuthority.generate(keyType: .p256))
        let context = try await minter.serverContext(for: "localhost", alpn: ["http/1.1"])
        let tls = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture(withResultOf: {
                    try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
                    try channel.pipeline.syncOperations.addHandler(AppHandler())
                })
            }
            .bind(host: "127.0.0.1", port: tlsPort).get()
        return VulnLabServer(app: app, raw: raw, tls: tls)
    }

    func waitUntilClosed() async throws {
        try await app.closeFuture.get()
    }
}

/// Reads HTTP/1 requests (header block + Content-Length body) and writes routed replies.
final class AppHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var buffer: [UInt8] = []

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        buffer.append(contentsOf: unwrapInboundIn(data).readableBytesView)
        while let next = Self.nextRequest(buffer) {
            let (request, used) = next
            buffer.removeFirst(used)
            let reply = VulnLab.respond(to: request)
            let close = request.hasHeaderToken("connection", "close")
            write(reply, context: context, close: close)
            if close { return }
        }
    }

    /// The first complete request in `bytes` and how many bytes it used.
    static func nextRequest(_ bytes: [UInt8]) -> (RawRequest, Int)? {
        let (end, terminator) = HTTP1.headerBlockEnd(bytes)
        guard terminator != 0 else { return nil }
        let head = RawRequest(Bytes(Array(bytes[..<end])))
        let declared = head.headerValue("content-length").flatMap { Int($0.string()) } ?? 0
        let total = end + max(0, declared)
        guard bytes.count >= total else { return nil }
        return (RawRequest(Bytes(Array(bytes[..<total]))), total)
    }

    private func write(_ reply: VulnReply, context: ChannelHandlerContext, close: Bool) {
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        let send: @Sendable () -> Void = {
            let context = bound.value
            var out = context.channel.allocator.buffer(capacity: reply.bytes.count)
            out.writeBytes(reply.bytes)
            let written = context.writeAndFlush(NIOAny(out))
            if close { written.whenComplete { _ in bound.value.close(promise: nil) } }
        }
        if reply.delayMilliseconds > 0 {
            context.eventLoop.scheduleTask(in: .milliseconds(Int64(reply.delayMilliseconds))) { send() }
        } else {
            send()
        }
    }
}

/// `/echo-raw`: collects bytes until the client pauses for 150 ms, writes them back verbatim, closes.
/// The pause (not HTTP parsing) ends the request, so even malformed, unterminated input round-trips.
final class RawEchoHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var received: [UInt8] = []
    private var timer: Scheduled<Void>?
    private var context: ChannelHandlerContext?

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        received.append(contentsOf: unwrapInboundIn(data).readableBytesView)
        timer?.cancel()
        let bound = NIOLoopBound(self, eventLoop: context.eventLoop)
        timer = context.eventLoop.scheduleTask(in: .milliseconds(150)) { bound.value.echo() }
    }

    private func echo() {
        guard let context else { return }
        var out = context.channel.allocator.buffer(capacity: received.count)
        out.writeBytes(received)
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.writeAndFlush(wrapOutboundOut(out)).whenComplete { _ in bound.value.close(promise: nil) }
    }
}
