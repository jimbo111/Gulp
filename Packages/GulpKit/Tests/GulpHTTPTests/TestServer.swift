import GulpCore
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import NIOSSL

@testable import GulpHTTP

/// A scripted reply from the test server.
struct ServerReply: Sendable {
    var bytes: [UInt8]
    var close: Bool

    init(_ text: String, close: Bool = false) {
        bytes = Array(text.utf8)
        self.close = close
    }
}

/// Decides the reply from the bytes received on a connection since its last reply (nil = wait).
typealias ServerScript = @Sendable (_ received: [UInt8], _ connection: Int) -> ServerReply?

/// True once a request's header block has fully arrived.
func headersComplete(_ bytes: [UInt8]) -> Bool {
    HTTP1.headerBlockEnd(bytes).terminator != 0
}

/// A 200 response with a correct Content-Length.
func ok(_ body: String, headers: String = "") -> ServerReply {
    ServerReply("HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\n\(headers)\r\n\(body)")
}

/// Runs the script for one accepted connection and logs every byte it receives.
final class ScriptHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let script: ServerScript
    private let log: NIOLockedValueBox<[[UInt8]]>
    private let index: Int
    private var pending: [UInt8] = []

    init(script: @escaping ServerScript, log: NIOLockedValueBox<[[UInt8]]>, index: Int) {
        self.script = script
        self.log = log
        self.index = index
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let bytes = Array(unwrapInboundIn(data).readableBytesView)
        pending += bytes
        let index = self.index
        log.withLockedValue { $0[index] += bytes }
        guard let reply = script(pending, index) else { return }
        pending = []
        var out = context.channel.allocator.buffer(capacity: reply.bytes.count)
        out.writeBytes(reply.bytes)
        let written = context.writeAndFlush(wrapOutboundOut(out))
        if reply.close {
            let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
            written.whenComplete { _ in bound.value.close(promise: nil) }
        }
    }
}

/// An in-process TCP server on 127.0.0.1 with a scripted responder.
final class TestServer: Sendable {
    let channel: any Channel
    private let log: NIOLockedValueBox<[[UInt8]]>

    private init(channel: any Channel, log: NIOLockedValueBox<[[UInt8]]>) {
        self.channel = channel
        self.log = log
    }

    /// Bound port.
    var port: Int { channel.localAddress?.port ?? 0 }
    /// A plaintext target for this server.
    var target: HTTPTarget { HTTPTarget(scheme: .http, host: "127.0.0.1", port: port) }
    /// Connections accepted so far.
    var connections: Int { log.withLockedValue { $0.count } }

    /// Every byte received on connection `index`.
    func received(_ index: Int = 0) -> [UInt8] {
        log.withLockedValue { index < $0.count ? $0[index] : [] }
    }

    /// Start a server; with `tls`, connections are TLS (the script sees decrypted bytes).
    static func start(
        tls: NIOSSLContext? = nil, _ script: @escaping ServerScript
    ) async throws -> TestServer {
        let log = NIOLockedValueBox<[[UInt8]]>([])
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let index = log.withLockedValue { list -> Int in
                    list.append([])
                    return list.count - 1
                }
                return channel.eventLoop.makeCompletedFuture(withResultOf: {
                    if let tls {
                        try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tls))
                    }
                    let handler = ScriptHandler(script: script, log: log, index: index)
                    try channel.pipeline.syncOperations.addHandler(handler)
                })
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return TestServer(channel: channel, log: log)
    }

    func stop() async {
        try? await channel.close().get()
    }
}
