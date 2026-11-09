// GulpHTTP — connection upgrades (F01 PRX-030, F03): send an `Upgrade: websocket` request on a
// fresh HTTP/1.1 connection and, on `101 Switching Protocols`, keep the connection as a raw byte
// stream. The proxy splices it to its client; tools (and `gulp-cli ws`) speak WebSocket over it.

import GulpCore
import NIOConcurrencyHelpers
import NIOCore

/// Records WebSocket connections and messages (PRX-031); implemented by the project (GulpStore).
public protocol WebSocketRecorder: Sendable {
    /// A connection opened by the upgrade recorded as `upgradeExchangeID`; returns its id.
    func webSocketOpened(upgradeExchangeID: ExchangeID?, url: String) async -> Int64?
    /// One message (control frames included), as forwarded. `original` is the payload before an
    /// edit (Match & Replace or Intercept, PRX-033); `dropped` marks a message that was not sent.
    func webSocketMessage(
        _ connection: Int64, direction: WSDirection, message: WSMessage, original: [UInt8]?, dropped: Bool
    ) async
    /// The connection closed (with the close code if a close frame was seen).
    func webSocketClosed(_ connection: Int64, code: Int?) async
}

/// A connection switched to another protocol.
public struct UpgradedConnection: Sendable {
    /// The channel, carrying raw bytes in both directions (write `ByteBuffer`s to it).
    public let channel: any Channel

    /// Write raw bytes (already-framed WebSocket frames, for instance).
    public func write(_ bytes: [UInt8]) async throws {
        try await channel.writeAndFlush(channel.allocator.buffer(bytes: bytes))
    }

    /// Close the connection.
    public func close() async {
        try? await channel.close()
    }
}

/// Delivers every byte of an upgraded connection to `onRead`, and its end to `onClose`.
final class RawStreamHandler: ChannelInboundHandler, Sendable {
    typealias InboundIn = ByteBuffer
    private let onRead: @Sendable ([UInt8]) -> Void
    private let onClose: @Sendable () -> Void

    init(onRead: @escaping @Sendable ([UInt8]) -> Void, onClose: @escaping @Sendable () -> Void) {
        self.onRead = onRead
        self.onClose = onClose
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        onRead(Array(unwrapInboundIn(data).readableBytesView))
    }

    func channelInactive(context: ChannelHandlerContext) {
        onClose()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        context.close(promise: nil)
    }
}

extension NIOHTTPEngine {
    /// Send an upgrade request (e.g. `Upgrade: websocket`) on a new HTTP/1.1 connection. The exchange
    /// is recorded like any other; on `101` the connection stays open and every later byte goes to
    /// `onRead` (the first frames may already be among them). Any other status closes it.
    public func upgrade(
        _ request: RawRequest, to target: HTTPTarget, options: SendOptions,
        onRead: @escaping @Sendable ([UInt8]) -> Void, onClose: @escaping @Sendable () -> Void
    ) async -> (result: ExchangeResult, connection: UpgradedConnection?) {
        var options = options
        options.httpVersion = .http1_1  // WebSocket over HTTP/2 (RFC 8441) is not offered
        options.connection = .newAndClose
        options.onResponseBytes = nil
        return await upgradeSend(request, to: target, options: options, onRead: onRead, onClose: onClose)
    }
}

/// A live WebSocket session (F06 REP-012): send client frames (masked, as RFC 6455 requires of
/// clients) and read the server's messages, reassembled, in order.
public final class WebSocketSession: Sendable {
    /// The recorded upgrade exchange (its response is the `101`).
    public let upgrade: Exchange
    /// The server's messages (control frames included) until the connection closes.
    public let messages: AsyncStream<WSMessage>
    private let connection: UpgradedConnection

    init(upgrade: Exchange, connection: UpgradedConnection, incoming: AsyncStream<[UInt8]>) {
        self.upgrade = upgrade
        self.connection = connection
        let (messages, output) = AsyncStream.makeStream(of: WSMessage.self)
        self.messages = messages
        Task {
            var parser = WSFrameParser()
            var assembler = WSMessageAssembler()
            for await bytes in incoming {
                for frame in parser.feed(bytes) {
                    if let message = assembler.add(frame) { output.yield(message) }
                }
            }
            output.finish()
        }
    }

    /// Send one message as a single (masked) frame; returns the bytes written.
    @discardableResult
    public func send(_ opcode: WSOpcode, _ payload: [UInt8]) async throws -> [UInt8] {
        let mask = (0..<4).map { _ in UInt8.random(in: 0...255) }
        let frame = WebSocketWire.frame(opcode: opcode, payload: payload, mask: mask)
        try await connection.write(frame)
        return frame
    }

    /// Send a text message.
    public func send(text: String) async throws {
        try await send(.text, Array(text.utf8))
    }

    /// Close: send a close frame with `code` (best effort) and close the connection.
    public func close(code: UInt16 = 1000) async {
        _ = try? await send(.close, [UInt8(code >> 8), UInt8(code & 0xFF)])
        await connection.close()
    }

    /// Whether the connection is still open.
    public var isOpen: Bool { connection.channel.isActive }
}
