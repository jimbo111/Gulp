// GulpHTTP — the per-connection NIO handler that writes raw request bytes and frames the response
// (HTTP-001, HTTP-002, HTTP-005). It never parses into NIOHTTP1 types: framing decisions use
// GulpCore's raw-preserving parser on the exact bytes received.

import GulpCore
import NIOCore

/// What the engine asks a connection to do: write `bytes`, then deliver the response to `promise`.
struct RequestCommand: Sendable {
    let bytes: ByteBuffer
    /// The request was HEAD: the response has no body whatever its framing headers say.
    let isHead: Bool
    /// The request was CONNECT: a 2xx response has no body and the connection becomes a tunnel.
    let isConnect: Bool
    let maxResponseBytes: Int
    let firstByteTimeout: TimeAmount
    let idleTimeout: TimeAmount
    let totalDeadline: NIODeadline
    let promise: EventLoopPromise<WireResponse>
    /// Streaming (PRX-050): every inbound chunk, as it arrives.
    var onBytes: (@Sendable ([UInt8]) -> Void)? = nil
    /// More bytes of the request already in flight (the withheld final bytes of a last-byte-sync
    /// group send, HTTP-034): written without flushing; the caller flushes.
    var continuation = false
    /// One of several requests written back to back (HTTP-011): written without flushing (the
    /// caller flushes once); if a response is still pending, this one queues behind it.
    var pipelined = false
}

/// The bytes and outcome of one request on the wire.
struct WireResponse: Sendable {
    /// The final response's bytes (interim responses excluded), possibly partial on error.
    var bytes: [UInt8]
    /// Interim (1xx) responses that preceded it, each as received.
    var interim: [[UInt8]]
    /// Nil when the response completed per its framing.
    var error: GulpNetworkError?
    var firstByteAt: NIODeadline?
    var lastByteAt: NIODeadline?
    /// The connection may carry another request (keep-alive, no surplus bytes).
    var reusable: Bool
    /// Any response byte arrived (decides whether a stale-connection retry is safe, HTTP-003).
    var receivedAny: Bool
}

/// How the current response's body is delimited, decided once its header block is in.
private struct ResponseHead {
    enum Framing { case none, contentLength(Int), chunked, closeDelimited }
    /// Absolute index (in the connection buffer) just past the header block.
    let blockEnd: Int
    let status: Int
    var framing: Framing
    let keepAlive: Bool

    var isInterim: Bool { status >= 100 && status < 200 && status != 101 }

    init(headerBytes: [UInt8], blockEnd: Int, isHead: Bool, isConnect: Bool) {
        let r = RawResponse(Bytes(headerBytes))
        self.blockEnd = blockEnd
        status = r.parsed.statusCode
        let version = r.bytes[r.parsed.version].string()
        let close = r.hasHeaderToken("connection", "close")
        let keep = r.hasHeaderToken("connection", "keep-alive")
        let tunnel = isConnect && status >= 200 && status < 300
        keepAlive = tunnel || (status != 101 && (version == "HTTP/1.1" ? !close : (keep && !close)))
        // RFC 9112 §6.3: HEAD, 1xx, 204, 304 and a 2xx to CONNECT end at the header block.
        if tunnel || isHead || status == 204 || status == 304 || (status >= 100 && status < 200) {
            framing = .none
        } else if r.parsed.transferEncodingChunked {
            framing = .chunked
        } else if let length = r.parsed.contentLength, length >= 0 {
            framing = .contentLength(length)
        } else {
            framing = .closeDelimited
        }
    }
}

/// One request at a time per connection, or several back to back when pipelined (HTTP-011): the
/// responses are then framed in order, each starting where the previous one ended.
final class HTTP1ClientHandler: ChannelDuplexHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundIn = RequestCommand
    typealias OutboundOut = ByteBuffer

    private struct Pending {
        let promise: EventLoopPromise<WireResponse>
        let isHead: Bool
        let isConnect: Bool
        let maxBytes: Int
        let idleTimeout: TimeAmount
        let onBytes: (@Sendable ([UInt8]) -> Void)?
        var buffer: [UInt8] = []
        var interim: [[UInt8]] = []
        /// Where the current (non-interim) message starts in `buffer`.
        var start = 0
        var head: ResponseHead?
        /// Where the next header-block scan resumes, so a slow header block is scanned once.
        var headerResume = 0
        var chunkResume = 0
        var firstByteAt: NIODeadline?
        var phaseTimer: Scheduled<Void>?
        var totalTimer: Scheduled<Void>?
    }

    private var pending: Pending?
    /// Pipelined requests waiting for their turn, with the timeouts to arm when they get it.
    private var queued: [(pending: Pending, firstByteTimeout: TimeAmount, totalDeadline: NIODeadline)] = []
    private var context: ChannelHandlerContext?
    /// After `101 Switching Protocols` the connection carries another protocol (WebSocket): bytes
    /// pass down the pipeline untouched instead of being parsed as HTTP (PRX-030).
    private var passThrough = false

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        fail(.connectionReset)
        self.context = nil
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        if passThrough {
            // Upgraded: writes are raw `ByteBuffer`s for the other protocol, not request commands.
            context.write(data, promise: promise)
            return
        }
        let command = unwrapOutboundIn(data)
        if command.continuation {
            guard pending != nil else {
                promise?.fail(GulpNetworkError.other("No request in flight to continue"))
                return
            }
            context.write(wrapOutboundOut(command.bytes), promise: promise)
            return
        }
        let request = Pending(
            promise: command.promise, isHead: command.isHead, isConnect: command.isConnect,
            maxBytes: command.maxResponseBytes, idleTimeout: command.idleTimeout, onBytes: command.onBytes)
        if pending != nil {
            guard command.pipelined else {
                let busy = GulpNetworkError.other("A request is already in flight on this connection")
                command.promise.fail(busy)
                promise?.fail(GulpNetworkError.other("Connection busy"))
                return
            }
            queued.append((request, command.firstByteTimeout, command.totalDeadline))
            context.write(wrapOutboundOut(command.bytes), promise: promise)
            return
        }
        start(request, firstByteTimeout: command.firstByteTimeout, totalDeadline: command.totalDeadline)
        if command.pipelined {
            context.write(wrapOutboundOut(command.bytes), promise: promise)
        } else {
            context.writeAndFlush(wrapOutboundOut(command.bytes), promise: promise)
        }
    }

    /// Make `request` the one whose response is being read, with its timeouts.
    private func start(_ request: Pending, firstByteTimeout: TimeAmount, totalDeadline: NIODeadline) {
        pending = request
        guard let context else { return }
        let bound = NIOLoopBound(self, eventLoop: context.eventLoop)
        pending?.totalTimer = context.eventLoop.scheduleTask(deadline: totalDeadline) {
            bound.value.timedOut(.totalTimeout)
        }
        armPhaseTimer(firstByteTimeout, error: .firstByteTimeout)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if passThrough {
            context.fireChannelRead(data)
            return
        }
        let incoming = unwrapInboundIn(data)
        guard pending != nil else {
            // Bytes nobody asked for: the connection can no longer be trusted for reuse.
            context.close(promise: nil)
            return
        }
        if pending?.firstByteAt == nil { pending?.firstByteAt = .now() }
        pending?.buffer.append(contentsOf: incoming.readableBytesView)
        pending?.onBytes?(Array(incoming.readableBytesView))
        if let p = pending, p.buffer.count > p.maxBytes {
            fail(.tooLarge(limit: p.maxBytes))
            context.close(promise: nil)
            return
        }
        if let idle = pending?.idleTimeout { armPhaseTimer(idle, error: .idleTimeout) }
        evaluate()
    }

    func channelInactive(context: ChannelHandlerContext) {
        if let p = pending {
            switch p.head?.framing {
            case .closeDelimited:
                complete(end: p.buffer.count, reusable: false)
            default:
                fail(p.buffer.isEmpty ? .connectionReset : .incompleteResponse)
            }
        }
        failQueued(.connectionReset)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        fail(Self.networkError(error))
        context.close(promise: nil)
    }

    // MARK: framing

    /// Complete the pending response if its framing says the buffered bytes are enough.
    private func evaluate() {
        while let p = pending {
            if p.head == nil {
                let (end, terminator) = HTTP1.headerBlockEnd(p.buffer, from: max(p.start, p.headerResume))
                guard end - p.start <= HTTP1.maxHeaderBytes else {
                    fail(.tooLarge(limit: HTTP1.maxHeaderBytes))
                    context?.close(promise: nil)
                    return
                }
                guard terminator != 0 else {  // header block not complete yet
                    pending?.headerResume = HTTP1.headerScanResume(p.buffer.count)
                    return
                }
                let headerBytes = Array(p.buffer[p.start..<end])
                let head = ResponseHead(
                    headerBytes: headerBytes, blockEnd: end, isHead: p.isHead, isConnect: p.isConnect)
                if head.isInterim {
                    pending?.interim.append(headerBytes)
                    pending?.start = end
                    continue
                }
                pending?.head = head
                pending?.chunkResume = head.blockEnd
            }
            guard let current = pending, let head = current.head else { return }
            switch head.framing {
            case .none:
                complete(end: head.blockEnd, reusable: head.keepAlive)
            case .contentLength(let length):
                guard current.buffer.count - head.blockEnd >= length else { return }
                complete(end: head.blockEnd + length, reusable: head.keepAlive)
            case .chunked:
                switch HTTP1.scanChunked(current.buffer, from: current.chunkResume) {
                case .complete(let end):
                    complete(end: end, reusable: head.keepAlive)
                case .needMore(let resumeAt):
                    pending?.chunkResume = resumeAt
                case .malformed:
                    // Unknowable end: fall back to reading until the server closes.
                    pending?.head?.framing = .closeDelimited
                }
            case .closeDelimited:
                break  // completes in channelInactive
            }
            return
        }
    }

    private func complete(end: Int, reusable: Bool) {
        guard let p = pending else { return }
        let surplus = p.buffer.count > end
        let switching = p.head?.status == 101
        finish(
            WireResponse(
                bytes: Array(p.buffer[p.start..<end]), interim: p.interim, error: nil,
                firstByteAt: p.firstByteAt, lastByteAt: .now(), reusable: reusable && !surplus && !switching,
                receivedAny: true))
        if !switching, !queued.isEmpty {
            // HTTP-011: the next pipelined response starts where this one ended.
            let next = queued.removeFirst()
            start(next.pending, firstByteTimeout: next.firstByteTimeout, totalDeadline: next.totalDeadline)
            if surplus {
                pending?.firstByteAt = .now()
                pending?.buffer = Array(p.buffer[end...])
                evaluate()
            }
            return
        }
        guard switching, let context else { return }
        // The first frames may have arrived with the 101: hand them on, then pass everything through.
        passThrough = true
        if surplus {
            let rest = context.channel.allocator.buffer(bytes: p.buffer[end...])
            context.fireChannelRead(NIOAny(rest))
        }
    }

    private func fail(_ error: GulpNetworkError) {
        guard let p = pending else { return }
        finish(
            WireResponse(
                bytes: Array(p.buffer[p.start...]), interim: p.interim, error: error,
                firstByteAt: p.firstByteAt, lastByteAt: p.firstByteAt == nil ? nil : .now(), reusable: false,
                receivedAny: !p.buffer.isEmpty))
        failQueued(error)
    }

    /// The connection is unusable: every pipelined request still waiting fails too.
    private func failQueued(_ error: GulpNetworkError) {
        let waiting = queued
        queued = []
        for item in waiting {
            item.pending.promise.succeed(
                WireResponse(
                    bytes: [], interim: [], error: error, firstByteAt: nil, lastByteAt: nil, reusable: false,
                    receivedAny: false))
        }
    }

    private func finish(_ response: WireResponse) {
        guard let p = pending else { return }
        p.phaseTimer?.cancel()
        p.totalTimer?.cancel()
        pending = nil
        p.promise.succeed(response)
    }

    // MARK: timeouts

    private func armPhaseTimer(_ amount: TimeAmount, error: GulpNetworkError) {
        guard let context, pending != nil else { return }
        pending?.phaseTimer?.cancel()
        let bound = NIOLoopBound(self, eventLoop: context.eventLoop)
        pending?.phaseTimer = context.eventLoop.scheduleTask(in: amount) {
            bound.value.timedOut(error)
        }
    }

    private func timedOut(_ error: GulpNetworkError) {
        guard pending != nil else { return }
        fail(error)
        context?.close(promise: nil)
    }

    /// Map a channel error to the typed network error recorded with the exchange.
    static func networkError(_ error: any Error) -> GulpNetworkError {
        if let e = error as? GulpNetworkError { return e }
        if let e = error as? ChannelError, case .connectTimeout = e { return .connectTimeout }
        let text = String(describing: error).lowercased()
        if text.contains("socks") { return .upstreamProxyError(String(describing: error)) }
        if text.contains("refused") { return .connectionRefused }
        if text.contains("reset") || text.contains("broken pipe") || text.contains("eof") {
            return .connectionReset
        }
        return .other(String(describing: error))
    }
}
