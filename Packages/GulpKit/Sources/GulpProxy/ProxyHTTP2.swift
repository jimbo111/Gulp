// GulpProxy — HTTP/2 between the client and the proxy (F01 PRX-009). When the intercepted TLS
// handshake lands on `h2` (ALPN mirroring, PRX-008), the connection is handed to an HTTP/2 server
// pipeline; every stream becomes one exchange, forwarded through the shared engine (which itself
// speaks h2 or HTTP/1.1 upstream) and answered on the same stream, trailers included (HTTP-027).

import GulpCore
import GulpHTTP
import NIOCore
import NIOHPACK
import NIOHTTP2

/// Serves HTTP/2 clients inside an intercepted tunnel.
enum ProxyHTTP2 {
    /// Install the HTTP/2 server pipeline on `channel` (called on its event loop).
    static func serve(channel: any Channel, target: HTTPTarget, upstream: ProxyUpstream) {
        channel.configureHTTP2Pipeline(mode: .server) { stream in
            stream.eventLoop.makeCompletedFuture {
                let handler = H2ProxyStreamHandler(target: target, upstream: upstream)
                try stream.pipeline.syncOperations.addHandler(handler)
            }
        }.whenFailure { _ in channel.close(promise: nil) }
    }
}

/// One client stream: collect the request, forward it, write the response frames back.
final class H2ProxyStreamHandler: ChannelInboundHandler {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias OutboundOut = HTTP2Frame.FramePayload

    private let target: HTTPTarget
    private let upstream: ProxyUpstream
    private var head: HPACKHeaders?
    private var body: [UInt8] = []
    private var dispatched = false
    /// The forwarding task; cancelled when the stream goes away (a held request is then dropped).
    private var forwarding: Task<Void, Never>?

    init(target: HTTPTarget, upstream: ProxyUpstream) {
        self.target = target
        self.upstream = upstream
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .headers(let frame):
            if head == nil { head = frame.headers }  // a second HEADERS is request trailers: ignored
            if frame.endStream { dispatch(context) }
        case .data(let frame):
            if case .byteBuffer(let buffer) = frame.data { body += buffer.readableBytesView }
            if body.count > RequestFramer.maxBodyBytes {
                context.writeAndFlush(wrapOutboundOut(.rstStream(.refusedStream)), promise: nil)
                context.close(promise: nil)
                return
            }
            if frame.endStream { dispatch(context) }
        default:
            break
        }
    }

    private func dispatch(_ context: ChannelHandlerContext) {
        guard !dispatched, let head else { return }
        dispatched = true
        let headers = head.filter { !$0.name.hasPrefix(":") }.map { H2Header($0.name, $0.value) }
        let method = head.first(name: ":method") ?? "GET"
        let scheme = head.first(name: ":scheme") ?? "https"
        let authority = head.first(name: ":authority") ?? target.host
        let path = head.first(name: ":path") ?? "/"
        let parts = H2RequestParts(
            method: method, scheme: scheme, authority: authority, path: path, headers: headers, body: body)
        let request = HTTP2Text.request(parts)
        let loop = context.eventLoop
        let bound = NIOLoopBound((self, context), eventLoop: loop)
        let upstream = self.upstream
        let target = self.target
        forwarding = Task {
            let reply: H2ResponseParts
            switch await upstream.send(request, to: target) {
            case .response(let response), .streamed(let response?, _):
                reply = HTTP2Text.responseParts(response)
            case .streamed(nil, _):
                let page = ProxyConnection.errorPage(502, "Gulp could not complete the request.")
                reply = HTTP2Text.responseParts(RawResponse(Bytes(page)))
            case .failed(let reason):
                let page = ProxyConnection.errorPage(502, "Gulp could not complete the request: \(reason).")
                reply = HTTP2Text.responseParts(RawResponse(Bytes(page)))
            case .dropped:
                let page = ProxyConnection.errorPage(502, ProxyConnection.droppedMessage)
                reply = HTTP2Text.responseParts(RawResponse(Bytes(page)))
            }
            loop.execute {
                let (handler, context) = bound.value
                handler.write(reply, context: context)
            }
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        forwarding?.cancel()
        context.fireChannelInactive()
    }

    private func write(_ reply: H2ResponseParts, context: ChannelHandlerContext) {
        var headers = HPACKHeaders([(":status", String(reply.status))])
        for header in reply.headers { headers.add(name: header.name, value: header.value) }
        let hasBody = !reply.body.isEmpty
        let hasTrailers = !reply.trailers.isEmpty
        let head = HTTP2Frame.FramePayload.Headers(headers: headers, endStream: !hasBody && !hasTrailers)
        context.write(wrapOutboundOut(.headers(head)), promise: nil)
        if hasBody {
            let data = IOData.byteBuffer(context.channel.allocator.buffer(bytes: reply.body))
            context.write(wrapOutboundOut(.data(.init(data: data, endStream: !hasTrailers))), promise: nil)
        }
        if hasTrailers {
            var trailers = HPACKHeaders()
            for trailer in reply.trailers { trailers.add(name: trailer.name, value: trailer.value) }
            let tail = HTTP2Frame.FramePayload.Headers(headers: trailers, endStream: true)
            context.write(wrapOutboundOut(.headers(tail)), promise: nil)
        }
        context.flush()
    }
}
