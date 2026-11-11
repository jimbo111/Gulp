// gulp-beacon — the OAST interaction server. v1 ships `--dev` only (F10 BCN-024): HTTP (the
// interactsh client API plus interaction capture) and DNS (UDP) on high local ports, in memory.
// Payload names are `<correlation id><nonce>.<domain>`; resolve them to this host (the dev DNS
// listener does; VulnLab connects to the Beacon directly). The deployable server — authoritative DNS
// on 53, ACME TLS on 443, retention — is post-1.0 (F10 §2.2; privileged ports need
// CAP_NET_BIND_SERVICE or a privilege drop).

import ArgumentParser
import BeaconKit
import Foundation
import Hummingbird
import Logging
import NIOCore
import NIOPosix

@main
struct GulpBeacon: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "gulp-beacon", abstract: "Gulp's OAST interaction server (dev mode).")

    @Flag(help: "Run the local dev server (the only mode in v1).") var dev = false
    @Option(help: "Address to listen on.") var host = "127.0.0.1"
    @Option(help: "HTTP port (the client API and HTTP interactions).") var httpPort = 8090
    @Option(help: "DNS (UDP) port.") var dnsPort = 8053
    @Option(help: "Payload domain.") var domain = "oast.test"
    @Option(help: "IPv4 address DNS answers A queries with.") var answer = "127.0.0.1"
    @Option(help: "Require this token in the Authorization header of API calls.") var token: String?

    func run() async throws {
        guard dev else {
            throw ValidationError(
                "Only --dev is available before 1.0 (see docs/features/F10-beacon-oast.md §2.2)")
        }
        let store = BeaconStore(token: token)
        let address = answer.split(separator: ".").compactMap { UInt8($0) }
        guard address.count == 4 else { throw ValidationError("--answer must be an IPv4 address") }
        let dns = try await DatagramBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(DNSHandler(store: store, address: address))
                }
            }
            .bind(host: host, port: dnsPort).get()
        let router = Router(context: BeaconContext.self)
        router.add(middleware: CaptureMiddleware(store: store, domain: domain.lowercased()))
        router.post("/register") { request, _ in try await reply(store, request) { await store.register($0) }
        }
        router.post("/deregister") { request, _ in
            try await reply(store, request) { await store.deregister($0) }
        }
        router.get("/poll") { request, _ -> Response in
            guard await store.authorized(request.headers[.authorization]) else {
                return Response(status: .unauthorized)
            }
            let reply = await store.poll(
                id: request.uri.queryParameters["id"].map(String.init),
                secret: request.uri.queryParameters["secret"].map(String.init))
            return response(reply)
        }
        var logger = Logger(label: "gulp-beacon")
        logger.logLevel = .warning
        let app = Application(
            router: router,
            configuration: .init(address: .hostname(host, port: httpPort), serverName: "gulp-beacon"),
            onServerRunning: { _ in
                print(
                    "gulp-beacon dev: http://\(host):\(httpPort) (API + HTTP interactions), dns udp \(host):\(dnsPort), domain \(domain)"
                )
            },
            logger: logger)
        try await app.runService()
        try await dns.close()
    }
}

/// The request context, with the peer address.
struct BeaconContext: RequestContext {
    var coreContext: CoreRequestContextStorage
    let remote: String

    init(source: ApplicationRequestContextSource) {
        coreContext = .init(source: source)
        remote = source.channel.remoteAddress?.ipAddress ?? "unknown"
    }
}

func response(_ reply: BeaconReply) -> Response {
    Response(
        status: HTTPResponse.Status(code: reply.status), headers: [.contentType: "application/json"],
        body: ResponseBody(byteBuffer: ByteBuffer(bytes: reply.body)))
}

func reply(_ store: BeaconStore, _ request: Request, _ handle: ([UInt8]) async -> BeaconReply) async throws
    -> Response
{
    guard await store.authorized(request.headers[.authorization]) else {
        return Response(status: .unauthorized)
    }
    var request = request
    let body = try await request.collectBody(upTo: 1 << 20)
    return response(await handle(Array(body.readableBytesView)))
}

/// Records every HTTP request whose Host carries a unique id under the domain, and answers it;
/// other requests (the API) continue to the router.
struct CaptureMiddleware: RouterMiddleware {
    typealias Context = BeaconContext
    let store: BeaconStore
    let domain: String

    func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response)
        async throws
        -> Response
    {
        let host = (request.head.authority ?? "").lowercased()
        let name = String(host.split(separator: ":").first ?? "")
        guard name.hasSuffix("." + domain), let found = BeaconIDs.find(in: name) else {
            return try await next(request, context)
        }
        var request = request
        let body = try await request.collectBody(upTo: 1 << 20)
        var raw = "\(request.method.rawValue) \(request.uri.string) HTTP/1.1\r\nHost: \(host)\r\n"
        for field in request.headers where field.name.canonicalName != "host" {
            raw += "\(field.name): \(field.value)\r\n"
        }
        raw += "\r\n" + String(decoding: body.readableBytesView, as: UTF8.self)
        await store.record(
            BeaconInteraction(
                proto: "http", uniqueID: found.unique, fullID: found.full, rawRequest: raw,
                remoteAddress: context.remote))
        return Response(
            status: .ok, headers: [.contentType: "text/html"],
            body: ResponseBody(byteBuffer: ByteBuffer(string: "<html><body>gulp-beacon</body></html>")))
    }
}

/// Answers DNS queries and records those that carry a unique id.
final class DNSHandler: ChannelInboundHandler, Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    let store: BeaconStore
    let address: [UInt8]

    init(store: BeaconStore, address: [UInt8]) {
        self.store = store
        self.address = address
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        let packet = Array(envelope.data.readableBytesView)
        guard let question = DNSCodec.question(packet) else { return }
        if let found = BeaconIDs.find(in: question.name) {
            let interaction = BeaconInteraction(
                proto: "dns", uniqueID: found.unique, fullID: found.full, queryType: question.typeName,
                rawRequest: "\(question.name). IN \(question.typeName)",
                remoteAddress: envelope.remoteAddress.ipAddress ?? "unknown")
            let store = self.store
            Task { await store.record(interaction) }
        }
        let reply = DNSCodec.answer(packet, question: question, address: address)
        let out = AddressedEnvelope(
            remoteAddress: envelope.remoteAddress, data: context.channel.allocator.buffer(bytes: reply))
        context.writeAndFlush(wrapOutboundOut(out), promise: nil)
    }
}
