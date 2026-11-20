// gulp-cli — OAST-correlated blind injection over WebSocket (F07 §2.6, WSX-005). Registers an OAST
// payload, carries its URL in a WebSocket message, and reports whether the server made an out-of-band
// interaction (DNS/HTTP) correlated to that payload — proving a blind SSRF/injection reachable only
// over the socket.

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpOAST

/// `gulp-cli ws-oast --target http://host --path /ws/ssrf --oast-server http://127.0.0.1:8090
/// --oast-domain oast.test`
struct WSOast: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ws-oast",
        abstract: "Carry an OAST payload in a WebSocket message and report correlated interactions.")

    @Option(help: "The server, e.g. http://127.0.0.1:8088.") var target: String
    @Option(help: "The WebSocket path.") var path = "/ws/ssrf"
    @Option(help: "The OAST/interactsh server (or dev Beacon).") var oastServer: String
    @Option(help: "The domain OAST payload hosts live under.") var oastDomain = ""
    @Option(help: "An OAST token, if the server requires one.") var oastToken: String?
    @Option(help: "A message template; «URL» is replaced by the OAST URL (default: the URL alone).")
    var template = "«URL»"
    @Option(help: "Seconds to wait for an interaction.") var wait = 8

    func run() async throws {
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let engine = ScopedSender(scope: .pinned(destination))
        defer { Task { await engine.shutdown() } }
        // The OAST server is the operator's own infrastructure, never the target: a deliberate override.
        guard let oastTarget = HTTPTarget(url: oastServer) else {
            throw ValidationError("Invalid --oast-server \(oastServer)")
        }
        let oastSender = ScopedSender(scope: .overridden(reason: "polls the operator's OAST server"))
        defer { Task { await oastSender.shutdown() } }
        let transport = EngineOASTTransport(engine: try await oastSender.engine(checkedFor: oastTarget))
        let client = try InteractshClient(
            serverURL: oastServer, domain: oastDomain.isEmpty ? nil : oastDomain,
            token: oastToken?.isEmpty == true ? nil : oastToken, transport: transport)
        try await client.register()
        defer { Task { try? await client.deregister() } }

        let payload = await client.newPayload()
        let url = payload.httpURL + "blind"
        let message = template.replacingOccurrences(of: "«URL»", with: url)
        print("ws-oast: injecting \(url) over \(path)")

        // Send the payload over one socket.
        let host = destination.hostHeader
        let nonce = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let upgrade = RawRequest(
            Bytes(
                "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: \(nonce)\r\n\r\n"))
        let session = try await engine.openWebSocket(
            upgrade, to: destination, options: SendOptions(recordAs: .automation))
        try await session.send(text: message)
        // Let any immediate reply drain, then close the socket; the interaction is out of band.
        try? await Task.sleep(nanoseconds: 300_000_000)
        await session.close()

        // Poll for a correlated interaction.
        var protos: Set<String> = []
        let deadline = ContinuousClock.now + .seconds(wait)
        while ContinuousClock.now < deadline, protos.isEmpty || !protos.contains("http") {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            let interactions = (try? await client.poll()) ?? []
            for interaction in interactions where interaction.uniqueID == payload.id.lowercased() {
                protos.insert(interaction.proto)
            }
        }

        if protos.isEmpty {
            print("ws-oast: no interaction — the message did not trigger a back-end request.")
        } else {
            print(
                "ws-oast: VULNERABLE — blind SSRF over WebSocket confirmed; interactions: "
                    + protos.sorted().joined(separator: ", "))
        }
    }
}
