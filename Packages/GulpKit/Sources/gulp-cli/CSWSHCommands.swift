// gulp-cli — Cross-Site WebSocket Hijacking probe (F23 WSX-003). A WebSocket endpoint that authorizes
// only at the HTTP handshake and does not check `Origin` can be opened from any site with the victim's
// cookies. This replays the handshake with an attacker `Origin`; if it still upgrades (101), the
// endpoint is CSWSH-vulnerable.

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP

/// `gulp-cli cswsh --target http://host --path /ws [--origin https://evil.test]`
struct CSWSH: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cswsh",
        abstract: "Probe a WebSocket endpoint for cross-site hijacking (no Origin check at handshake).")

    @Option(help: "The server, e.g. http://127.0.0.1:8088.") var target: String
    @Option(help: "The WebSocket path.") var path = "/ws"
    @Option(help: "The attacker Origin to present.") var origin = "https://attacker.example"

    func run() async throws {
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let defaultPort = destination.scheme == .https ? 443 : 80
        let host =
            destination.port == defaultPort ? destination.host : "\(destination.host):\(destination.port)"
        let nonce = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let upgrade = RawRequest(
            Bytes(
                "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: \(nonce)\r\nOrigin: \(origin)\r\n\r\n")
        )
        let engine = NIOHTTPEngine()
        defer { Task { await engine.shutdown() } }
        do {
            let session = try await engine.openWebSocket(
                upgrade, to: destination, options: SendOptions(recordAs: .automation))
            await session.close()
            print(
                "cswsh: VULNERABLE — \(path) accepted a cross-site handshake from Origin \(origin) "
                    + "(no Origin check). If it authorizes via cookies, any site can hijack it.")
        } catch {
            print("cswsh: not vulnerable — the cross-site handshake was rejected.")
        }
    }
}
