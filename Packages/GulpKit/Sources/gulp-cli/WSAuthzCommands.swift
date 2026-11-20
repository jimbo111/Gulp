// gulp-cli — WebSocket per-message authorization probe (F23 WSX-004). Replays a privileged WebSocket
// message over two fresh connections — one under a privileged identity, one under a stripped/other
// identity — and reports whether the privileged action still succeeds for the stripped identity. A
// server that authorizes only at the handshake lets the stripped identity through; one that
// re-authorizes each message refuses it.

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpScanner

/// `gulp-cli ws-authz --target http://host --path /ws/authz --message '{"action":"secret"}'
/// --privileged-cookie sid=admin --stripped-cookie sid=guest`
struct WSAuthz: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ws-authz",
        abstract: "Probe a WebSocket for per-message authorization (handshake-only vs per-message).")

    @Option(help: "The server, e.g. http://127.0.0.1:8088.") var target: String
    @Option(help: "The WebSocket path.") var path = "/ws/authz"
    @Option(help: "The privileged message to replay (sent verbatim as a text frame).")
    var message: String
    @Option(help: "Cookie for the privileged handshake, e.g. sid=admin.") var privilegedCookie: String
    @Option(help: "Cookie for the stripped handshake (omit to send no identity).")
    var strippedCookie: String?
    @Option(help: "A substring that marks a successful privileged reply (default: the reply itself).")
    var successMarker = ""
    @Option(help: "How long to wait for each reply, in milliseconds.") var timeoutMs = 2000

    func run() async throws {
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let engine = ScopedSender(scope: .pinned(destination))
        defer { Task { await engine.shutdown() } }

        let privilegedReply = try await replay(cookie: privilegedCookie, engine: engine, to: destination)
        let strippedReply = try await replay(cookie: strippedCookie, engine: engine, to: destination)

        print("ws-authz: privileged reply → \(privilegedReply.isEmpty ? "(none)" : privilegedReply)")
        print("ws-authz: stripped reply   → \(strippedReply.isEmpty ? "(none)" : strippedReply)")

        let verdict = WSAuthzProbe.classify(
            privilegedReply: privilegedReply, strippedReply: strippedReply, successMarker: successMarker)
        switch verdict {
        case .missing:
            print(
                "ws-authz: VULNERABLE — the privileged action succeeded under a stripped identity, so "
                    + "\(path) authorizes only at the handshake (no per-message authorization).")
        case .enforced:
            print(
                "ws-authz: enforced — the stripped identity was refused, so \(path) re-authorizes each "
                    + "message.")
        case .inconclusive:
            print(
                "ws-authz: inconclusive — the privileged baseline did not succeed; check the message, "
                    + "the privileged identity, or --success-marker.")
        }
    }

    /// Open a fresh socket with the given cookie, send `message`, and return the first text reply.
    private func replay(cookie: String?, engine: ScopedSender, to destination: HTTPTarget) async throws
        -> String
    {
        let host = destination.hostHeader
        let nonce = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let cookieLine = cookie.map { "Cookie: \($0)\r\n" } ?? ""
        let upgrade = RawRequest(
            Bytes(
                "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: \(nonce)\r\n\(cookieLine)\r\n"))
        let session = try await engine.openWebSocket(
            upgrade, to: destination, options: SendOptions(recordAs: .automation))
        defer { Task { await session.close() } }
        try await session.send(text: message)
        return await Self.firstText(session, timeoutMs: timeoutMs) ?? ""
    }

    /// The first text message on `session`, or nil if none arrives within `timeoutMs`.
    static func firstText(_ session: WebSocketSession, timeoutMs: Int) async -> String? {
        await withTaskGroup(of: String?.self) { group in
            group.addTask {
                for await msg in session.messages where msg.opcode == WSOpcode.text.rawValue {
                    return String(decoding: msg.payload, as: UTF8.self)
                }
                return nil
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(max(0, timeoutMs)) * 1_000_000)
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
    }
}
