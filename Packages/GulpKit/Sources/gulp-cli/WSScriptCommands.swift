// gulp-cli — scripted WebSocket sequences (F15 §2.3, WSX-008). Drives a `send / expect` script over one
// persistent WebSocket connection: it sends each `send` frame and, for each `expect`, waits for the
// next received frame and checks it matches, printing a transcript. A failed expect stops the run.

import ArgumentParser
import Foundation
import GulpCodec
import GulpCore
import GulpHTTP

/// An ordered inbox of a socket's text replies (one reply per `take`, with a per-wait timeout).
private actor WSScriptQueue {
    private var buffer: [String] = []
    private var waiter: CheckedContinuation<String?, Never>?
    private var closed = false

    func deliver(_ message: String) {
        if let waiter {
            self.waiter = nil
            waiter.resume(returning: message)
        } else {
            buffer.append(message)
        }
    }

    func close() {
        closed = true
        if let waiter {
            self.waiter = nil
            waiter.resume(returning: nil)
        }
    }

    func timeout() {
        if let waiter {
            self.waiter = nil
            waiter.resume(returning: nil)
        }
    }

    func take() async -> String? {
        if !buffer.isEmpty { return buffer.removeFirst() }
        if closed { return nil }
        return await withCheckedContinuation { waiter = $0 }
    }
}

/// `gulp-cli ws-script --target http://host --path /ws --script seq.txt`
struct WSScript_: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ws-script",
        abstract: "Run a send/expect WebSocket sequence over one connection (stateful protocols).")

    @Option(help: "The server, e.g. http://127.0.0.1:8088.") var target: String
    @Option(help: "The WebSocket path.") var path = "/ws"
    @Option(help: "A script file: `send <text>` / `expect <substr>` / `expect-regex <pat>` lines.")
    var script: String

    func run() async throws {
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        guard let data = FileManager.default.contents(atPath: script),
            let text = String(data: data, encoding: .utf8)
        else { throw ValidationError("Cannot read \(script)") }
        let sequence = WSScript.parse(text)
        guard !sequence.steps.isEmpty else { throw ValidationError("The script has no steps.") }

        let engine = NIOHTTPEngine()
        defer { Task { await engine.shutdown() } }
        let defaultPort = destination.scheme == .https ? 443 : 80
        let host =
            destination.port == defaultPort ? destination.host : "\(destination.host):\(destination.port)"
        let nonce = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let upgrade = RawRequest(
            Bytes(
                "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: \(nonce)\r\n\r\n"))
        let session = try await engine.openWebSocket(
            upgrade, to: destination, options: SendOptions(recordAs: .automation))
        let queue = WSScriptQueue()
        let reader = Task {
            for await message in session.messages where message.opcode == WSOpcode.text.rawValue {
                await queue.deliver(String(decoding: message.payload, as: UTF8.self))
            }
            await queue.close()
        }
        defer {
            reader.cancel()
            Task { await session.close() }
        }

        var allMatched = true
        for (index, step) in sequence.steps.enumerated() {
            switch step {
            case .send(let message):
                try await session.send(text: message)
                print("  #\(index + 1) send    \(message)")
            case .expect(let pattern, let isRegex, let timeoutMs):
                let timeoutTask = Task {
                    try? await Task.sleep(nanoseconds: UInt64(max(0, timeoutMs)) * 1_000_000)
                    await queue.timeout()
                }
                let frame = await queue.take()
                timeoutTask.cancel()
                let matched = frame.map { WSScriptMatch.matches($0, step: step) } ?? false
                let kind = isRegex ? "expect~" : "expect "
                print(
                    "  #\(index + 1) \(kind) \(pattern) → \(matched ? "MATCH" : "MISS") "
                        + "[\(frame ?? "(timeout)")]")
                if !matched {
                    allMatched = false
                    print("ws-script: step #\(index + 1) did not match; stopping.")
                    return
                }
            }
        }
        print("ws-script: \(allMatched ? "all steps matched" : "a step did not match")")
    }
}
