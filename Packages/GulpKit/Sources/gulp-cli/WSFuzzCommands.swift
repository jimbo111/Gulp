// gulp-cli — WebSocket Fuzzer (F07 §2.6, WSX-002). Iterates a `§…§`-marked message template's payloads
// as frames over one persistent WebSocket connection and runs the Fuzzer's grep/extract analysis on
// each reply.

import ArgumentParser
import Foundation
import GulpCodec
import GulpCore
import GulpFuzzer
import GulpHTTP

/// An ordered inbox of a socket's text replies, so the fuzzer can pull exactly one reply per message.
private actor WSReplyQueue {
    private var buffer: [[UInt8]] = []
    private var waiter: CheckedContinuation<[UInt8]?, Never>?
    private var closed = false

    func deliver(_ message: [UInt8]) {
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

    /// Resume a pending reader with nil (used by the per-exchange timeout).
    func timeout() {
        if let waiter {
            self.waiter = nil
            waiter.resume(returning: nil)
        }
    }

    func take() async -> [UInt8]? {
        if !buffer.isEmpty { return buffer.removeFirst() }
        if closed { return nil }
        return await withCheckedContinuation { waiter = $0 }
    }
}

/// A `WSFuzzChannel` over one live `WebSocketSession`: send one text frame, return the next text reply
/// (or nil after `timeoutMs`).
private final class LiveWSChannel: WSFuzzChannel {
    private let session: WebSocketSession
    private let queue = WSReplyQueue()
    private let timeoutMs: Int
    private let reader: Task<Void, Never>

    init(_ session: WebSocketSession, timeoutMs: Int) {
        self.session = session
        self.timeoutMs = timeoutMs
        let queue = self.queue
        reader = Task {
            for await message in session.messages where message.opcode == WSOpcode.text.rawValue {
                await queue.deliver(message.payload)
            }
            await queue.close()
        }
    }

    func exchange(_ message: [UInt8]) async throws -> [UInt8]? {
        try await session.send(.text, message)
        let queue = self.queue
        let timeoutTask = Task { [timeoutMs] in
            try? await Task.sleep(nanoseconds: UInt64(max(0, timeoutMs)) * 1_000_000)
            await queue.timeout()
        }
        let reply = await queue.take()
        timeoutTask.cancel()
        return reply
    }

    func stop() { reader.cancel() }
}

/// `gulp-cli ws-fuzz --target http://host --path /ws/fuzz --template 'cmd=§x§' --payloads a,b,c
/// --grep INJECT`
struct WSFuzz: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ws-fuzz",
        abstract: "Fuzz a WebSocket message template over one live socket (grep/extract each reply).")

    @Option(help: "The server, e.g. http://127.0.0.1:8088.") var target: String
    @Option(help: "The WebSocket path.") var path = "/ws/fuzz"
    @Option(help: "The message template, with §…§ around each payload position.") var template: String
    @Flag(help: "Treat --template as a captured message and auto-mark its JSON values (WSX-007).")
    var auto = false
    @Option(help: "Comma-separated payloads (or use --payload-file).") var payloads = ""
    @Option(help: "A wordlist file, one payload per line.") var payloadFile: String?
    @Option(help: "Add a literal prefix to every payload.") var prefix: String?
    @Option(help: "Add a literal suffix to every payload.") var suffix: String?
    @Option(help: "A grep pattern (regex) run on each reply.") var grep: String?
    @Option(help: "Extract a regex capture group 1 from each reply.") var extract: String?
    @Option(help: "Delay between sends, in milliseconds.") var delayMs = 0
    @Flag(help: "Stop at the first reply that matches --grep.") var stopOnMatch = false
    @Option(help: "How long to wait for each reply, in milliseconds.") var timeoutMs = 2000

    func run() async throws {
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let source: PayloadSource
        if let payloadFile {
            source = .file(path: payloadFile)
        } else {
            let items = payloads.split(separator: ",").map(String.init)
            guard !items.isEmpty else { throw ValidationError("Provide --payloads or --payload-file.") }
            source = .list(items)
        }
        var processors: [PayloadProcessor] = []
        if let prefix { processors.append(.prefix(prefix)) }
        if let suffix { processors.append(.suffix(suffix)) }

        let messageTemplate: String
        if auto {
            let decoded = WSSubprotocolCodec.decode(Array(template.utf8))
            messageTemplate = WSSubprotocolCodec.autoInsertionPoints(decoded)
            print("ws-fuzz: \(decoded.subprotocol.rawValue) → template \(messageTemplate)")
        } else {
            messageTemplate = template
        }

        let config = WSFuzzConfig(
            template: Array(messageTemplate.utf8),
            payloadSet: PayloadSet(source, processors: processors),
            matches: grep.map { [GrepMatch($0, isRegex: true)] } ?? [],
            extracts: extract.map { [.regex(pattern: $0, group: 1)] } ?? [],
            delayMs: delayMs, stopOnFirstMatch: stopOnMatch)
        let engine = try WSFuzzEngine(config)

        let http = ScopedSender(scope: .pinned(destination))
        defer { Task { await http.shutdown() } }
        let host = destination.hostHeader
        let nonce = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let upgrade = RawRequest(
            Bytes(
                "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: \(nonce)\r\n\r\n"))
        let session = try await http.openWebSocket(
            upgrade, to: destination, options: SendOptions(recordAs: .automation))
        let channel = LiveWSChannel(session, timeoutMs: timeoutMs)
        defer {
            channel.stop()
            Task { await session.close() }
        }

        let results = try await engine.run(on: channel)
        print("ws-fuzz: \(results.count) message(s) over one socket to \(path)")
        var hits = 0
        for result in results {
            let matched = result.matches.contains(true)
            if matched { hits += 1 }
            let flag = matched ? "MATCH" : "     "
            let extract = result.extracts.first.flatMap { $0 }.map { " extract=\($0)" } ?? ""
            print(
                "  [\(flag)] #\(result.index) payload=\(result.payload) reflected=\(result.reflected.rawValue)"
                    + "\(extract)")
        }
        print("ws-fuzz: \(hits) match(es)")
    }
}
