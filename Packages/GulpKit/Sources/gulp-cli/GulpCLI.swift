// gulp-cli — headless entry point for Gulp: `send` (M1), `proxy`/`history` (M2), `ca` (M3); scan/project
// automation arrives with M17 (docs/features/F21-automation.md). It drives the same ProjectSession as
// the app, so headless and GUI behave the same (doc 01 §5.2).

import ArgumentParser
import Dispatch
import Foundation
import GulpBrowser
import GulpCodec
import GulpCore
import GulpHTTP
import GulpProxy
import GulpStore
import GulpTLS
import GulpWorkspace

/// Version marker for the Gulp command-line tool.
enum GulpCLI {
    /// Semantic version of the CLI; bumped as the tool gains commands.
    static let version = "0.4.0"
}

/// The root command. `@main` (in a file not named main.swift) is how ArgumentParser runs an async
/// command; calling `main()` from top-level code picks the synchronous entry point, which refuses.
@main
struct GulpCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "gulp-cli", abstract: "Gulp, headless.", version: GulpCLI.version,
        subcommands: [Send.self, Proxy.self, History.self, CA.self, CopyAs.self, WS.self, Browser.self])
}

/// `gulp-cli send --raw request.txt --target http://host:port` writes the file's bytes exactly as
/// they are (HTTP-001) and prints the exact response bytes, interim 1xx responses included. With
/// `--repeat`, it sends the request many times and prints a summary instead.
struct Send: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Send a raw HTTP/1 request and print the exact response bytes.")

    @Option(help: "File holding the exact request bytes to send.")
    var raw: String

    @Option(help: "Where to connect, e.g. http://127.0.0.1:8088 (only scheme, host and port are used).")
    var target: String

    @Option(help: "Send through this HTTP proxy, e.g. http://127.0.0.1:8080 (HTTP-006).")
    var via: String?

    @Flag(help: "Recompute Content-Length from the body before sending (HTTP-008).")
    var updateContentLength = false

    @Option(help: "Total timeout in seconds.")
    var timeout = 30

    @Option(name: .customLong("repeat"), help: "Send the request this many times and print a summary.")
    var repeatCount = 1

    @Option(help: "With --repeat: how many sends run at once.")
    var concurrency = 1

    func run() async throws {
        guard let data = FileManager.default.contents(atPath: raw) else {
            throw ValidationError("Cannot read \(raw)")
        }
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target); expected http://host[:port]")
        }
        var options = SendOptions(recordAs: .automation)
        options.updateContentLength = updateContentLength
        options.timeouts.total = .seconds(timeout)
        if let via {
            guard let proxy = HTTPTarget(url: via) else { throw ValidationError("Invalid --via \(via)") }
            options.upstreamProxy = .proxy(UpstreamProxy(kind: .http, host: proxy.host, port: proxy.port))
        }
        let request = RawRequest(Bytes([UInt8](data)))
        let engine = NIOHTTPEngine()
        defer { Task { await engine.shutdown() } }
        if repeatCount > 1 {
            try await sendMany(request, to: destination, options: options, engine: engine)
            return
        }
        let result = await engine.send(request, to: destination, options: options)
        if let response = result.exchange.response {
            for interim in response.interim {
                FileHandle.standardOutput.write(Data(interim.bytes.rawBytes))
            }
            FileHandle.standardOutput.write(Data(response.bytes.rawBytes))
        }
        if let error = result.error {
            FileHandle.standardError.write(Data("gulp-cli: \(error.userDescription) [\(error.code)]\n".utf8))
            throw ExitCode(2)
        }
    }

    private func sendMany(
        _ request: RawRequest, to destination: HTTPTarget, options: SendOptions, engine: NIOHTTPEngine
    ) async throws {
        let total = repeatCount
        let lanes = max(1, min(concurrency, total))
        let succeeded = await withTaskGroup(of: Int.self) { group in
            for lane in 0..<lanes {
                group.addTask {
                    var ok = 0
                    for _ in stride(from: lane, to: total, by: lanes) {
                        let result = await engine.send(request, to: destination, options: options)
                        if result.error == nil { ok += 1 }
                    }
                    return ok
                }
            }
            return await group.reduce(0, +)
        }
        print("\(succeeded)/\(total) succeeded")
        if succeeded != total { throw ExitCode(2) }
    }
}

/// `gulp-cli proxy --project p.gulp --port 8080` runs the proxy headless, recording into the
/// project, until SIGINT/SIGTERM — then flushes and closes the project cleanly (PRJ-003).
struct Proxy: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Run the recording HTTP proxy headless.")

    @Option(help: "Project file to record into (created if missing).")
    var project: String

    @Option(help: "Listener port (0 picks a free port).")
    var port = 8080

    @Option(help: "Listener bind address.")
    var bind = "127.0.0.1"

    @Option(name: .customLong("add-header"), help: "Match & Replace: add this header to every request.")
    var addHeaders: [String] = []

    @Option(
        name: .customLong("intercept-replace"),
        help: "Intercept every request and forward it with FROM replaced by TO (\"FROM=>TO\").")
    var interceptReplacements: [String] = []

    func run() async throws {
        let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
        let listener = ProxyListenerConfig(bindAddress: bind, port: port)
        try await session.settings.set(ProxySettings(listeners: [listener]), scope: .project)
        if !addHeaders.isEmpty {
            let added = addHeaders.map { MatchReplaceRule(kind: .requestHeader, match: "", replace: $0) }
            let existing = session.settings.get(MatchReplaceSettings.self).rules
            try await session.setMatchReplaceRules(existing + added)
        }
        let replacements = try interceptReplacements.map { pair -> (String, String) in
            let parts = pair.components(separatedBy: "=>")
            guard parts.count == 2 else { throw ValidationError("--intercept-replace expects FROM=>TO") }
            return (parts[0], parts[1])
        }
        if !replacements.isEmpty {
            var intercept = InterceptSettings()
            intercept.interceptRequests = true
            intercept.requestRules = []
            try await session.setInterceptSettings(intercept)
            Task { await Self.autoForward(session, replacements) }
        }
        let results = await session.startProxyListeners()
        switch results[listener.id] {
        case .success(let bound):
            print("gulp-cli proxy: listening on \(bind):\(bound), recording into \(project)")
        case .failure(let error):
            FileHandle.standardError.write(Data("gulp-cli: \(error.message)\n".utf8))
            throw ExitCode(1)
        case nil:
            throw ExitCode(1)
        }
        await Signals.wait(for: [SIGINT, SIGTERM])
        try await session.close()
        print("gulp-cli proxy: stopped; project saved")
    }

    /// A scripted intercept user: edit every held request and forward it (exercises PRX-010…012).
    static func autoForward(_ session: ProjectSession, _ replacements: [(String, String)]) async {
        for await delivery in await session.events.subscribe() {
            guard case .interceptQueued = delivery.event else { continue }
            for item in await session.intercept.items where item.kind == .request {
                var text = item.request.bytes.string()
                for (from, to) in replacements { text = text.replacingOccurrences(of: from, with: to) }
                await session.intercept.decide(item.id, .forward(Bytes(text)))
            }
        }
    }
}

/// `gulp-cli copy-as --project p.gulp --id 3 --format curl` prints a recorded request as code (ETL-008).
struct CopyAs: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "copy-as",
        abstract: "Print a recorded request as cURL, Python, fetch, PowerShell or Go.")

    @Option(help: "Project file.")
    var project: String

    @Option(help: "Exchange id.")
    var id: Int64

    @Option(help: "curl, powershell, fetch, python or go.")
    var format = "curl"

    func run() async throws {
        let formats: [String: RequestExportFormat] = [
            "curl": .curl, "powershell": .powershell, "fetch": .fetch, "python": .python, "go": .go,
        ]
        guard let chosen = formats[format.lowercased()] else {
            throw ValidationError("Unknown format \(format)")
        }
        let store = try ProjectStore.open(at: URL(fileURLWithPath: project))
        defer { Task { try? await store.close() } }
        guard let exchange = try await store.exchange(id: id) else {
            throw ValidationError("No exchange \(id)")
        }
        print(RequestExport.export(exchange.request, target: exchange.target, as: chosen))
    }
}

/// `gulp-cli history --project p.gulp` prints what a project recorded.
struct History: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Print a project's HTTP history.")

    @Option(help: "Project file.")
    var project: String

    @Option(help: "Also list the last N exchanges.")
    var last = 0

    @Option(help: "Print one exchange's stored request and response.")
    var show: Int64?

    @Flag(help: "List WebSocket connections and their messages (PRX-031).")
    var websockets = false

    func run() async throws {
        let url = URL(fileURLWithPath: project)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw ValidationError("No project at \(project)")
        }
        let store = try ProjectStore.open(at: url)
        let count = try await store.count()
        print("exchanges: \(count)")
        if last > 0 {
            let rows = try await store.summaries(offset: max(0, count - last), limit: last)
            for row in rows {
                let status = row.status.map(String.init) ?? (row.error ?? "-")
                let version = row.httpVersion.rawValue
                print("\(row.id)\t\(row.method ?? "-")\t\(status)\t\(version)\t\(row.url)")
            }
        }
        if let show {
            guard let exchange = try await store.exchange(id: show) else {
                throw ValidationError("No exchange \(show)")
            }
            if let original = exchange.edited?.originalRequest {
                print("--- original request (before edits) ---")
                print(original.bytes.string())
            }
            print("--- request (\(exchange.httpVersion.rawValue)) ---")
            print(exchange.request.bytes.string())
            print("--- response ---")
            print(exchange.response?.wireBytes.string() ?? "(none)")
        }
        if websockets { try await printWebSockets(store) }
        try await store.close()
    }

    private func printWebSockets(_ store: ProjectStore) async throws {
        let connections = try await store.webSocketConnections()
        print("websockets: \(connections.count)")
        for connection in connections {
            let code = connection.closeCode.map(String.init) ?? "-"
            let closed = connection.closedAt == nil ? "open" : "closed \(code)"
            let upgrade = connection.upgradeExchangeID.map { "#\($0)" } ?? "-"
            let count = "\(connection.messageCount) messages"
            print("ws \(connection.id)\t\(connection.url)\tupgrade \(upgrade)\t\(closed)\t\(count)")
            for message in try await store.webSocketMessages(connection: connection.id) {
                let arrow = message.direction == WSDirection.toServer.rawValue ? "->" : "<-"
                let name = WS.opcodeName(message.opcode)
                print("  \(arrow) \(name)\t\(WS.preview(message.payload, opcode: message.opcode))")
            }
        }
    }
}

/// `gulp-cli ca export --out gulp-ca.pem` exports the user's Gulp CA certificate (TLS-006), creating
/// the CA on first use; clients that trust it accept the certificates the proxy presents.
struct CA: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Show or export the Gulp CA certificate.", subcommands: [Export.self, Show.self])

    struct Export: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Write the CA certificate to a file.")

        @Option(help: "Output file.")
        var out: String

        @Flag(help: "Write DER instead of PEM.")
        var der = false

        func run() async throws {
            let authority = try WorkspaceEnvironment.standard.certificateAuthority()
            let bytes = der ? try authority.certificateDER() : Array(try authority.certificatePEM().utf8)
            guard FileManager.default.createFile(atPath: out, contents: Data(bytes)) else {
                throw ValidationError("Cannot write \(out)")
            }
            print("gulp-cli ca: wrote \(out) (SHA-256 \(try authority.sha256Fingerprint()))")
        }
    }

    struct Show: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the CA's subject and fingerprint.")

        func run() async throws {
            let authority = try WorkspaceEnvironment.standard.certificateAuthority()
            print("subject: \(authority.certificate.subject)")
            print("sha256:  \(try authority.sha256Fingerprint())")
            let certificate = authority.certificate
            print("valid:   \(certificate.notValidBefore) – \(certificate.notValidAfter)")
        }
    }
}

/// Waits for a POSIX signal without killing the process, so shutdown can flush (PRJ-003).
enum Signals {
    // The dispatch sources must outlive the wait; touched only on the main thread.
    nonisolated(unsafe) static var sources: [DispatchSourceSignal] = []

    @MainActor
    static func wait(for signals: [Int32]) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let once = OnceFlag()
            for number in signals {
                signal(number, SIG_IGN)
                let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
                source.setEventHandler {
                    if once.claim() { continuation.resume() }
                }
                source.resume()
                sources.append(source)
            }
        }
    }
}

/// True exactly once, from any thread.
final class OnceFlag: @unchecked Sendable {
    // @unchecked: `done` is only read and written while holding `lock`.
    private let lock = NSLock()
    private var done = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}

/// `gulp-cli ws --url ws://127.0.0.1:8088/ws --send hi` opens a WebSocket (optionally through a proxy
/// with `--via`), sends each `--send` as a text message, prints what comes back, then closes
/// (F01 PRX-030; the VulnLab echo and the M4b DoD use it).
struct WS: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Talk to a WebSocket endpoint.")

    @Option(help: "ws:// or wss:// URL.")
    var url: String

    @Option(help: "Connect through this HTTP proxy, e.g. http://127.0.0.1:8080.")
    var via: String?

    @Option(help: "A text message to send (repeatable).")
    var send: [String] = []

    @Option(help: "How many messages to wait for before closing (default: one per --send, plus one).")
    var expect: Int?

    @Option(help: "Seconds to wait for replies.")
    var timeout = 5

    func run() async throws {
        guard let (target, path) = Self.target(url) else {
            throw ValidationError("Invalid --url \(url); expected ws://host[:port]/path")
        }
        var options = SendOptions(recordAs: .automation)
        options.timeouts.total = .seconds(timeout)
        if let via {
            guard let proxy = HTTPTarget(url: via) else { throw ValidationError("Invalid --via \(via)") }
            options.upstreamProxy = .proxy(UpstreamProxy(kind: .http, host: proxy.host, port: proxy.port))
        }
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        let host = standard ? target.host : "\(target.host):\(target.port)"
        let key = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let request = RawRequest(
            Bytes(
                Array(
                    ("GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        + "Sec-WebSocket-Key: \(key)\r\nSec-WebSocket-Version: 13\r\n\r\n").utf8)))
        let (incoming, feed) = AsyncStream.makeStream(of: [UInt8].self)
        let engine = NIOHTTPEngine()
        defer { Task { await engine.shutdown() } }
        let (result, connection) = await engine.upgrade(
            request, to: target, options: options, onRead: { feed.yield($0) }, onClose: { feed.finish() })
        guard let connection else {
            let reason =
                result.error?.userDescription ?? result.exchange.response?.bytes.string() ?? "no response"
            FileHandle.standardError.write(Data("gulp-cli: upgrade failed: \(reason)\n".utf8))
            throw ExitCode(2)
        }
        print("connected: \(result.exchange.response?.bytes.string().split(separator: "\r\n").first ?? "")")
        for text in send {
            try await connection.write(
                WebSocketWire.frame(opcode: .text, payload: Array(text.utf8), mask: Self.mask()))
            print("-> \(text)")
        }
        let wanted = expect ?? (send.count + 1)
        let received = await Self.collect(incoming, messages: wanted, timeout: timeout)
        for message in received {
            let opcode = Int(message.opcode)
            print("<- \(Self.opcodeName(opcode))\t\(Self.preview(message.payload, opcode: opcode))")
        }
        let close = WebSocketWire.frame(opcode: .close, payload: [0x03, 0xE8], mask: Self.mask())  // 1000
        try? await connection.write(close)
        try? await Task.sleep(for: .milliseconds(200))
        await connection.close()
        if received.count < wanted {
            let message = "gulp-cli: got \(received.count) of \(wanted) messages\n"
            FileHandle.standardError.write(Data(message.utf8))
            throw ExitCode(2)
        }
    }

    /// The HTTP target and request path for a ws/wss URL.
    static func target(_ url: String) -> (HTTPTarget, String)? {
        let lower = url.lowercased()
        let http: String
        if lower.hasPrefix("ws://") {
            http = "http://" + url.dropFirst(5)
        } else if lower.hasPrefix("wss://") {
            http = "https://" + url.dropFirst(6)
        } else {
            return nil
        }
        guard let target = HTTPTarget(url: http) else { return nil }
        let rest = http.split(separator: "/", maxSplits: 3, omittingEmptySubsequences: false)
        let path = rest.count > 3 ? "/" + rest[3] : "/"
        return (target, path)
    }

    static func mask() -> [UInt8] { (0..<4).map { _ in UInt8.random(in: 0...255) } }

    static func opcodeName(_ opcode: Int) -> String {
        WSOpcode(rawValue: UInt8(truncatingIfNeeded: opcode)).map { "\($0)" } ?? "op\(opcode)"
    }

    /// Messages received so far (shared between the reader and the timeout).
    actor Inbox {
        var messages: [WSMessage] = []
        func add(_ message: WSMessage) { messages.append(message) }
    }

    /// Messages (data and control) from the server, until `messages` arrived or `timeout` passed;
    /// on timeout, whatever arrived.
    static func collect(_ incoming: AsyncStream<[UInt8]>, messages: Int, timeout: Int) async -> [WSMessage] {
        let inbox = Inbox()
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                var parser = WSFrameParser()
                var assembler = WSMessageAssembler()
                var count = 0
                for await bytes in incoming {
                    for frame in parser.feed(bytes) {
                        guard let message = assembler.add(frame) else { continue }
                        await inbox.add(message)
                        count += 1
                    }
                    if count >= messages { break }
                }
            }
            group.addTask { try? await Task.sleep(for: .seconds(timeout)) }
            await group.next()
            group.cancelAll()
        }
        return await inbox.messages
    }

    /// Text as text (cut at 200 characters), anything else as a byte count.
    static func preview(_ payload: [UInt8], opcode: Int) -> String {
        if opcode == Int(WSOpcode.text.rawValue) {
            let text = String(decoding: payload, as: UTF8.self)
            return text.count > 200 ? String(text.prefix(200)) + "…" : text
        }
        if opcode == Int(WSOpcode.close.rawValue), payload.count >= 2 {
            return "code \(Int(payload[0]) << 8 | Int(payload[1]))"
        }
        return "\(payload.count) bytes"
    }
}

/// `gulp-cli browser --proxy-port 8080 --url https://localhost:8443/` launches the Gulp Browser
/// (F16 BRW-001…BRW-003) through a running Gulp listener, trusting the user's Gulp CA by its key pin.
/// `--headless --dump-dom` prints the page and exits (the M4b browser check on macOS CI).
struct Browser: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Launch a browser proxied through Gulp.")

    @Option(help: "The Gulp listener port to proxy through.")
    var proxyPort: Int

    @Option(help: "A page to open (repeatable).")
    var url: [String] = []

    @Option(help: "Browser executable (default: the first Chromium-family browser found).")
    var browser: String?

    @Flag(help: "Run without a window.")
    var headless = false

    @Flag(help: "With --headless: print the page's DOM and exit.")
    var dumpDom = false

    func run() async throws {
        let environment = WorkspaceEnvironment.standard
        let chosen: InstalledBrowser
        if let browser {
            chosen = InstalledBrowser(name: "browser", executable: URL(fileURLWithPath: browser))
        } else if let found = environment.installedBrowsers().first {
            chosen = found
        } else {
            throw ValidationError("No Chromium-family browser found; pass --browser /path/to/chrome")
        }
        let authority = try environment.certificateAuthority()
        // A fresh profile per CLI run; the proxy presents the CA in its chain, so its pin suffices.
        let profile = FileManager.default.temporaryDirectory
            .appendingPathComponent("gulp-browser-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: profile) }
        let options = BrowserLaunchOptions(
            proxyPort: proxyPort, spkiPins: [authority.key.spkiPin], profile: profile, urls: url,
            headless: headless, dumpDOM: dumpDom)
        print("gulp-cli browser: \(chosen.name) via 127.0.0.1:\(proxyPort)")
        let launcher = BrowserLauncher()
        let launched = try launcher.launch(chosen, options: options, output: .standardOutput)
        let status = launcher.wait(launched) ?? 0
        if status != 0 { throw ExitCode(status) }
    }
}
