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
import GulpRepeater
import GulpStore
import GulpTLS
import GulpWorkspace

/// Version marker for the Gulp command-line tool.
enum GulpCLI {
    /// Semantic version of the CLI; bumped as the tool gains commands.
    static let version = "0.11.0"
}

/// The root command. `@main` (in a file not named main.swift) is how ArgumentParser runs an async
/// command; calling `main()` from top-level code picks the synchronous entry point, which refuses.
@main
struct GulpCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "gulp-cli", abstract: "Gulp, headless.", version: GulpCLI.version,
        subcommands: [
            Send.self, Group.self, Paste.self, Repeater.self, Proxy.self, History.self, CA.self, CopyAs.self,
            WS.self, Browser.self, Scope.self, Target.self, ProjectCommand.self, MCP.self, Decode.self,
            Diff.self, JWTCommand.self, Fuzz.self, Discover.self, Wordlists.self, Query.self, Search.self,
            LoggerCommand.self, Filters.self, NotebookCommand.self, Coverage.self, Seed.self,
            IssuesCommand.self, ScanCommand.self, GRPCCommand.self, CrawlCommand.self, OASTCommand.self,
            GovernorCommand.self, SessionCommand.self, AuthzCommand.self, GraphQLCommand.self,
            ReportCommand.self, SequencerCommand.self, DiscoverParams.self, Smuggle.self, CSWSH.self,
            JSReconCommand.self, Pollute.self, WSAuthz.self, WSFuzz.self, SmuggleConfirm.self,
            WSOast.self,
        ])
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

    @Option(
        name: .customLong("repeat"),
        help: "Send the request this many times and print a summary; `{n}` in the request becomes 1…N.")
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
        // `{n}` in the file becomes each send's number; without it the bytes go out unchanged.
        let template = request.bytes.string()
        let numbered = template.contains("{n}")
        let succeeded = await withTaskGroup(of: Int.self) { group in
            for lane in 0..<lanes {
                group.addTask {
                    var ok = 0
                    for index in stride(from: lane, to: total, by: lanes) {
                        let outgoing =
                            numbered
                            ? RawRequest(
                                Bytes(template.replacingOccurrences(of: "{n}", with: String(index + 1))))
                            : request
                        let result = await engine.send(outgoing, to: destination, options: options)
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

    @Flag(help: "Use the project's scope for the proxy: out-of-scope traffic is not recorded (TGT-024).")
    var useScope = false

    func run() async throws {
        let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
        let listener = ProxyListenerConfig(bindAddress: bind, port: port)
        var proxySettings = ProxySettings(listeners: [listener])
        proxySettings.useScope = useScope
        try await session.settings.set(proxySettings, scope: .project)
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

    @Flag(
        name: .customLong("connections"),
        help: "List connections and how many exchanges each carried (HIS-042).")
    var connectionView = false

    func run() async throws {
        let url = URL(fileURLWithPath: project)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw ValidationError("No project at \(project)")
        }
        let store = try ProjectStore.open(at: url)
        let count = try await store.count()
        print("exchanges: \(count)")
        if connectionView {
            for connection in try await store.connectionSummaries() {
                print(
                    "conn \(connection.id)\t\(connection.origin)\t\(connection.httpVersion)\t"
                        + "\(connection.alpn ?? "-")\t\(connection.exchanges) exchange(s)\t"
                        + "#\(connection.firstID)…#\(connection.lastID)")
            }
        }
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

/// `gulp-cli group --raw req.txt --target https://localhost:8443 --count 20 --mode single-packet`
/// sends the request `count` times as one group (F03 HTTP-030…HTTP-035) and prints each result
/// with its final-write offset, then the status counts and the spread.
struct Group: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Send a request as a group (race testing).")

    @Option(help: "File holding the exact request bytes.")
    var raw: String

    @Option(help: "Where to connect, e.g. https://127.0.0.1:8443.")
    var target: String

    @Option(help: "How many copies to send.")
    var count = 20

    @Option(help: "single-packet, parallel, sequential (one connection) or separate (a connection each).")
    var mode = "single-packet"

    @Option(help: "Single-packet warm-up in milliseconds.")
    var warmUp = 100

    @Flag(help: "Use HTTP/1.1 even if the server offers HTTP/2.")
    var http1 = false

    func run() async throws {
        guard let data = FileManager.default.contents(atPath: raw) else {
            throw ValidationError("Cannot read \(raw)")
        }
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let groupMode: GroupSendMode
        switch mode {
        case "single-packet": groupMode = .singlePacket
        case "parallel": groupMode = .parallel
        case "sequential": groupMode = .sequentialSingleConnection
        case "separate": groupMode = .sequentialSeparateConnections
        default: throw ValidationError("Unknown --mode \(mode)")
        }
        var options = SendOptions(recordAs: .automation)
        options.singlePacketWarmUp = .milliseconds(warmUp)
        options.httpVersion = http1 ? .http1_1 : .auto
        options.tls.validateCertificates = false
        options.timeouts.total = .seconds(30)
        let request = RawRequest(Bytes([UInt8](data)))
        let items = (0..<max(1, count)).map { _ in GroupItem(request: request, target: destination) }
        let engine = NIOHTTPEngine()
        defer { Task { await engine.shutdown() } }
        let results = await engine.sendGroup(items, mode: groupMode, options: options)
        var statuses: [String: Int] = [:]
        for (index, result) in results.enumerated() {
            let status =
                result.exchange.response.map { String($0.parsed.statusCode) } ?? (result.error?.code ?? "-")
            statuses[status, default: 0] += 1
            let offset = result.exchange.timing.finalWriteOffsetMs.map { String(format: "%.2f", $0) } ?? "-"
            let version = result.exchange.httpVersion.rawValue
            print("\(index + 1)\t\(status)\t\(version)\tfinal+\(offset) ms")
        }
        print(
            "statuses: "
                + statuses.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " "))
        let offsets = results.compactMap(\.exchange.timing.finalWriteOffsetMs)
        if let spread = offsets.max() { print(String(format: "final-write spread: %.2f ms", spread)) }
    }
}

/// `gulp-cli paste < snippet.txt` parses a pasted cURL command, `fetch(...)` call or raw request
/// (F06 REP-017) and prints the request it becomes; `--send` sends it and prints the response.
struct Paste: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Turn a pasted cURL/fetch/raw request into a request.")

    @Option(help: "Read the paste from this file instead of standard input.")
    var file: String?

    @Flag(help: "Send the request and print the response.")
    var send = false

    func run() async throws {
        let data: Data
        if let file {
            guard let contents = FileManager.default.contents(atPath: file) else {
                throw ValidationError("Cannot read \(file)")
            }
            data = contents
        } else {
            data = FileHandle.standardInput.readDataToEndOfFile()
        }
        let imported = try RequestImport.parse(String(decoding: data, as: UTF8.self))
        let target = imported.target
        print(
            "target: \(target.scheme.rawValue)://\(target.host):\(target.port)\(imported.prefersHTTP2 ? " (HTTP/2)" : "")"
        )
        for item in imported.ignored { print("ignored: \(item)") }
        print("--- request ---")
        print(imported.request.bytes.string())
        guard send else { return }
        var options = SendOptions(recordAs: .automation)
        options.tls.validateCertificates = !imported.insecure
        options.httpVersion = imported.prefersHTTP2 ? .http2 : .auto
        if imported.followRedirects { options.followRedirects = RedirectPolicy(mode: .always) }
        let engine = NIOHTTPEngine()
        defer { Task { await engine.shutdown() } }
        let result = await engine.send(imported.request, to: target, options: options)
        print("--- response ---")
        print(
            result.exchange.response?.wireBytes.string() ?? "(none: \(result.error?.userDescription ?? "?"))")
        if result.error != nil { throw ExitCode(2) }
    }
}

/// `gulp-cli repeater --project p.gulp --raw req.txt --target http://127.0.0.1:8088` sends through a
/// Repeater tab stored in the project (F06), printing a streamed response as it arrives (REP-016).
struct Repeater: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Send a request from a Repeater tab in a project.")

    @Option(help: "Project file (created if missing).")
    var project: String

    @Option(help: "File holding the exact request bytes.")
    var raw: String

    @Option(help: "Where to connect.")
    var target: String

    @Option(help: "Tab title.")
    var title = "cli"

    @Flag(help: "Print each piece of the response as it arrives, with its time.")
    var stream = false

    @Flag(help: "Send even if the target is outside the project's scope (the app's \"Send anyway\").")
    var allowOutOfScope = false

    @Option(
        help: "Set a Transform Tag variable for «var(name)» (name=value; repeatable; saved in the project).")
    var `var`: [String] = []

    @Flag(help: "Send Transform Tags literally instead of evaluating them.")
    var noTags = false

    @Option(
        help:
            "After sending, poll OAST for this many seconds and print the interactions the request caused (F10)."
    )
    var oastWait: Double = 0

    func run() async throws {
        guard let data = FileManager.default.contents(atPath: raw) else {
            throw ValidationError("Cannot read \(raw)")
        }
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
        // TGT-023: a manual send to an out-of-scope target asks first; headless, the answer is the flag.
        if !allowOutOfScope, await session.scopeDecision(for: destination, request: [UInt8](data)) == .confirm
        {
            try await session.close()
            FileHandle.standardError.write(
                Data(
                    "gulp-cli: Target is out of scope. Send anyway? Re-run with --allow-out-of-scope.\n".utf8)
            )
            throw ExitCode(3)
        }
        if !`var`.isEmpty {
            var values = await session.tagVariables()
            for pair in `var` {
                let parts = pair.split(separator: "=", maxSplits: 1)
                guard parts.count == 2 else { throw ValidationError("--var expects name=value") }
                values[String(parts[0])] = String(parts[1])
            }
            try await session.setTagVariables(values)
        }
        var options = RepeaterOptions()
        options.transformTags = !noTags
        let tab = await session.repeater.openTab(
            request: RawRequest(Bytes([UInt8](data))), target: destination, title: title, options: options)
        let printer = stream ? Self.chunkPrinter(since: .now) : nil
        let result = await session.repeater.send(tab.id, onBytes: printer)
        if !stream { print(result?.exchange.response?.wireBytes.string() ?? "(no response)") }
        let history = await session.repeater.history(tab.id)
        print("tab \(tab.id) '\(tab.title)': \(history.count) send(s); last exchange #\(history.last ?? 0)")
        if oastWait > 0, let last = history.last {
            await printOASTInteractions(session, exchange: last, wait: oastWait)
        }
        try await session.close()
        if result?.error != nil { throw ExitCode(2) }
    }

    /// Prints each received piece on one line with its arrival time.
    static func chunkPrinter(since started: ContinuousClock.Instant) -> @Sendable ([UInt8]) -> Void {
        { bytes in
            let elapsed = ContinuousClock.now - started
            let ms =
                Double(elapsed.components.seconds) * 1_000 + Double(elapsed.components.attoseconds) / 1e15
            let text = String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: "\r", with: "")
            print(String(format: "[+%.0f ms] ", ms) + text.split(separator: "\n").joined(separator: " | "))
        }
    }
}
