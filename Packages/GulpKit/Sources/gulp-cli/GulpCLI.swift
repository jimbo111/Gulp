// gulp-cli — headless entry point for Gulp: `send` (M1), `proxy`/`history` (M2), `ca` (M3); scan/project
// automation arrives with M17 (docs/features/F21-automation.md). It drives the same ProjectSession as
// the app, so headless and GUI behave the same (doc 01 §5.2).

import ArgumentParser
import Dispatch
import Foundation
import GulpCore
import GulpHTTP
import GulpProxy
import GulpStore
import GulpTLS
import GulpWorkspace

/// Version marker for the Gulp command-line tool.
enum GulpCLI {
    /// Semantic version of the CLI; bumped as the tool gains commands.
    static let version = "0.3.0"
}

/// The root command. `@main` (in a file not named main.swift) is how ArgumentParser runs an async
/// command; calling `main()` from top-level code picks the synchronous entry point, which refuses.
@main
struct GulpCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "gulp-cli", abstract: "Gulp, headless.", version: GulpCLI.version,
        subcommands: [Send.self, Proxy.self, History.self, CA.self])
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

    func run() async throws {
        let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
        let listener = ProxyListenerConfig(bindAddress: bind, port: port)
        try await session.settings.set(ProxySettings(listeners: [listener]), scope: .project)
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
            print("--- request (\(exchange.httpVersion.rawValue)) ---")
            print(exchange.request.bytes.string())
            print("--- response ---")
            print(exchange.response?.wireBytes.string() ?? "(none)")
        }
        try await store.close()
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
