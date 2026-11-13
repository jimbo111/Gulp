// GulpBrowser — launching a browser for CDP automation (F16 BRW-005). The launch flags and the
// `DevToolsActivePort` parsing are pure and tested on Linux; connecting the CDP WebSocket and driving
// a target needs a real browser, so that runs in a browser-capable environment (the macOS app, or a
// CI runner with Chromium). Kept separate from the one-click launcher (BRW-001…004), which predates
// the CDP client.

import Foundation
import GulpCore
import GulpHTTP

/// Browser automation over CDP.
public enum BrowserAutomation {
    /// The flags that start a Chromium with an automation endpoint on a free port, an isolated
    /// profile and the Gulp CA pinned. `debugPort` 0 asks the browser to pick a free port (read back
    /// from the profile's `DevToolsActivePort` file).
    public static func launchArguments(
        profile: URL, spkiPin: String?, proxy: String?, headless: Bool, debugPort: Int = 0
    ) -> [String] {
        var arguments = [
            "--remote-debugging-port=\(debugPort)",
            "--user-data-dir=\(profile.path)",
            "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
        ]
        if headless { arguments += ["--headless=new", "--no-sandbox", "--disable-gpu"] }
        if let proxy { arguments.append("--proxy-server=\(proxy)") }
        if let spkiPin { arguments.append("--ignore-certificate-errors-spki-list=\(spkiPin)") }
        return arguments
    }

    /// Build the browser's CDP WebSocket URL from a profile's `DevToolsActivePort` file (line 1 is the
    /// port, line 2 the `/devtools/browser/<id>` path).
    public static func devToolsEndpoint(fromPortFile contents: String, host: String = "127.0.0.1") -> URL? {
        let lines = contents.split(whereSeparator: \.isNewline).map(String.init)
        guard let first = lines.first, let port = Int(first.trimmingCharacters(in: .whitespaces)),
            (1...65535).contains(port)
        else { return nil }
        let pathPart = lines.count > 1 ? lines[1].trimmingCharacters(in: .whitespaces) : "/devtools/browser"
        let path = pathPart.hasPrefix("/") ? pathPart : "/\(pathPart)"
        return URL(string: "ws://\(host):\(port)\(path)")
    }

    /// Launch `executable` with the automation flags and wait (up to `timeout` seconds) for its
    /// `DevToolsActivePort` file, returning the running process and the CDP endpoint. Needs a real
    /// browser; the flags and the endpoint parsing are what the tests cover.
    public static func launch(
        executable: URL, profile: URL, spkiPin: String? = nil, proxy: String? = nil, headless: Bool = true,
        timeout: Double = 15
    ) throws -> (process: Process, endpoint: URL) {
        let fileManager = FileManager.default
        try? fileManager.createDirectory(at: profile, withIntermediateDirectories: true)
        let process = Process()
        process.executableURL = executable
        process.arguments = launchArguments(
            profile: profile, spkiPin: spkiPin, proxy: proxy, headless: headless)
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        let portFile = profile.appendingPathComponent("DevToolsActivePort")
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let contents = try? String(contentsOf: portFile, encoding: .utf8),
                let endpoint = devToolsEndpoint(fromPortFile: contents)
            {
                return (process, endpoint)
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        process.terminate()
        throw GulpError(message: "The browser did not expose a DevTools endpoint within \(timeout)s.")
    }

    /// Open a CDP client to a browser endpoint through Gulp's engine (ungoverned, direct to localhost).
    public static func connect(to endpoint: URL, engine: NIOHTTPEngine) async throws -> CDPClient {
        guard let host = endpoint.host, let port = endpoint.port else {
            throw GulpError(message: "Bad DevTools endpoint \(endpoint).")
        }
        let path = endpoint.path.isEmpty ? "/" : endpoint.path
        let upgrade = RawRequest(
            Bytes(
                "GET \(path) HTTP/1.1\r\nHost: \(host):\(port)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: \(Self.nonce())\r\n\r\n"))
        let session = try await engine.openWebSocket(
            upgrade, to: HTTPTarget(scheme: .http, host: host, port: port),
            options: SendOptions(recordAs: .automation))
        let client = CDPClient(transport: WebSocketCDPTransport(session: session))
        await client.start()
        return client
    }

    static func nonce() -> String {
        Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
    }
}
