// gulp-cli — headless entry point for Gulp. M1 ships `send`; scan/proxy/project commands arrive
// with the automation surface (M17, docs/features/F21-automation.md).

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP

/// Version marker for the Gulp command-line tool.
enum GulpCLI {
    /// Semantic version of the CLI; bumped as the tool gains commands.
    static let version = "0.1.0"
}

/// The root command. `@main` (in a file not named main.swift) is how ArgumentParser runs an async
/// command; calling `main()` from top-level code picks the synchronous entry point, which refuses.
@main
struct GulpCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "gulp-cli", abstract: "Gulp, headless.", version: GulpCLI.version,
        subcommands: [Send.self])
}

/// `gulp-cli send --raw request.txt --target http://host:port` writes the file's bytes exactly as
/// they are (HTTP-001) and prints the exact response bytes, interim 1xx responses included.
struct Send: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Send a raw HTTP/1 request and print the exact response bytes.")

    @Option(help: "File holding the exact request bytes to send.")
    var raw: String

    @Option(help: "Where to connect, e.g. http://127.0.0.1:8088 (only scheme, host and port are used).")
    var target: String

    @Flag(help: "Recompute Content-Length from the body before sending (HTTP-008).")
    var updateContentLength = false

    @Option(help: "Total timeout in seconds.")
    var timeout = 30

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
        let engine = NIOHTTPEngine()
        let result = await engine.send(RawRequest(Bytes([UInt8](data))), to: destination, options: options)
        await engine.shutdown()
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
}
