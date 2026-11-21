// GulpExtensions — the production transport for an out-of-process extension: the child's stdin/stdout
// (F18 EXT-002). Launch the command from the manifest, write framed JSON-RPC to its stdin and read its
// stdout. `Process`-based, so it works wherever the interpreter the extension needs is installed.

import Foundation

/// Carries JSON-RPC frames over a child process's stdio.
public final class ProcessExtensionTransport: ExtensionTransport, @unchecked Sendable {
    // @unchecked: the pipes and process are only used from the methods below; `Process`/`Pipe` are the
    // standard way to drive a child and are internally synchronized.
    private let process = Process()
    private let inPipe = Pipe()
    private let outPipe = Pipe()

    /// Launch `command` (argv; first element is the executable). Throws if it can't start.
    public init(command: [String], workingDirectory: URL? = nil) throws {
        guard let executable = command.first else {
            throw ExtensionError.malformed
        }
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = Array(command.dropFirst())
        process.standardInput = inPipe
        process.standardOutput = outPipe
        process.standardError = FileHandle.nullDevice
        if let workingDirectory { process.currentDirectoryURL = workingDirectory }
        try process.run()
    }

    /// Writes `bytes` to the child's stdin.
    public func send(_ bytes: [UInt8]) async throws {
        try inPipe.fileHandleForWriting.write(contentsOf: Data(bytes))
    }

    /// Delivers stdout data to `onData` as it arrives; returns when the child closes stdout.
    public func receiveLoop(_ onData: @Sendable @escaping ([UInt8]) -> Void) async {
        let handle = outPipe.fileHandleForReading
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            handle.readabilityHandler = { handle in
                let data = handle.availableData
                if data.isEmpty {
                    handle.readabilityHandler = nil
                    continuation.resume()
                } else {
                    onData([UInt8](data))
                }
            }
        }
    }

    /// Terminates the child if it is still running and closes its stdin.
    public func close() async {
        if process.isRunning { process.terminate() }
        try? inPipe.fileHandleForWriting.close()
    }
}
