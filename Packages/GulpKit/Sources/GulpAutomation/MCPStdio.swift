// GulpAutomation — the MCP stdio transport (F21 AUT-020): newline-delimited JSON-RPC on standard
// input and output, as local clients such as Claude Code launch servers (`claude mcp add gulp --
// gulp-cli mcp --project p.gulp`). Standard output carries protocol messages only; diagnostics go
// to standard error. Messages are handled one at a time, in order.

import Foundation

/// Runs an `MCPServer` over standard input/output until input ends.
public enum MCPStdio {
    /// Serve until standard input is closed.
    public static func run(_ server: MCPServer) async {
        let lines = AsyncStream<String> { continuation in
            // `readLine` blocks, so it runs on its own thread, not the cooperative pool.
            let thread = Thread {
                while let line = readLine(strippingNewline: true) { continuation.yield(line) }
                continuation.finish()
            }
            thread.start()
        }
        for await line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            if let reply = await server.handle(Data(trimmed.utf8)) {
                FileHandle.standardOutput.write(reply + Data("\n".utf8))
            }
        }
    }
}
