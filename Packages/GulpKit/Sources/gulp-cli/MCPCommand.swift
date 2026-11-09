// gulp-cli — `mcp` (F21 AUT-020): run Gulp's MCP server over stdio against a project, for local AI
// clients. Register it with Claude Code:
//     claude mcp add gulp -- gulp-cli mcp --project /path/to/engagement.gulp --approval in-scope
// (without `--approval in-scope` the agent can read but not send).
// Standard output is the protocol; nothing else is printed there.

import ArgumentParser
import Foundation
import GulpAutomation
import GulpWorkspace

/// `gulp-cli mcp --project p.gulp`.
struct MCP: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Serve a project to MCP clients (e.g. Claude Code) over stdio.")

    @Option(help: "Project file (created if missing).")
    var project: String

    @Option(help: "Agent sends: deny (read-only, default) or in-scope (sent without asking when in scope).")
    var approval = "deny"

    func run() async throws {
        guard let policy = ApprovalPolicy(rawValue: approval), policy != .ask else {
            throw ValidationError("--approval must be in-scope or deny (\"ask\" needs the app to approve).")
        }
        let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
        FileHandle.standardError.write(
            Data("gulp-cli mcp: serving \(project) over stdio (\(policy.rawValue))\n".utf8))
        await MCPStdio.run(MCPServer(session: session, policy: policy, serverVersion: GulpCLI.version))
        try await session.close()
    }
}
