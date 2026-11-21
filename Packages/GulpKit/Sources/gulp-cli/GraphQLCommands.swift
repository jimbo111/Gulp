// gulp-cli — the GraphQL Workbench headless (F23 §5, M13b): `graphql introspect` introspects an
// endpoint and prints the schema; `graphql scan` runs the security checks (introspection exposed,
// broken object/field authorization) and raises issues.

import ArgumentParser
import Foundation
import GulpCodec
import GulpCore
import GulpWorkspace

struct GraphQLCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "graphql",
        abstract: "GraphQL Workbench: introspect and scan a GraphQL endpoint (F23 §5).",
        subcommands: [Introspect.self, Scan.self])

    struct Introspect: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Introspect an endpoint and print its schema.")
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "Endpoint URL, e.g. http://127.0.0.1:8088/graphql.") var url: String
        @Flag(help: "Send even when the endpoint is out of scope (explicit override).")
        var allowOutOfScope = false

        func run() async throws {
            guard let target = HTTPTarget(url: url), let parsed = URL(string: url) else {
                throw ValidationError("Invalid --url")
            }
            let path = parsed.path.isEmpty ? "/graphql" : parsed.path
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            let result = try await session.introspectGraphQL(
                path: path, target: target, allowOutOfScope: allowOutOfScope)
            if let schema = result.schema {
                print("graphql: introspection ENABLED")
                print(schema.render())
            } else {
                print("graphql: introspection disabled or not a GraphQL endpoint")
            }
            try await session.close()
        }
    }

    struct Scan: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Run GraphQL security checks (introspection exposed, broken object/field authz).")
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "Endpoint URL, e.g. http://127.0.0.1:8088/graphql.") var url: String
        @Option(help: "A probe query that should be denied but returns sensitive data when authz is broken.")
        var probe: String?
        @Option(help: "A marker whose presence in the probe's response proves the authz bug (e.g. an email).")
        var marker: String?
        @Flag(help: "Scan even when the endpoint is out of scope (explicit override).")
        var allowOutOfScope = false

        func run() async throws {
            guard let target = HTTPTarget(url: url), let parsed = URL(string: url) else {
                throw ValidationError("Invalid --url")
            }
            let path = parsed.path.isEmpty ? "/graphql" : parsed.path
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            let probeRequest = probe.map { GraphQLRequest(query: $0) }
            let raised = try await session.scanGraphQL(
                path: path, target: target, authzProbe: probeRequest, sensitiveMarker: marker,
                allowOutOfScope: allowOutOfScope)
            print("graphql: \(raised.count) issue(s) raised")
            for issue in try await session.store.issues() where issue.typeID.hasPrefix("graphql.") {
                print("  \(issue.typeID)\t\(issue.host)\(issue.path)")
            }
            try await session.close()
        }
    }
}
