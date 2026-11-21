import Foundation
import GulpCodec
import GulpCore
import Testing

@testable import GulpWorkspace

// AGENTS.md "Scope safety" / F04 TGT-023 for the project-backed tools that aren't the Scanner,
// Crawler or Fuzzer: nothing leaves the machine for an out-of-scope target unless the action
// carries an explicit override. Port 1 refuses connections, so a send that did go out is still
// recorded (an exchange with an error) and shows up in the store count.

@Suite("Scope safety in the workspace (TGT-023)")
struct ScopeSafetyTests {
    let lab = HTTPTarget(scheme: .http, host: "127.0.0.1", port: 1)

    @Test("ADV-042 / TGT-023: a GraphQL scan refuses an out-of-scope endpoint unless overridden")
    func test_TGT023_graphQLScanScope() async throws {
        let session = try await open(isolatedEnvironment(), "graphql-scope")
        // An empty scope refuses everything for an active tool.
        await #expect(throws: OutOfScope.self) {
            try await session.scanGraphQL(path: "/graphql", target: lab)
        }
        // An exclude rule holds, even for a host allowed with "don't ask again".
        try await session.setScope([
            ScopeRule(host: "127.0.0.1"), ScopeRule(kind: .exclude, host: "127.0.0.1", path: "^/graphql"),
        ])
        await session.allowOutOfScopeSends(to: "127.0.0.1")
        await #expect(throws: OutOfScope.self) {
            try await session.scanGraphQL(path: "/graphql", target: lab)
        }
        await session.store.writer.flush()
        #expect(try await session.store.count() == 0, "nothing was sent")
        _ = try await session.scanGraphQL(path: "/graphql", target: lab, allowOutOfScope: true)
        await session.store.writer.flush()
        #expect(try await session.store.count() == 1, "the override sends the introspection query")
        try await session.close()
    }

    @Test("ADV-040/041 / TGT-023: introspect and send are manual sends: out of scope needs the override")
    func test_TGT023_graphQLManualScope() async throws {
        let session = try await open(isolatedEnvironment(), "graphql-manual")
        try await session.addToScope(url: "http://elsewhere.test/")
        await #expect {
            try await session.introspectGraphQL(path: "/graphql", target: lab)
        } throws: { ($0 as? RPCServiceError)?.outOfScope == true }
        await #expect {
            try await session.sendGraphQL(GraphQLRequest(query: "{ a }"), path: "/graphql", target: lab)
        } throws: { ($0 as? RPCServiceError)?.outOfScope == true }
        await session.store.writer.flush()
        #expect(try await session.store.count() == 0, "nothing was sent")
        _ = try await session.introspectGraphQL(path: "/graphql", target: lab, allowOutOfScope: true)
        _ = try await session.sendGraphQL(
            GraphQLRequest(query: "{ a }"), path: "/graphql", target: lab, allowOutOfScope: true)
        await session.store.writer.flush()
        #expect(try await session.store.count() == 2)
        try await session.close()
    }
}
