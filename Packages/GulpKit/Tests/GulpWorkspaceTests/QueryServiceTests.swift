import Foundation
import GulpCore
import GulpProxy
import GulpQuery
import GulpStore
import Testing

@testable import GulpWorkspace

@Suite("GulpQL in the workspace: queries, saved filters, Logger (HIS-020, 026, 040, 041)")
struct QueryServiceTests {
    func record(
        _ session: ProjectSession, _ path: String, _ status: Int, _ source: ToolSource, host: String = "lab"
    )
        async -> ExchangeID
    {
        await session.store.writer.record(
            Exchange(
                source: source, target: HTTPTarget(scheme: .http, host: host),
                request: RawRequest(Bytes("GET \(path) HTTP/1.1\r\nHost: \(host)\r\n\r\n")),
                response: RawResponse(Bytes("HTTP/1.1 \(status) X\r\nContent-Length: 4\r\n\r\nbody")),
                state: .complete))
    }

    @Test("HIS-020: session queries use the project's scope; parse errors surface")
    func test_HIS020_sessionQuery() async throws {
        let session = try await open(isolatedEnvironment(), "query")
        let a = await record(session, "/a", 200, .proxy)
        let b = await record(session, "/b", 500, .repeater, host: "other")
        try await session.setScope([ScopeRule(host: "lab")])
        #expect(try await session.query("resp.status >= 500") == [b])
        #expect(try await session.query("matches_scope") == [a])
        #expect(try await session.query(#"resp.body contains "body" and not in_scope"#) == [b])
        #expect(try await session.query("") == [a, b])
        await #expect(throws: GulpQLError.self) { try await session.query("resp.statuz == 1") }
        try await session.close()
    }

    @Test("HIS-026: saved filters, recents, export and import")
    func test_HIS026_savedFilters() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "filters")
        try await session.saveFilter(name: "5xx", query: "resp.status >= 500")
        try await session.saveFilter(name: "api", query: #"req.host ~ "api""#)
        try await session.saveFilter(name: "5xx", query: "resp.status in 500..599")  // replaces by name
        await #expect(throws: GulpQLError.self) { try await session.saveFilter(name: "bad", query: "(") }
        #expect(await session.filterSettings().saved.map(\.name) == ["api", "5xx"])
        for query in ["a", "b", "a", "  "] { try await session.rememberFilter(query) }
        #expect(await session.filterSettings().recents == ["a", "b"])
        let shared = try await session.exportFilters()
        #expect(String(decoding: shared, as: UTF8.self).contains(#""query" : "req.host ~ \"api\"""#))
        try await session.close()

        // Saved filters are user-level: another project sees them; importing adds only new ones.
        let other = try await open(environment, "other")
        #expect(await other.filterSettings().saved.count == 2)
        let incoming = Data(
            (#"{"gulpFilters":1,"filters":[{"name":"api","query":"req.host ~ \"api\""},"#
                + #"{"name":"api","query":"source == proxy"},{"name":"broken","query":"(("}]}"#).utf8)
        #expect(try await other.importFilters(incoming) == 1)
        #expect(await other.filterSettings().saved.map(\.name) == ["api", "5xx", "api (2)"])
        try await other.close()
    }

    @Test("HIS-040/041: the Logger shows every tool through its own source set and filter")
    func test_HIS040_logger() async throws {
        let session = try await open(isolatedEnvironment(), "logger")
        let a = await record(session, "/a", 200, .proxy)
        let b = await record(session, "/b", 404, .repeater)
        let c = await record(session, "/c", 500, .fuzzer)
        #expect(try await session.loggerIDs() == [c, b, a])
        var settings = LoggerSettings()
        settings.sources = ["proxy", "Fuzzer"]
        try await session.setLoggerSettings(settings)
        #expect(try await session.loggerIDs() == [c, a])
        settings.query = "resp.status >= 400"
        try await session.setLoggerSettings(settings)
        #expect(try await session.loggerIDs() == [c])
        settings.query = "resp.status >="
        await #expect(throws: GulpQLError.self) { try await session.setLoggerSettings(settings) }
        #expect(await session.loggerSettings().query == "resp.status >= 400")
        try await session.close()
    }

    @Test(
        "F05 acceptance 4 / HIS-027: one expression drives a Logger filter and an intercept rule identically")
    func test_HIS027_sameExpression() async throws {
        let session = try await open(isolatedEnvironment(), "same")
        try await session.setScope([ScopeRule(host: "lab")])
        let expression =
            #"req.path startswith "/api" and not req.method == GET and (in_scope or req.query contains "force")"#
        let requests: [(String, String, String)] = [
            ("POST", "/api/order", "lab"), ("GET", "/api/order", "lab"), ("PUT", "/api/x?force=1", "other"),
            ("DELETE", "/api/x", "other"), ("POST", "/home", "lab"), ("PATCH", "/api", "lab"),
        ]
        var ids: [ExchangeID] = []
        for (method, path, host) in requests {
            ids.append(
                await session.store.writer.record(
                    Exchange(
                        source: .proxy, target: HTTPTarget(scheme: .http, host: host),
                        request: RawRequest(Bytes("\(method) \(path) HTTP/1.1\r\nHost: \(host)\r\n\r\n")),
                        state: .complete)))
        }
        var logger = LoggerSettings()
        logger.query = expression
        try await session.setLoggerSettings(logger)
        let logged = Set(try await session.loggerIDs())

        var intercept = InterceptSettings()
        intercept.interceptRequests = true
        intercept.requestQuery = expression
        try await session.setInterceptSettings(intercept)
        var held: Set<ExchangeID> = []
        for (index, (method, path, host)) in requests.enumerated() {
            let request = RawRequest(Bytes("\(method) \(path) HTTP/1.1\r\nHost: \(host)\r\n\r\n"))
            if try await holdsRequest(session.intercept, request, HTTPTarget(scheme: .http, host: host)) {
                held.insert(ids[index])
            }
        }
        #expect(logged == held && logged == [ids[0], ids[2], ids[5]])

        intercept.requestQuery = "req.method =="
        await #expect(throws: GulpQLError.self) { try await session.setInterceptSettings(intercept) }
        try await session.close()
    }
}

/// Whether `queue` holds `request` (a held request is forwarded right away).
func holdsRequest(_ queue: InterceptQueue, _ request: RawRequest, _ target: HTTPTarget) async throws -> Bool {
    let decision = Task { await queue.holdRequest(request, target: target).held }
    for _ in 0..<100 {
        if await !queue.items.isEmpty {
            await queue.decideAll(.forward(nil))
            break
        }
        try await Task.sleep(for: .milliseconds(2))
    }
    return await decision.value
}
