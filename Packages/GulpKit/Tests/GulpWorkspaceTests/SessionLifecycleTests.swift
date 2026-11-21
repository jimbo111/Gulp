import Foundation
import GulpCore
import GulpFuzzer
import GulpHTTP
import GulpStore
import Testing

@testable import GulpWorkspace

// Project lifecycle (F20 PRJ-002, GOV-001): work in flight during Save As and close goes to the file
// the session uses now, and close() stops active tools before the engine and the store shut down.

@Suite("Project lifecycle: Save As and close with work in flight (PRJ-002, GOV-001)", .serialized)
struct SessionLifecycleTests {
    @Test("PRJ-002: a response that completes during Save As's copy lands in the new file")
    func test_PRJ002_updateDuringSaveAsCopy() async throws {
        let environment = isolatedEnvironment()
        let old = try ProjectStore.open(at: projectURL(environment, "old"))
        let recorder = ProjectRecorder(store: old)
        var exchange = Exchange(
            source: .proxy, target: HTTPTarget(scheme: .http, host: "a"),
            request: RawRequest(Bytes("GET / HTTP/1.1\r\nHost: a\r\n\r\n")))
        exchange.id = await recorder.record(exchange)
        await recorder.pause()
        let copy = projectURL(environment, "copy")
        try await old.backup(to: copy)  // Save As copies the file…
        exchange.response = RawResponse(Bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        exchange.state = .complete
        await recorder.update(exchange)  // …while the response completes.
        let new = try ProjectStore.open(at: copy)
        await recorder.resume(with: new)
        await new.writer.flush()
        #expect(try await new.exchange(id: exchange.id)?.response != nil)
        try await old.close()
        try await new.close()
    }
}
