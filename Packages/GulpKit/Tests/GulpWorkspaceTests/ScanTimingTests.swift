import Foundation
import GulpCore
import GulpHTTP
import GulpProxy
import GulpScanner
import Testing

@testable import GulpWorkspace

@Suite("Scanner probe timing (F08 SCN-032)", .serialized)
struct ScanTimingTests {
    @Test("SCN-032: a probe's seconds are wire time, not the throttle wait before the send")
    func test_SCN032_probeTimeExcludesThrottleWait() async throws {
        let environment = isolatedEnvironment()
        let session = try await open(environment, "timing")
        // The project's own proxy listener answers an origin-form request at once (a 400 page).
        try await session.settings.set(
            ProxySettings(listeners: [ProxyListenerConfig(port: 0)]), scope: .project)
        let port = try #require(await session.startProxyListeners().values.compactMap { try? $0.get() }.first)
        // Two requests a second: every send after the first waits about 0.5 s in the throttle.
        await session.http.throttle.set(ThrottleLimits(hosts: ["127.0.0.1": 2]))
        let send = await session.scanSender()
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: port)
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\n\r\n"))
        let started = ContinuousClock.now
        var seconds: [Double] = []
        for _ in 0..<3 { seconds.append(await send(request, target).seconds) }
        #expect(ContinuousClock.now - started >= .milliseconds(900), "the throttle held the sends back")
        #expect(seconds.allSatisfy { $0 < 0.3 }, "\(seconds)")
        try await session.close()
    }
}
