import GulpCore
import Testing

@testable import GulpHTTP

// F03 HTTP-013: the shared requests-per-second throttle.

@Suite("GulpHTTP — throttle (HTTP-013)")
struct ThrottleTests {
    @Test("HTTP-013: slots are reserved per host and globally; unlimited hosts pass at once")
    func test_HTTP013_reservations() async {
        let now = ContinuousClock.now
        let global = Throttle(ThrottleLimits(globalPerSecond: 10))
        var delays: [Duration] = []
        for _ in 0..<3 { delays.append(await global.reserve(host: "a", now: now)) }
        #expect(delays == [.zero, .milliseconds(100), .milliseconds(200)])

        let perHost = Throttle(ThrottleLimits(perHostPerSecond: 5, hosts: ["fast.test": 0, "slow.test": 1]))
        #expect(await perHost.reserve(host: "a.test", now: now) == .zero)
        #expect(await perHost.reserve(host: "a.test", now: now) == .milliseconds(200))
        #expect(await perHost.reserve(host: "b.test", now: now) == .zero)  // each host has its own schedule
        #expect(await perHost.reserve(host: "fast.test", now: now) == .zero)  // override: unlimited
        #expect(await perHost.reserve(host: "fast.test", now: now) == .zero)
        #expect(await perHost.reserve(host: "slow.test", now: now) == .zero)
        #expect(await perHost.reserve(host: "slow.test", now: now) == .seconds(1))
        // Later requests aren't penalised for earlier idle time.
        #expect(await perHost.reserve(host: "a.test", now: now + .seconds(5)) == .zero)
    }

    @Test("HTTP-013: the engine paces its sends")
    func test_HTTP013_enginePaces() async throws {
        let server = try await TestServer.start { received, _ in headersComplete(received) ? ok("ok") : nil }
        let engine = NIOHTTPEngine()
        await engine.throttle.set(ThrottleLimits(perHostPerSecond: 20))
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        var settings = SendOptions(recordAs: .repeater)
        settings.timeouts.total = .seconds(10)
        let options = settings
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        let started = ContinuousClock.now
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<5 { group.addTask { _ = await engine.send(request, to: target, options: options) } }
        }
        #expect(ContinuousClock.now - started >= .milliseconds(190))  // 4 gaps of 50 ms
        await engine.throttle.set(.none)
        // No limits: no slot is ever reserved (checked on the schedule itself; wall-clock bounds
        // are unreliable under a parallel test run), and sends still go through promptly.
        let now = ContinuousClock.now
        for _ in 0..<5 { #expect(await engine.throttle.reserve(host: "127.0.0.1", now: now) == .zero) }
        let unthrottled = ContinuousClock.now
        for _ in 0..<5 { _ = await engine.send(request, to: target, options: options) }
        #expect(ContinuousClock.now - unthrottled < .seconds(2))
        await engine.shutdown()
        await server.stop()
    }
}
