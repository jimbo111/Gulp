import Foundation
import GulpCore
import NIOConcurrencyHelpers
import Testing

@testable import GulpHTTP

// F03 §3.4 (GOV-002, GOV-003, GOV-007) and the engine side of the panic stop (F20 GOV-001).

@Suite("Shared limiter (GOV-002/003/007, GOV-001)", .serialized)
struct ResourcePoolTests {
    /// A server that answers only once `open` is set; until then requests hang (they stay in flight).
    static func gatedServer(_ open: NIOLockedValueBox<Bool>) async throws -> TestServer {
        try await TestServer.start { received, _ in
            guard headersComplete(received), open.withLockedValue({ $0 }) else { return nil }
            return ok("done")
        }
    }

    func fuzzerOptions(timeout: Int = 10) -> SendOptions {
        var options = SendOptions(recordAs: .fuzzer)
        options.timeouts.total = .seconds(timeout)
        return options
    }

    func waitUntil(_ condition: @escaping () async -> Bool) async {
        for _ in 0..<200 where !(await condition()) { try? await Task.sleep(for: .milliseconds(10)) }
    }

    @Test("GOV-002/003: global and per-host concurrency caps hold across tools; ungoverned sends are exempt")
    func test_GOV002_GOV003_caps() async throws {
        let open = NIOLockedValueBox(false)
        let server = try await Self.gatedServer(open)
        let engine = NIOHTTPEngine()
        await engine.resources.set(ConcurrencyLimits(global: 6, perHost: 4, adaptiveBackoff: false))
        let hostA = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        let hostB = HTTPTarget(scheme: .http, host: "localhost", port: server.port)
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        let options = fuzzerOptions()
        var scanner = SendOptions(recordAs: .scanner)
        scanner.timeouts.total = .seconds(10)
        let all = Task {
            await withTaskGroup(of: Int?.self) { group in
                for index in 0..<16 {
                    // Two "tools" (Fuzzer, Scanner) on two hosts.
                    let target = index % 2 == 0 ? hostA : hostB
                    let opts = index % 4 < 2 ? options : scanner
                    group.addTask {
                        await engine.send(request, to: target, options: opts).exchange.response?.parsed
                            .statusCode
                    }
                }
                return await group.reduce(into: []) { $0.append($1) }
            }
        }
        await waitUntil { await engine.resources.inFlightCount.global == 6 }
        try await Task.sleep(for: .milliseconds(150))
        let now = await engine.resources.inFlightCount
        #expect(now.global == 6)
        #expect(now.byHost.values.allSatisfy { $0 <= 4 })
        // The user's own traffic doesn't wait for the budget.
        var repeater = SendOptions(recordAs: .repeater)
        repeater.timeouts.total = .milliseconds(300)
        let own = await engine.send(request, to: hostA, options: repeater)
        #expect(own.error == .totalTimeout)  // it was sent (and hung like the others), not queued
        open.withLockedValue { $0 = true }
        await engine.resources.pause()  // cut the hung ones; they re-send and now get answers
        await engine.resources.resume()
        let statuses = await all.value
        #expect(statuses.count == 16 && statuses.allSatisfy { $0 == 200 })
        let peaks = await engine.resources.peaks
        #expect(peaks.global == 6 && peaks.byHost.values.allSatisfy { $0 <= 4 })
        await engine.shutdown()
        await server.stop()
    }

    @Test("GOV-003: a per-host cap of 0 blocks the host for active tools only")
    func test_GOV003_blocked() async throws {
        let server = try await TestServer.start { received, _ in headersComplete(received) ? ok("hi") : nil }
        let engine = NIOHTTPEngine()
        await engine.resources.set(ConcurrencyLimits(hosts: ["127.0.0.1": 0]))
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        let blocked = await engine.send(request, to: server.target, options: fuzzerOptions())
        #expect(blocked.error?.code == "other" && server.connections == 0)
        let mine = await engine.send(request, to: server.target, options: SendOptions(recordAs: .repeater))
        #expect(mine.exchange.response?.parsed.statusCode == 200)
        await engine.shutdown()
        await server.stop()
    }

    @Test("F20 GOV-001: pausing cuts every in-flight governed send at once; resume re-sends them")
    func test_GOV001_panic() async throws {
        let open = NIOLockedValueBox(false)
        let server = try await Self.gatedServer(open)
        let engine = NIOHTTPEngine()
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        let options = fuzzerOptions()
        let target = server.target
        let all = Task {
            await withTaskGroup(of: Int?.self) { group in
                for _ in 0..<8 {
                    group.addTask {
                        await engine.send(request, to: target, options: options).exchange.response?.parsed
                            .statusCode
                    }
                }
                return await group.reduce(into: []) { $0.append($1) }
            }
        }
        await waitUntil { await engine.resources.inFlightCount.global == 8 }
        let started = ContinuousClock.now
        #expect(await engine.resources.pause() == 8)
        await waitUntil { await engine.resources.inFlightCount.global == 0 }
        #expect(await engine.resources.inFlightCount.global == 0)
        #expect(ContinuousClock.now - started < .milliseconds(500))
        // Paused: a new governed send waits instead of going out.
        let late = Task {
            await engine.send(request, to: target, options: options).exchange.response?.parsed.statusCode
        }
        try await Task.sleep(for: .milliseconds(200))
        #expect(await engine.resources.inFlightCount.global == 0)
        open.withLockedValue { $0 = true }
        await engine.resources.resume()
        #expect(await all.value.allSatisfy { $0 == 200 })
        #expect(await late.value == 200)
        await engine.shutdown()
        await server.stop()
    }

    @Test("GOV-007: a burst of 503s halves the host's rate; runs of good responses restore it")
    func test_GOV007_backoff() async throws {
        let throttle = Throttle()
        let pool = ResourcePool(throttle: throttle)
        let t0 = ContinuousClock.now
        // 20 responses within a second: the observed rate is 20/s; 5 of them are 503s.
        var change: ResourcePool.BackoffChange?
        for index in 0..<20 {
            let outcome: ResourcePool.Outcome = index >= 15 ? .status(503) : .status(200)
            if let next = await pool.observe("lab", outcome, now: t0 + .milliseconds(index * 40)) {
                change = next
            }
        }
        #expect(change == .init(rate: 10))
        #expect(await pool.throttledHosts.first?.rate == 10)
        // Within a second of the step nothing changes; after it, 10 good responses double the rate.
        var later = t0 + .milliseconds(1_000)
        for _ in 0..<10 {
            later = later + .milliseconds(50)
            change = await pool.observe("lab", .status(200), now: later)
        }
        #expect(change == .init(rate: 20) || change == nil)
        later = later + .seconds(1)
        for _ in 0..<10 {
            later = later + .milliseconds(50)
            if let next = await pool.observe("lab", .status(200), now: later) { change = next }
        }
        #expect(change == .init(rate: nil))  // back at the original rate: no longer throttled
        #expect(await pool.throttledHosts.isEmpty)
        // Timeouts count; other failures don't.
        for index in 0..<5 { _ = await pool.observe("slow", .timeout, now: later + .milliseconds(index)) }
        #expect(await pool.throttledHosts.map(\.host) == ["slow"])
        for index in 0..<10 { _ = await pool.observe("other", .other, now: later + .milliseconds(index)) }
        #expect(!(await pool.throttledHosts.map(\.host).contains("other")))
    }

    @Test("GOV-007: the throttle holds governed sends (only) to a backoff rate")
    func test_GOV007_throttle() async {
        let throttle = Throttle()
        await throttle.setBackoff("lab", rate: 10)
        let now = ContinuousClock.now
        #expect(await throttle.reserve(host: "lab", now: now, governed: true) == .zero)
        #expect(await throttle.reserve(host: "lab", now: now, governed: true) == .milliseconds(100))
        #expect(await throttle.reserve(host: "lab", now: now, governed: false) == .zero)
        await throttle.setBackoff("lab", rate: nil)
        #expect(await throttle.reserve(host: "lab", now: now, governed: true) == .zero)
    }
}
