import Foundation
import GulpCore
import GulpHTTP
import Testing

@testable import GulpFuzzer

// F07 FUZ-004, FUZ-014, FUZ-030, FUZ-031: the attack runner, against an in-process fake engine.

/// Answers from the request bytes; counts sends.
final class FakeEngine: HTTPEngine, @unchecked Sendable {
    // `lock` guards `calls` and `requests`; everything else is immutable.
    private let lock = NSLock()
    private var calls = 0
    private var requests: [String] = []
    let reply: @Sendable (String, Int) -> (status: Int, body: String)?

    init(reply: @escaping @Sendable (String, Int) -> (status: Int, body: String)?) {
        self.reply = reply
    }

    var sendCount: Int { lock.withLock { calls } }
    var sent: [String] { lock.withLock { requests } }

    func send(_ request: RawRequest, to target: HTTPTarget, options: SendOptions) async -> ExchangeResult {
        let text = request.bytes.string()
        let call = lock.withLock {
            calls += 1
            requests.append(text)
            return calls
        }
        var exchange = Exchange(
            id: Int64(call), source: options.recordAs, target: target, request: request, state: .complete)
        exchange.timing.totalMs = 1
        guard let answer = reply(text, call) else {
            return ExchangeResult(exchange: exchange, error: .connectionRefused)
        }
        exchange.response = RawResponse(
            Bytes(
                "HTTP/1.1 \(answer.status) X\r\nContent-Length: \(answer.body.utf8.count)\r\n\r\n\(answer.body)"
            ))
        return ExchangeResult(exchange: exchange)
    }

    func send(_ request: H2RequestSpec, to target: HTTPTarget, options: SendOptions) async -> ExchangeResult {
        ExchangeResult(
            exchange: Exchange(source: .fuzzer, target: target, request: RawRequest(Bytes(""))),
            error: .cancelled)
    }

    func sendGroup(_ items: [GroupItem], mode: GroupSendMode, options: SendOptions) async -> [ExchangeResult]
    { [] }

    func openWebSocket(_ upgrade: RawRequest, to target: HTTPTarget, options: SendOptions) async throws
        -> WebSocketSession
    {
        throw GulpError(message: "not in tests")
    }

    func negotiatedProtocol(for target: HTTPTarget, options: SendOptions) async -> String? { nil }
}

func collect(_ attack: FuzzAttack) async -> (results: [FuzzResult], summary: FuzzSummary?) {
    var results: [FuzzResult] = []
    var summary: FuzzSummary?
    for await event in await attack.start() {
        switch event {
        case .result(let result): results.append(result)
        case .finished(let done): summary = done
        }
    }
    return (results, summary)
}

let lab = HTTPTarget(scheme: .http, host: "lab", port: 8088)

@Suite("GulpFuzzer — attack runner (FUZ-004, FUZ-014, FUZ-030, FUZ-031)")
struct FuzzAttackTests {
    func config(
        _ request: String, _ type: AttackType, _ sets: [PayloadSet],
        _ settings: FuzzSettings = FuzzSettings(),
        matches: [GrepMatch] = [], extracts: [GrepExtract] = []
    ) -> FuzzAttackConfig {
        FuzzAttackConfig(
            name: "t", target: lab, request: Array(request.utf8), attackType: type, sets: sets,
            matches: matches,
            extracts: extracts, settings: settings)
    }

    @Test("F07 acceptance 2: a 10×10 cluster bomb runs every pair concurrently and finds the valid one")
    func test_FUZ002_clusterBomb() async throws {
        let engine = FakeEngine { request, _ in
            request.contains("u=alice&p=7") ? (302, "welcome") : (200, "Invalid credentials")
        }
        var settings = FuzzSettings()
        settings.concurrency = 8
        let users = PayloadSet(.list((0..<10).map { $0 == 3 ? "alice" : "user\($0)" }))
        let passwords = PayloadSet(.numbers(from: 0, to: 9, step: 1, minDigits: 0, hex: false))
        let attack = try FuzzAttack(
            config: config(
                "POST /login HTTP/1.1\r\nHost: lab\r\n\r\nu=§x§&p=§y§", .clusterBomb, [users, passwords],
                settings,
                matches: [GrepMatch("Invalid credentials")]),
            engine: engine, inScope: nil)
        let (results, summary) = await collect(attack)
        #expect(results.count == 100 && Set(results.map(\.seq)) == Set(1...100) && summary?.sent == 100)
        let hits = results.filter { $0.status == 302 }
        #expect(
            hits.count == 1 && hits.first?.payloads == ["alice", "7"]
                && hits.first?.findings.matches == [false])
        #expect(results.filter { $0.findings.matches == [true] }.count == 99)
    }

    @Test("FUZ-030: the requests-per-second cap is honoured; delays apply")
    func test_FUZ030_rateLimit() async throws {
        let engine = FakeEngine { _, _ in (200, "ok") }
        var settings = FuzzSettings()
        settings.concurrency = 10
        settings.requestsPerSecond = 100
        let attack = try FuzzAttack(
            config: config("GET /§a§ HTTP/1.1\r\n\r\n", .sniper, [PayloadSet(.null(count: 21))], settings),
            engine: engine, inScope: nil)
        let started = ContinuousClock.now
        let (results, summary) = await collect(attack)
        let elapsed = ContinuousClock.now - started
        #expect(results.count == 21)
        #expect(elapsed >= .milliseconds(190), "21 requests at 100/s take ≥ 200 ms (took \(elapsed))")
        #expect((summary?.rate ?? 1_000) <= 115)
    }

    @Test("FUZ-031: stop on a grep match, stop after N errors, retries")
    func test_FUZ031_stopAndRetry() async throws {
        let found = FakeEngine { request, _ in request.contains("/42 ") ? (200, "FLAG{x}") : (404, "no") }
        var stop = FuzzSettings()
        stop.concurrency = 1
        stop.stopOnGrepMatch = true
        let attack = try FuzzAttack(
            config: config(
                "GET /§n§ HTTP/1.1\r\n\r\n", .sniper,
                [PayloadSet(.numbers(from: 1, to: 1_000, step: 1, minDigits: 0, hex: false))],
                stop, matches: [GrepMatch("FLAG\\{", isRegex: true)]),
            engine: found, inScope: nil)
        let (results, summary) = await collect(attack)
        #expect(summary?.stopReason == "grep match" && results.count == 42 && found.sendCount == 42)

        let failing = FakeEngine { _, _ in nil }
        var errors = FuzzSettings()
        errors.concurrency = 1
        errors.stopAfterErrors = 5
        let failed = try FuzzAttack(
            config: config("GET /§n§ HTTP/1.1\r\n\r\n", .sniper, [PayloadSet(.null(count: 100))], errors),
            engine: failing, inScope: nil)
        let (failedResults, failedSummary) = await collect(failed)
        #expect(
            failedSummary?.stopReason == "errors" && failedResults.count == 5
                && failedResults.allSatisfy { $0.error == "connection_refused" })

        // Every first attempt fails; one retry succeeds.
        let flaky = FakeEngine { _, call in call.isMultiple(of: 2) ? (200, "ok") : nil }
        var retry = FuzzSettings()
        retry.concurrency = 1
        retry.retries = 1
        let retried = try FuzzAttack(
            config: config("GET /§n§ HTTP/1.1\r\n\r\n", .sniper, [PayloadSet(.null(count: 10))], retry),
            engine: flaky, inScope: nil)
        let (retriedResults, _) = await collect(retried)
        #expect(
            retriedResults.count == 10 && retriedResults.allSatisfy { $0.error == nil }
                && flaky.sendCount == 20)
    }

    @Test("FUZ-014 / F07 acceptance 3: recursive grep feeds each response's CSRF token into the next request")
    func test_FUZ014_recursiveGrep() async throws {
        let engine = FakeEngine { _, call in (200, #"<input name="csrf" value="tok\#(call)">"#) }
        var settings = FuzzSettings()
        settings.concurrency = 8  // forced to 1 by the recursive set
        let attack = try FuzzAttack(
            config: config(
                "POST /login HTTP/1.1\r\n\r\ncsrf=§t§&u=§u§", .pitchfork,
                [
                    PayloadSet(.recursiveGrep(extractIndex: 0, initial: "first", count: 5)),
                    PayloadSet(.list(["a", "b", "c", "d", "e"])),
                ],
                settings, extracts: [.between(start: #"value=""#, end: "\"")]),
            engine: engine, inScope: nil)
        let (results, _) = await collect(attack)
        #expect(results.map { $0.payloads[0] } == ["first", "tok1", "tok2", "tok3", "tok4"])
        #expect(results.map { $0.findings.extracts[0] } == ["tok1", "tok2", "tok3", "tok4", "tok5"])
        #expect(engine.sent[1].hasSuffix("csrf=tok1&u=b"))
    }

    @Test("ScopeGuard: out-of-scope requests are reported, not sent; pause and resume; CSV export")
    func test_FUZ030_scopePause() async throws {
        let engine = FakeEngine { _, _ in (200, "ok") }
        let attack = try FuzzAttack(
            config: config(
                "GET /§p§ HTTP/1.1\r\n\r\n", .sniper, [PayloadSet(.list(["app/a", "admin", "app/b"]))]),
            engine: engine, inScope: { _, path in path.hasPrefix("/app") })
        let (results, _) = await collect(attack)
        #expect(results.count == 3 && engine.sendCount == 2)
        #expect(results.first { $0.payloads == ["admin"] }?.error == "out_of_scope")

        let slow = FakeEngine { _, _ in (200, "ok") }
        var settings = FuzzSettings()
        settings.concurrency = 1
        settings.delayMs = 5
        let paused = try FuzzAttack(
            config: config("GET /§p§ HTTP/1.1\r\n\r\n", .sniper, [PayloadSet(.null(count: 40))], settings),
            engine: slow, inScope: nil)
        let stream = await paused.start()
        await paused.pause()
        try await Task.sleep(for: .milliseconds(150))
        let whilePaused = slow.sendCount
        try await Task.sleep(for: .milliseconds(100))
        #expect(slow.sendCount == whilePaused && whilePaused < 40)
        await paused.resume()
        var count = 0
        for await event in stream { if case .result = event { count += 1 } }
        #expect(count == 40)

        let csv = fuzzResultsCSV(
            results, config: config("§a§", .sniper, [PayloadSet(.list(["x"]))], matches: [GrepMatch("ok")]))
        #expect(csv.hasPrefix("#,payloads,status,length,ms,error,match: ok,reflected\r\n"))
    }
}
