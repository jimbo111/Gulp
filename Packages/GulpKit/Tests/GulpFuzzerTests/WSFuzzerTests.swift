import Testing

@testable import GulpFuzzer

@Suite("WebSocket Fuzzer (F07 §2.6, WSX-002)")
struct WSFuzzerTests {
    /// A channel that echoes each message back as `echo: <message>` (like VulnLab's `/ws`).
    struct EchoChannel: WSFuzzChannel {
        func exchange(_ message: [UInt8]) async throws -> [UInt8]? {
            Array("echo: ".utf8) + message
        }
    }

    @Test("one socket, many payloads: grep, extract and reflection run on each reply")
    func test_WSX002_fuzzOverOneSocket() async throws {
        let config = WSFuzzConfig(
            template: Array("cmd=§x§".utf8),
            payloadSet: PayloadSet(.list(["alpha", "bravo", "INJECT"])),
            matches: [GrepMatch("INJECT")],
            extracts: [.regex(pattern: #"echo: cmd=(\w+)"#, group: 1)])
        let results = try await WSFuzzEngine(config).run(on: EchoChannel())

        #expect(results.count == 3)
        #expect(results.map(\.matches) == [[false], [false], [true]])
        #expect(results.map { $0.extracts[0] } == ["alpha", "bravo", "INJECT"])
        #expect(results.allSatisfy { $0.reflected == .raw })
        #expect(results[2].sent == "cmd=INJECT")
    }

    @Test("payload processors (prefix/suffix) are applied before sending")
    func test_WSX002_payloadProcessing() async throws {
        let config = WSFuzzConfig(
            template: Array("q=§x§".utf8),
            payloadSet: PayloadSet(.list(["ping"]), processors: [.prefix("<"), .suffix(">")]),
            matches: [GrepMatch("<ping>")])
        let results = try await WSFuzzEngine(config).run(on: EchoChannel())
        #expect(results.count == 1)
        #expect(results[0].sent == "q=<ping>")
        #expect(results[0].matches == [true])
    }

    @Test("stop-on-first-match ends the run at the first matching reply")
    func test_WSX002_stopOnFirstMatch() async throws {
        let config = WSFuzzConfig(
            template: Array("v=§x§".utf8),
            payloadSet: PayloadSet(.list(["a", "HIT", "c"])),
            matches: [GrepMatch("HIT")],
            stopOnFirstMatch: true)
        let results = try await WSFuzzEngine(config).run(on: EchoChannel())
        #expect(results.count == 2)
        #expect(results.last?.matches == [true])
    }

    @Test("a template with no positions is rejected")
    func test_WSX002_requiresPosition() {
        let config = WSFuzzConfig(template: Array("no markers".utf8), payloadSet: PayloadSet(.list(["x"])))
        #expect(throws: FuzzTemplateError.self) {
            try WSFuzzEngine(config)
        }
    }
}
