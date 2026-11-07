import GulpCore
import Testing

@testable import GulpHTTP

// F03 HTTP/1 engine tests against an in-process scripted server (TestServer.swift). Each test names
// the requirement it covers (CLAUDE.md §2). Timeouts are generous so a framing bug fails fast with a
// typed error instead of hanging the suite.

func options(_ configure: (inout SendOptions) -> Void = { _ in }) -> SendOptions {
    var o = SendOptions(recordAs: .repeater)
    o.timeouts.firstByte = .seconds(5)
    o.timeouts.idleBetweenBytes = .seconds(5)
    o.timeouts.total = .seconds(15)
    configure(&o)
    return o
}

func get(_ path: String = "/", method: String = "GET") -> RawRequest {
    RawRequest(Bytes("\(method) \(path) HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
}

/// One framing scenario for HTTP-002.
struct FramingCase: Sendable, CustomTestStringConvertible {
    let name: String
    let method: String
    let reply: ServerReply
    /// The final response bytes the engine must record (interim responses excluded).
    let expected: String
    let interimCount: Int
    var testDescription: String { name }
}

struct AddHeaderHook: RequestHook {
    let kind: HookSet = .extensions
    func willSend(_ req: inout OutgoingRequest, context: HookContext) async throws {
        let insertAt = HTTP1.headerBlockEnd(req.request.bytes.rawBytes).end - 2
        req.request = req.request.replacing(insertAt..<insertAt, with: Bytes("X-Hook: 1\r\n"))
    }
}

actor MemoryRecorder: ExchangeRecorder {
    var stored: [Exchange] = []
    func record(_ exchange: Exchange) -> ExchangeID {
        stored.append(exchange)
        return ExchangeID(stored.count)
    }
}

@Suite("GulpHTTP — raw HTTP/1 engine (F03)", .serialized)
struct EngineTests {
    // MARK: HTTP-001

    @Test("HTTP-001: the exact request bytes reach the server (case, duplicates, bare LF)")
    func test_HTTP001_writesRawBytes() async throws {
        let server = try await TestServer.start { b, _ in headersComplete(b) ? ok("hi") : nil }
        let engine = NIOHTTPEngine()
        let raw = Bytes("GET /x HTTP/1.1\nhOsT: 127.0.0.1\nX-Dup: 1\nx-dup: 2\n\n")
        let result = await engine.send(RawRequest(raw), to: server.target, options: options())
        #expect(result.error == nil)
        #expect(server.received() == raw.rawBytes)
        #expect(result.exchange.response?.bytes.string().hasSuffix("hi") == true)
        await engine.shutdown()
        await server.stop()
    }

    // MARK: HTTP-002

    static let chunkedHead = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    static let chunkedBody = "5\r\n0\r\n\r\n\r\n3\r\nend\r\n0\r\nX-T: 1\r\n\r\n"

    static let framingCases: [FramingCase] = [
        FramingCase(
            name: "Content-Length", method: "GET",
            reply: ServerReply("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
            expected: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", interimCount: 0),
        // The first chunk's data is "0\r\n\r\n": only an exact parser knows it is not the last chunk.
        FramingCase(
            name: "chunked with trailer", method: "GET",
            reply: ServerReply(EngineTests.chunkedHead + EngineTests.chunkedBody),
            expected: EngineTests.chunkedHead + EngineTests.chunkedBody,
            interimCount: 0),
        FramingCase(
            name: "close-delimited", method: "GET",
            reply: ServerReply("HTTP/1.1 200 OK\r\n\r\nuntil close", close: true),
            expected: "HTTP/1.1 200 OK\r\n\r\nuntil close", interimCount: 0),
        FramingCase(
            name: "204", method: "GET", reply: ServerReply("HTTP/1.1 204 No Content\r\n\r\n"),
            expected: "HTTP/1.1 204 No Content\r\n\r\n", interimCount: 0),
        FramingCase(
            name: "304 with Content-Length", method: "GET",
            reply: ServerReply("HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n"),
            expected: "HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n", interimCount: 0),
        FramingCase(
            name: "HEAD with Content-Length", method: "HEAD",
            reply: ServerReply("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"),
            expected: "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n", interimCount: 0),
        FramingCase(
            name: "100 Continue then 200", method: "GET",
            reply: ServerReply("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
            expected: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", interimCount: 1),
    ]

    @Test("HTTP-002: response framing", arguments: EngineTests.framingCases)
    func test_HTTP002_framing(_ c: FramingCase) async throws {
        let reply = c.reply
        let server = try await TestServer.start { b, _ in headersComplete(b) ? reply : nil }
        let engine = NIOHTTPEngine()
        let result = await engine.send(get(method: c.method), to: server.target, options: options())
        #expect(result.error == nil)
        #expect(result.exchange.state == .complete)
        #expect(result.exchange.response?.bytes.string() == c.expected)
        #expect(result.exchange.response?.interim.count == c.interimCount)
        #expect(result.exchange.response?.parsed.incomplete == false)
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTP-002: a chunked body is kept raw and offered de-chunked")
    func test_HTTP002_dechunkedView() async throws {
        let body = "4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n"
        let reply = ServerReply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\(body)")
        let server = try await TestServer.start { b, _ in headersComplete(b) ? reply : nil }
        let engine = NIOHTTPEngine()
        let result = await engine.send(get(), to: server.target, options: options())
        let response = try #require(result.exchange.response)
        #expect(response.bytes[response.parsed.body].string() == body)
        #expect(response.parsed.dechunkedBody?.string() == "wikipedia")
        await engine.shutdown()
        await server.stop()
    }

    // MARK: HTTP-003

    @Test("HTTP-003: keep-alive connections are pooled and reused")
    func test_HTTP003_reuse() async throws {
        let server = try await TestServer.start { b, _ in headersComplete(b) ? ok("a") : nil }
        let engine = NIOHTTPEngine()
        let first = await engine.send(get(), to: server.target, options: options())
        let second = await engine.send(get(), to: server.target, options: options())
        #expect(first.error == nil && second.error == nil)
        #expect(server.connections == 1)
        #expect(first.exchange.connectionID == second.exchange.connectionID)
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTP-003: Connection: close and newAndClose are not reused")
    func test_HTTP003_noReuse() async throws {
        let server = try await TestServer.start { b, _ in
            headersComplete(b) ? ok("a", headers: "Connection: close\r\n") : nil
        }
        let engine = NIOHTTPEngine()
        _ = await engine.send(get(), to: server.target, options: options())
        _ = await engine.send(get(), to: server.target, options: options())
        #expect(server.connections == 2)
        _ = await engine.send(get(), to: server.target, options: options { $0.connection = .newAndClose })
        #expect(server.connections == 3)
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTP-003: a pooled connection the server closed is detected and replaced")
    func test_HTTP003_staleConnection() async throws {
        // Advertises keep-alive but closes right after replying.
        let server = try await TestServer.start { b, _ in
            guard headersComplete(b) else { return nil }
            var reply = ok("a")
            reply.close = true
            return reply
        }
        let engine = NIOHTTPEngine()
        let first = await engine.send(get(), to: server.target, options: options())
        try await Task.sleep(for: .milliseconds(100))
        let second = await engine.send(get(), to: server.target, options: options())
        #expect(first.error == nil)
        #expect(second.error == nil)
        #expect(server.connections == 2)
        await engine.shutdown()
        await server.stop()
    }

    // MARK: HTTP-004

    @Test("HTTP-004: hostname overrides and per-target IP overrides; DNS failures are typed")
    func test_HTTP004_resolution() async throws {
        let server = try await TestServer.start { b, _ in headersComplete(b) ? ok("a") : nil }
        var config = NIOHTTPEngine.Configuration()
        config.hostOverrides = ["gulp.test": "127.0.0.1"]
        let engine = NIOHTTPEngine(configuration: config)
        let viaTable = await engine.send(
            get(), to: HTTPTarget(scheme: .http, host: "gulp.test", port: server.port), options: options())
        #expect(viaTable.error == nil)
        let pinned = HTTPTarget(scheme: .http, host: "other.test", port: server.port, ipOverride: "127.0.0.1")
        let viaTarget = await engine.send(get(), to: pinned, options: options())
        #expect(viaTarget.error == nil)
        let missing = await engine.send(
            get(), to: HTTPTarget(scheme: .http, host: "nonexistent.invalid", port: 80), options: options())
        #expect(missing.error == .dnsFailure("nonexistent.invalid"))
        await engine.shutdown()
        await server.stop()
    }

    // MARK: HTTP-005

    @Test("HTTP-005: first-byte, idle and total timeouts are typed errors")
    func test_HTTP005_timeouts() async throws {
        let silent = try await TestServer.start { _, _ in nil }
        let engine = NIOHTTPEngine()
        let firstByte = await engine.send(
            get(), to: silent.target, options: options { $0.timeouts.firstByte = .milliseconds(300) })
        #expect(firstByte.error == .firstByteTimeout)
        let total = await engine.send(
            get(), to: silent.target,
            options: options {
                $0.timeouts.firstByte = .seconds(30)
                $0.timeouts.total = .milliseconds(400)
            })
        #expect(total.error == .totalTimeout)

        let stalling = try await TestServer.start { b, _ in
            headersComplete(b) ? ServerReply("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc") : nil
        }
        let shortIdle = options { $0.timeouts.idleBetweenBytes = .milliseconds(300) }
        let idle = await engine.send(get(), to: stalling.target, options: shortIdle)
        #expect(idle.error == .idleTimeout)
        #expect(idle.exchange.response?.bytes.string().hasSuffix("abc") == true)  // partial bytes kept
        await engine.shutdown()
        await silent.stop()
        await stalling.stop()
    }

    @Test("HTTP-005: a refused connection is a typed error")
    func test_HTTP005_refused() async throws {
        let server = try await TestServer.start { _, _ in nil }
        let target = server.target
        await server.stop()
        let engine = NIOHTTPEngine()
        let result = await engine.send(get(), to: target, options: options())
        #expect(result.error == .connectionRefused)
        #expect(result.exchange.state == .failed(.connectionRefused))
        await engine.shutdown()
    }

    @Test("HTTP-002/005: a response cut short is recorded as incomplete with its partial bytes")
    func test_HTTP002_incomplete() async throws {
        let server = try await TestServer.start { b, _ in
            headersComplete(b)
                ? ServerReply("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", close: true) : nil
        }
        let engine = NIOHTTPEngine()
        let result = await engine.send(get(), to: server.target, options: options())
        #expect(result.error == .incompleteResponse)
        #expect(result.exchange.response?.bytes.string().hasSuffix("abc") == true)
        await engine.shutdown()
        await server.stop()
    }

    @Test("maxResponseBytes: an oversized response fails with tooLarge")
    func test_tooLarge() async throws {
        let server = try await TestServer.start { b, _ in
            headersComplete(b) ? ok(String(repeating: "x", count: 100)) : nil
        }
        let engine = NIOHTTPEngine()
        let small = options { $0.maxResponseBytes = 10 }
        let result = await engine.send(get(), to: server.target, options: small)
        #expect(result.error == .tooLarge(limit: 10))
        await engine.shutdown()
        await server.stop()
    }

    // MARK: HTTP-008

    @Test("HTTP-008: Update Content-Length fixes or adds the header; off means untouched")
    func test_HTTP008_updateContentLength() async throws {
        let server = try await TestServer.start { b, _ in headersComplete(b) ? ok("a") : nil }
        let engine = NIOHTTPEngine()
        let wrong = RawRequest(Bytes("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 99\r\n\r\nabc"))
        let missing = RawRequest(Bytes("POST / HTTP/1.1\r\nHost: h\r\n\r\nabc"))
        let off = options { $0.connection = .newAndClose }
        let on = options {
            $0.connection = .newAndClose
            $0.updateContentLength = true
        }
        _ = await engine.send(wrong, to: server.target, options: off)
        _ = await engine.send(wrong, to: server.target, options: on)
        _ = await engine.send(missing, to: server.target, options: on)
        #expect(server.received(0) == wrong.bytes.rawBytes)
        let fixed = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"
        #expect(Bytes(server.received(1)).string() == fixed)
        #expect(Bytes(server.received(2)).string() == fixed)
        await engine.shutdown()
        await server.stop()
    }

    // MARK: HTTP-009

    @Test("HTTP-009: cancelling the task closes the connection and records .cancelled")
    func test_HTTP009_cancellation() async throws {
        let server = try await TestServer.start { _, _ in nil }
        let engine = NIOHTTPEngine()
        let target = server.target
        let task = Task { await engine.send(get(), to: target, options: options()) }
        try await Task.sleep(for: .milliseconds(200))
        task.cancel()
        let result = await task.value
        #expect(result.error == .cancelled)
        #expect(result.exchange.state == .failed(.cancelled))
        await engine.shutdown()
        await server.stop()
    }

    // MARK: HTTP-010

    @Test("HTTP-010: every timing phase is measured; DNS/connect are nil on a reused connection")
    func test_HTTP010_timing() async throws {
        let server = try await TestServer.start { b, _ in headersComplete(b) ? ok("timing") : nil }
        let engine = NIOHTTPEngine()
        let fresh = await engine.send(get(), to: server.target, options: options()).exchange.timing
        let phases = [fresh.dnsMs, fresh.connectMs, fresh.requestWriteMs, fresh.ttfbMs, fresh.downloadMs]
        for phase in phases + [fresh.totalMs] {
            #expect(phase != nil && phase! >= 0)
        }
        let reused = await engine.send(get(), to: server.target, options: options()).exchange.timing
        #expect(reused.dnsMs == nil && reused.connectMs == nil && reused.totalMs != nil)
        await engine.shutdown()
        await server.stop()
    }

    // MARK: hooks, recording, groups, not-yet-implemented paths

    @Test("Request hooks run unless disabled, and the recorder stores each exchange")
    func test_hooksAndRecording() async throws {
        let server = try await TestServer.start { b, _ in headersComplete(b) ? ok("a") : nil }
        let recorder = MemoryRecorder()
        let engine = NIOHTTPEngine(requestHooks: [AddHeaderHook()], recorder: recorder)
        let fresh = options { $0.connection = .newAndClose }
        let hooked = await engine.send(get(), to: server.target, options: fresh)
        let plain = await engine.send(
            get(), to: server.target,
            options: options {
                $0.connection = .newAndClose
                $0.applyHooks = []
            })
        #expect(Bytes(server.received(0)).string().contains("X-Hook: 1\r\n"))
        #expect(server.received(1) == get().bytes.rawBytes)
        #expect(hooked.exchange.id == 1 && plain.exchange.id == 2)
        let count = await recorder.stored.count
        #expect(count == 2)
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTP-030/031/032: group sends use one, separate, or parallel connections")
    func test_HTTP030_groups() async throws {
        let server = try await TestServer.start { b, _ in headersComplete(b) ? ok("g") : nil }
        let engine = NIOHTTPEngine()
        let items = (0..<3).map { _ in GroupItem(request: get(), target: server.target) }
        let single = await engine.sendGroup(items, mode: .sequentialSingleConnection, options: options())
        #expect(single.allSatisfy { $0.error == nil } && server.connections == 1)
        let separate = await engine.sendGroup(items, mode: .sequentialSeparateConnections, options: options())
        #expect(separate.allSatisfy { $0.error == nil } && server.connections == 4)
        let parallel = await engine.sendGroup(items, mode: .parallel, options: options())
        #expect(parallel.allSatisfy { $0.error == nil } && server.connections == 7)
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTPS, HTTP/2 and WebSockets report their milestone instead of misbehaving")
    func test_notYetImplemented() async throws {
        let engine = NIOHTTPEngine()
        let tlsTarget = HTTPTarget(scheme: .https, host: "127.0.0.1")
        let https = await engine.send(get(), to: tlsTarget, options: options())
        #expect(https.error?.code == "tls_failure")
        let spec = H2RequestSpec(pseudoHeaders: [], headers: [])
        let h2 = await engine.send(spec, to: tlsTarget, options: options())
        #expect(h2.error == .other("HTTP/2 is implemented in M3"))
        await #expect(throws: GulpError.self) {
            _ = try await engine.openWebSocket(get(), to: tlsTarget, options: options())
        }
    }
}
