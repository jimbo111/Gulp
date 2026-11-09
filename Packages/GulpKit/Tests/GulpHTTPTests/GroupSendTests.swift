import GulpCore
import GulpTLS
import Testing

@testable import GulpHTTP

// F03 HTTP-033/034/035: single-packet group sends — every request except its final bytes goes out
// first; after the warm-up all final bytes are released together.

@Suite("GulpHTTP — single-packet group sends (HTTP-033…HTTP-035)", .serialized)
struct GroupSendTests {
    func options(warmUp: Duration = .milliseconds(300)) -> SendOptions {
        var options = SendOptions(recordAs: .repeater)
        options.timeouts.total = .seconds(10)
        options.singlePacketWarmUp = warmUp
        return options
    }

    @Test("HTTP-034: HTTP/1 last-byte sync — waits for the warm-up, exact bytes, tight spread")
    func test_HTTP034_lastByteSync() async throws {
        let server = try await TestServer.start { received, _ in
            guard headersComplete(received) else { return nil }
            let text = String(decoding: received, as: UTF8.self)
            // A request is complete once its whole body (Content-Length: 4) is in.
            guard text.hasPrefix("GET") || text.hasSuffix("coin") else { return nil }
            return ok("redeemed")
        }
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: server.port)
        let items = (0..<5).map { index in
            GroupItem(
                request: RawRequest(
                    Bytes("POST /redeem?n=\(index) HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\ncoin")),
                target: target)
        }
        let started = ContinuousClock.now
        let results = await engine.sendGroup(items, mode: .singlePacket, options: options())
        #expect(ContinuousClock.now - started >= .milliseconds(300))  // the final bytes waited
        #expect(results.count == 5)
        #expect(results.allSatisfy { $0.error == nil && $0.exchange.response?.parsed.statusCode == 200 })
        for (index, result) in results.enumerated() {
            // Results come back in item order.
            #expect(result.exchange.request.bytes.string().hasPrefix("POST /redeem?n=\(index) "))
        }
        // Every connection received exactly one request, byte for byte.
        let sent = Set(items.map { $0.request.bytes.rawBytes })
        let receivedSet = Set((0..<5).map { server.received($0) })
        #expect(receivedSet == sent)
        let offsets = results.compactMap(\.exchange.timing.finalWriteOffsetMs)
        #expect(offsets.count == 5)
        #expect((offsets.max() ?? 99) < 50)  // HTTP-035: the spread of the final writes
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTP-033: HTTP/2 single packet — one connection, every stream answered, one final flush")
    func test_HTTP033_h2SinglePacket() async throws {
        let server = try await HTTP2EngineTests.tlsServer()
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: server.port)
        var items = (0..<4).map { index in
            GroupItem(
                request: RawRequest(
                    Bytes(
                        "POST /redeem/\(index) HTTP/1.1\r\nHost: localhost\r\n"
                            + "Content-Length: 4\r\n\r\ncoin")),
                target: target)
        }
        let balance = RawRequest(Bytes("GET /balance HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        items.append(GroupItem(request: balance, target: target))
        let started = ContinuousClock.now
        let results = await engine.sendGroup(items, mode: .singlePacket, options: options())
        #expect(ContinuousClock.now - started >= .milliseconds(300))
        #expect(server.connections == 1)
        #expect(results.allSatisfy { $0.exchange.httpVersion == .http2 && $0.error == nil })
        let bodies = results.map {
            $0.exchange.response?.bytes.string().split(separator: "\r\n").last.map(String.init)
        }
        let expected = (0..<4).map { "POST /redeem/\($0) 4" } + ["GET /balance 0"]
        #expect(bodies == expected)
        // All final frames were flushed together: no spread at all.
        #expect(results.allSatisfy { $0.exchange.timing.finalWriteOffsetMs == 0 })
        await engine.shutdown()
        await server.stop()
    }

    @Test("HTTP-033 → 034: a server that won't speak h2 gets the HTTP/1 last-byte sync instead")
    func test_HTTP033_fallback() async throws {
        let (server, _) = try await UpstreamTLSEngineTests.tlsServer()  // HTTP/1.1-only TLS server
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: server.port)
        let items = (0..<3).map { _ in
            GroupItem(
                request: RawRequest(Bytes("GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n")), target: target)
        }
        let results = await engine.sendGroup(
            items, mode: .singlePacket, options: options(warmUp: .milliseconds(50)))
        #expect(results.allSatisfy { $0.error == nil && $0.exchange.httpVersion == .http1_1 })
        #expect(results.allSatisfy { $0.exchange.response?.bytes.string().hasSuffix("secret") == true })
        await engine.shutdown()
        await server.stop()
    }
}
