import GulpCore
import GulpHTTP
import Testing

@testable import GulpProxy

// F01 PRX-020…PRX-022: Match & Replace on raw bytes.

func lastReceived(_ origin: Origin) -> String {
    String(decoding: origin.received(origin.connections - 1), as: UTF8.self)
}

@Suite("GulpProxy — Match & Replace (PRX-020…PRX-022)", .serialized)
struct MatchReplaceTests {
    let request = RawRequest(
        Bytes(
            "POST /login?next=%2Fhome&debug=0 HTTP/1.1\r\nHost: a\r\nUser-Agent: curl/8\r\n"
                + "Accept-Encoding: gzip\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                + "Content-Length: 21\r\n\r\nuser=alice&role=guest"))

    func apply(_ rule: MatchReplaceRule) -> String {
        MatchReplace.apply([rule], to: request).bytes.string()
    }

    @Test("PRX-020: an empty header match adds a header; an emptied header line is removed")
    func test_PRX020_headers() {
        let added = apply(MatchReplaceRule(kind: .requestHeader, match: "", replace: "X-Test: 1"))
        #expect(added.contains("Content-Length: 21\r\nX-Test: 1\r\n\r\nuser=alice&role=guest"))
        let removal = MatchReplaceRule(
            kind: .requestHeader, match: "(?i)^accept-encoding:.*$", replace: "", isRegex: true)
        let removed = apply(removal)
        #expect(!removed.contains("Accept-Encoding"))
        #expect(removed.contains("User-Agent: curl/8\r\nContent-Type:"))
    }

    @Test("PRX-020: regex groups ($1) and literal replacements")
    func test_PRX020_regexGroups() {
        let rule = MatchReplaceRule(
            kind: .requestHeader, match: "^User-Agent: (\\w+)/(\\d+)$", replace: "User-Agent: $1-gulp/$2",
            isRegex: true)
        #expect(apply(rule).contains("User-Agent: curl-gulp/8\r\n"))
        let literal = MatchReplaceRule(kind: .requestFirstLine, match: "/login", replace: "/signin")
        #expect(apply(literal).hasPrefix("POST /signin?next=%2Fhome&debug=0 HTTP/1.1\r\n"))
    }

    @Test("PRX-020: a body rule keeps Content-Length right; params by name and value")
    func test_PRX020_bodyAndParams() {
        let body = apply(MatchReplaceRule(kind: .requestBody, match: "guest", replace: "administrator"))
        #expect(body.hasSuffix("Content-Length: 29\r\n\r\nuser=alice&role=administrator"))
        let value = apply(MatchReplaceRule(kind: .requestParamValue, match: "0", replace: "1"))
        #expect(value.hasPrefix("POST /login?next=%2Fhome&debug=1 HTTP/1.1"))
        let name = apply(MatchReplaceRule(kind: .requestParamName, match: "role", replace: "group"))
        #expect(name.hasSuffix("Content-Length: 22\r\n\r\nuser=alice&group=guest"))
    }

    @Test("Rewrites are byte-exact: invalid UTF-8 survives and UTF-8 in rules matches UTF-8 bytes")
    func byteFidelity() {
        let head = Array("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n".utf8)
        let binary = RawRequest(Bytes(head + [0xFF, 0xC3, 0xA9, 0x00, 0x41]))
        let rule = MatchReplaceRule(kind: .requestBody, match: "é", replace: "e")
        let out = MatchReplace.apply([rule], to: binary).bytes.rawBytes
        #expect(Array(out.suffix(4)) == [0xFF, 0x65, 0x00, 0x41])
        #expect(String(decoding: out, as: UTF8.self).contains("Content-Length: 4\r\n"))
    }

    @Test("Responses: header, first line and body rules; HSTS preset")
    func responses() {
        let response = RawResponse(
            Bytes("HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=1\r\nContent-Length: 2\r\n\r\nok")
        )
        var hsts = MatchReplaceRule.presets.first { $0.comment == "Hide HSTS" }!
        hsts.enabled = true
        let bodyRule = MatchReplaceRule(kind: .responseBody, match: "ok", replace: "fine")
        let out = MatchReplace.apply([hsts, bodyRule], to: response).bytes.string()
        #expect(out == "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nfine")
        let noContent = RawResponse(Bytes("HTTP/1.1 204 No Content\r\n\r\n"))
        #expect(MatchReplace.apply([bodyRule], to: noContent) == noContent)
    }

    @Test("PRX-022: presets exist and are disabled by default")
    func test_PRX022_presets() {
        #expect(MatchReplaceRule.presets.count >= 6)
        #expect(MatchReplaceRule.presets.allSatisfy { !$0.enabled })
        #expect(MatchReplace.apply(MatchReplaceRule.presets, to: request) == request)
    }

    @Test("PRX-021: the hook rewrites proxy traffic; tools only with applyToTools; the original is kept")
    func test_PRX021_hook() async throws {
        let origin = try await Origin.start(reply: okReply)
        let addHeader = MatchReplaceRule(kind: .requestHeader, match: "", replace: "X-Gulp: 1")
        let hook = MatchReplaceHook(rules: [addHeader])
        let recorded = Recorded()
        let engine = NIOHTTPEngine(requestHooks: [hook], recorder: recorded)
        let target = HTTPTarget(scheme: .http, host: "127.0.0.1", port: origin.port)
        let get = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        _ = await engine.send(get, to: target, options: SendOptions(recordAs: .proxy))
        #expect(String(decoding: origin.received(0), as: UTF8.self).contains("X-Gulp: 1\r\n"))
        let exchanges = await recorded.exchanges
        #expect(exchanges.first?.edited?.originalRequest == get)  // PRX-012: the original is kept
        var repeater = SendOptions(recordAs: .repeater)
        repeater.connection = .newAndClose
        _ = await engine.send(get, to: target, options: repeater)
        #expect(!lastReceived(origin).contains("X-Gulp"))
        let forTools = MatchReplaceRule(
            kind: .requestHeader, match: "", replace: "X-Gulp: 2", applyToTools: true)
        hook.setRules([forTools])
        _ = await engine.send(get, to: target, options: repeater)
        #expect(lastReceived(origin).contains("X-Gulp: 2"))
        await engine.shutdown()
        await origin.stop()
    }
}
