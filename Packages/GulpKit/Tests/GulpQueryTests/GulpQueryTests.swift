import Foundation
import GulpCore
import Testing

@testable import GulpQuery

let target = HTTPTarget(scheme: .https, host: "api.lab.test")

func exchange(
    _ request: String, _ response: String? = nil, source: ToolSource = .proxy, id: ExchangeID = 1,
    tags: [String] = [], comment: String? = nil, start: Date = Date(timeIntervalSince1970: 1_800_000_000)
) -> Exchange {
    var timing = Timing(start: start)
    timing.totalMs = 42
    return Exchange(
        id: id, source: source, target: target, request: RawRequest(Bytes(request)),
        response: response.map { RawResponse(Bytes($0)) }, state: .complete, timing: timing,
        annotation: Annotation(comment: comment, tags: tags))
}

func matches(_ query: String, _ exchange: Exchange, _ context: GulpQLContext = GulpQLContext()) throws -> Bool
{
    try GulpQLPredicate(query).evaluate(exchange, context: context)
}

@Suite("GulpQL (HIS-020…024)")
struct GulpQLTests {
    let search = exchange(
        "GET /api/search?q=gulpfish&page=2 HTTP/1.1\r\nHost: api.lab.test\r\nCookie: sid=abc123; theme=dark\r\n"
            + "X-Api-Key: k1\r\nX-Api-Key: k2\r\n\r\n",
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\n"
            + "Set-Cookie: session=zzz; HttpOnly\r\n\r\n<html><title>Down</title>You searched gulpfish</html>",
        tags: ["imported"], comment: "check later")

    @Test("HIS-020: and binds tighter than or; not binds tightest; text round-trips")
    func test_HIS020_precedence() throws {
        let expression = try GulpQL.parse(#"resp.status >= 500 or req.host ~ "api" and not in_scope"#)
        guard case .or(_, .and(_, .not(.test(let field)))) = expression else {
            Issue.record("unexpected tree \(expression)")
            return
        }
        #expect(field.name == "in_scope")
        #expect(expression.description == #"resp.status >= 500 or req.host ~ "api" and not in_scope"#)
        let grouped = try GulpQL.parse(#"(resp.status in 500..599 or source == proxy) and tag == "x""#)
        #expect(grouped.description == #"(resp.status in 500..599 or source == "proxy") and tag == "x""#)
        #expect(try GulpQL.parse(grouped.description) == grouped)
        #expect(try GulpQL.parse("") == .constant(true))
        #expect(
            try GulpQL.parse("req.method == GET && !has_response || id in [1, 2]").description
                == #"req.method == "GET" and not has_response or id in [1, 2]"#)
    }

    @Test("HIS-025: errors carry a message and the range to underline")
    func test_HIS025_errors() {
        func error(_ text: String) -> GulpQLError? {
            do {
                _ = try GulpQL.parse(text)
                return nil
            } catch {
                return error
            }
        }
        let typo = error(#"req.hots == "x""#)
        #expect(typo?.message.contains("did you mean req.host") == true && typo?.range == 0..<8)
        #expect(error(#"req.body ~ "(unclosed""#)?.message.contains("invalid regex") == true)
        #expect(error("req.header == 1")?.message.contains("takes 1 argument") == true)
        #expect(error(#"req.path == "x"#)?.message == "unterminated string")
        #expect(error("resp.status == 200 resp.status == 201")?.message.contains("expected and/or") == true)
        #expect(error("in_scope > 1")?.message.contains("true/false") == true)
        #expect(error("resp.status in 5")?.message.contains("in needs") == true)
        #expect(error(#"time_between("yesterday", "today")"#)?.message.contains("isn't a date") == true)
        #expect(error("(resp.status == 1")?.message == "expected “)”")
    }

    @Test("HIS-021: request and response fields")
    func test_HIS021_fields() throws {
        let e = search
        #expect(try matches(#"req.method == "get" and req.host == "API.lab.test" and req.port == 443"#, e))
        #expect(try matches(#"req.path == "/api/search" and req.query contains "page=2""#, e))
        #expect(try matches(#"req.url == "https://api.lab.test/api/search?q=gulpfish&page=2""#, e))
        #expect(try matches(#"req.header("x-api-key") == "k2" and req.headers("X-API-KEY") == "k1""#, e))
        #expect(try matches(#"req.cookie("sid") == "abc123" and req.param("q") == "gulpfish""#, e))
        #expect(try matches(#"req.params == "page" and req.has_param("q") and req.has_param"#, e))
        #expect(try matches(#"req.line == "GET /api/search?q=gulpfish&page=2 HTTP/1.1""#, e))
        #expect(try matches(#"resp.status == 503 and resp.status in 500..599 and resp.status != 200"#, e))
        #expect(try matches(#"resp.mime == "text/html" and resp.title == "Down""#, e))
        #expect(try matches(#"resp.body contains "gulpfish" and resp.body =~ /You searched/"#, e))
        #expect(try !matches(#"resp.body =~ /you searched/"#, e))  // =~ is case-sensitive
        #expect(try matches(#"resp.body ~ /you searched/"#, e))
        #expect(try matches(#"resp.cookie("session") == "zzz" and resp.sets_cookie"#, e))
        #expect(try matches(#"resp.header("content-type") startswith "text/" and resp.time < 100"#, e))
        #expect(try matches(#"source == proxy and tag == "IMPORTED" and comment endswith "later""#, e))
        #expect(try matches(#"source in [repeater, proxy] and not edited and has_response"#, e))
        #expect(try matches("id == 1 and req.length > 50", e))
    }

    @Test("§5: missing values never match; not and has_response stay consistent")
    func test_HIS023_missing() throws {
        let requestOnly = exchange("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
        #expect(try !matches("resp.status >= 500", requestOnly))
        #expect(try !matches("resp.status != 200", requestOnly))
        #expect(try matches("not resp.status >= 500", requestOnly))
        #expect(try matches("not has_response", requestOnly))
        #expect(try !matches(#"req.header("x-missing") != "a""#, requestOnly))
        #expect(try matches(#"tag != "imported""#, requestOnly))  // no tags: none equals it
    }

    @Test("HIS-022: reflected, time_between, matches_scope")
    func test_HIS022_helpers() throws {
        #expect(try matches(#"reflected("q")"#, search))
        #expect(try !matches(#"reflected("page")"#, search))  // "2" is too short to count
        let start = "2027-01-15T08:00:01Z"  // one second after the exchange started
        #expect(try matches(#"time_between("2027-01-01", "2027-02-01")"#, search))
        #expect(try !matches(#"time_between("\#(start)", "2027-02-01")"#, search))
        let scope = ScopeService(rules: [ScopeRule(kind: .include, host: "api.lab.test")])
        #expect(try matches("matches_scope and in_scope", search, GulpQLContext(scope: scope)))
        #expect(try !matches("matches_scope", search))
        // The store's stored flag answers both, as SQL push-down reads the same column.
        let stored = GulpQLContext(scope: scope, inScope: { _ in false })
        #expect(try !matches("matches_scope or in_scope", search, stored))
        let form = exchange(
            "POST /login HTTP/1.1\r\nHost: a\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
                + "user=alice+smith&next=%2Fhome",
            "HTTP/1.1 200 OK\r\n\r\nWelcome alice smith")
        #expect(try matches(#"req.param("user") == "alice smith" and reflected("user")"#, form))
        let json = exchange(
            "POST /api HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"name\":\"zed42\",\"n\":7}",
            "HTTP/1.1 200 OK\r\n\r\nhello zed42")
        #expect(try matches(#"req.param("n") == 7 and reflected("name")"#, json))
    }

    @Test("§5: compressed bodies are searched through the injected decoder")
    func test_HIS023_decodeBody() throws {
        let gzipped = exchange(
            "GET / HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Encoding: rot\r\n\r\nuryyb")
        let rot13: @Sendable ([UInt8], String) -> [UInt8]? = { bytes, encoding in
            guard encoding == "rot" else { return nil }
            return bytes.map { b in
                switch b {
                case 97...122: (b - 97 + 13) % 26 + 97
                default: b
                }
            }
        }
        #expect(try !matches(#"resp.body contains "hello""#, gzipped))
        #expect(try matches(#"resp.body contains "hello""#, gzipped, GulpQLContext(decodeBody: rot13)))
    }

    @Test("HIS-024: indexed columns push down; bodies and headers stay residual")
    func test_HIS024_lowering() throws {
        let both = try GulpQL.parse(#"resp.status >= 500 and req.host ~ "api""#).sqlLowering()
        #expect(both.residual == nil)
        #expect(
            both.sql
                == "((exchanges.status IS NOT NULL AND exchanges.status >= ? AND exchanges.status <= ?) AND "
                + "(exchanges.host IS NOT NULL AND gulpql_regexp(?, exchanges.host, ?)))")
        #expect(both.bindings == [.int(500), .int(Int64.max), .text("api"), .int(1)])

        let mixed = try GulpQL.parse(#"source == Proxy and resp.body contains "x""#).sqlLowering()
        #expect(mixed.sql == "(exchanges.source IS NOT NULL AND exchanges.source = ?)")
        #expect(mixed.bindings == [.text("proxy")])
        #expect(mixed.residual == .compare(GulpQLField("resp.body"), .contains, .string("x")))

        let either = try GulpQL.parse(#"resp.status == 200 or resp.body contains "x""#).sqlLowering()
        #expect(either.sql == nil && either.residual != nil)

        let negated = try GulpQL.parse("not in_scope and tag != imported").sqlLowering()
        #expect(negated.residual == nil)
        #expect(
            negated.sql
                == "((NOT exchanges.in_scope = 1) AND (NOT EXISTS (SELECT 1 FROM exchange_tags t "
                + "WHERE t.exchange_id = exchanges.id AND t.tag = ? COLLATE NOCASE)))")

        let path = try GulpQL.parse(#"req.path contains "50%_off""#).sqlLowering()
        #expect(path.bindings == [.text(#"%50\%\_off%"#)])
        let range = try GulpQL.parse("resp.status in 500..599 and req.method in [get, post]").sqlLowering()
        #expect(
            range.residual == nil
                && range.bindings == [.double(500), .double(599), .text("get"), .text("post")])
    }

    @Test("HIS-025: completions and token colors")
    func test_HIS025_assist() {
        #expect(GulpQL.completions("resp.st", cursor: 7) == ["resp.status"])
        #expect(GulpQL.completions("req.ha", cursor: 6) == ["req.has_param"])
        let kinds = GulpQL.highlights(#"resp.status >= 500 and req.host ~ /api/"#).map(\.kind)
        #expect(kinds == [.field, .operator, .number, .keyword, .field, .operator, .regex])
    }

    @Test("HIS-043: a custom column is one GulpQL field evaluated per row")
    func test_HIS043_column() throws {
        #expect(try GulpQLColumn(#"resp.header("set-cookie")"#).value(for: search) == "session=zzz; HttpOnly")
        #expect(try GulpQLColumn(#"req.param("q")"#).value(for: search) == "gulpfish")
        #expect(try GulpQLColumn("resp.status").value(for: search) == "503")
        #expect(try GulpQLColumn(#"req.cookie("nope")"#).value(for: search) == nil)
        #expect(throws: GulpQLError.self) { try GulpQLColumn("resp.status == 1") }
    }
}
