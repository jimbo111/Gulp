import Foundation
import Testing

@testable import GulpCodec

// F12 DEC-020…DEC-023: Transform Tags.

@Suite("GulpCodec — Transform Tags (DEC-020…DEC-023)")
struct TransformTagTests {
    let tags = TransformTags()

    func run(_ text: String, _ state: TagState = TagState(), advance: Bool = true) throws -> String {
        String(decoding: try tags.evaluate(Array(text.utf8), state: state, advance: advance), as: UTF8.self)
    }

    @Test("DEC-020/021: nesting, variables, ops with positional and named args; outside bytes untouched")
    func test_DEC020_evaluate() throws {
        let state = TagState(variables: ["user": "alice", "pass": "s3cret"])
        #expect(
            try run("Authorization: Basic «base64{ «var(user)»:«var(pass)» }»\r\n", state)
                == "Authorization: Basic YWxpY2U6czNjcmV0\r\n")
        #expect(
            try run("«hmac-sha256(key){msg}»")
                == "2d93cbc1be167bcb1637a4a23cbff01a7878f0c50ee833954ea5221bb1b8c628")
        #expect(
            try run("«hmac-sha256(key=key){msg}»")
                == "2d93cbc1be167bcb1637a4a23cbff01a7878f0c50ee833954ea5221bb1b8c628")
        #expect(try run("x=«url-encode{a b&c}»;«upper{«base64url{??>}»}»") == "x=a%20b%26c;PZ8-")
        #expect(try run("«len{hello}» «lit(a,b)»") == "5 a,b")
        #expect(try run("tags ««escaped»» stay") == "tags «escaped» stay")
        #expect(try run("no tags at all\r\n\r\n\u{0}") == "no tags at all\r\n\r\n\u{0}")
        let random = try run("«random(hex,12)»")
        #expect(random.count == 12 && random.allSatisfy { "0123456789abcdef".contains($0) })
        #expect(try run("«uuid()»").count == 36)
        #expect(Int(try run("«now(unix)»")) ?? 0 > 1_700_000_000)
        #expect(try run("«now(yyyy)»").count == 4)
        // Counters advance per evaluation; previews don't consume them.
        let counters = TagState()
        #expect(try run("«counter(n)»", counters, advance: false) == "1")
        #expect(try run("«counter(n)»-«counter(n)»", counters) == "1-2")
        #expect(try run("«counter(n)»", counters) == "3")
    }

    @Test(
        "DEC-023: unknown ops, bad args, missing variables and unbalanced delimiters are errors with offsets")
    func test_DEC023_errors() throws {
        func error(_ text: String) -> TransformTagError? {
            do {
                _ = try run(text)
                return nil
            } catch let error as TransformTagError {
                return error
            } catch {
                return nil
            }
        }
        #expect(error("ab«nope{x}»")?.offset == 2)
        #expect(error("ab«nope{x}»")?.message.contains("unknown operation") == true)
        #expect(error("«var(missing)»")?.message.contains("not set") == true)
        #expect(error("«base64{unclosed")?.message.contains("unterminated") == true)
        #expect(error("stray » here")?.message.contains("closing delimiter") == true)
        #expect(error("«hex-decode{zz}»")?.message.contains("hex-decode") == true)
        #expect(error("«beacon()»")?.message.contains("OAST") == true)  // off until configured (BCN-004)
        #expect(error("«base64(1,2){x}»")?.message.contains("no arguments") == true)
        let custom = TransformTags(open: "{{", close: "}}")
        #expect(
            String(
                decoding: try custom.evaluate(Array("a {{base64{hi}}} b".utf8), state: TagState()),
                as: UTF8.self) == "a aGk= b")
    }
}

@Suite("beacon() tag (DEC-021, F10 BCN-001)")
struct BeaconTagTests {
    @Test("beacon() mints a fresh payload per use in the requested form once OAST is configured")
    func test_DEC021_beacon() throws {
        final class Counter: @unchecked Sendable {
            // @unchecked: `value` is only touched under `lock`.
            let lock = NSLock()
            var value = 0
            func next() -> Int {
                lock.withLock {
                    value += 1; return value
                }
            }
        }
        let state = TagState()
        let counter = Counter()
        state.setOASTMinter { "id\(counter.next()).oast.test" }
        let text = try TransformTags().evaluate(
            Array("«beacon()» «beacon(url)» «beacon(https)» «beacon(email)»".utf8), state: state)
        #expect(
            String(decoding: text, as: UTF8.self)
                == "id1.oast.test http://id2.oast.test/ https://id3.oast.test/ gulp@id4.oast.test")
        #expect(throws: TransformTagError.self) {
            try TransformTags().evaluate(Array("«beacon(ftp)»".utf8), state: state)
        }
        state.setOASTMinter(nil)
        #expect(throws: TransformTagError.self) {
            try TransformTags().evaluate(Array("«beacon()»".utf8), state: state)
        }
    }
}
