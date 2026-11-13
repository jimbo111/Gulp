import Testing

@testable import GulpCodec

@Suite("Scripted WebSocket sequences (F15 §2.3, WSX-008)")
struct WSScriptTests {
    @Test("parse: send / expect / expect-regex with comments and timeouts")
    func test_WSX008_parse() {
        let script = WSScript.parse(
            """
            # a login handshake
            send {"op":"hello"}
            expect welcome @500
            expect-regex ^\\{"ok":true

            send {"op":"bye"}
            """)
        #expect(
            script.steps == [
                .send(#"{"op":"hello"}"#),
                .expect(pattern: "welcome", isRegex: false, timeoutMs: 500),
                .expect(pattern: #"^\{"ok":true"#, isRegex: true, timeoutMs: 2000),
                .send(#"{"op":"bye"}"#),
            ])
    }

    @Test("match: substring and regex expects, send never matches")
    func test_WSX008_match() {
        let sub = WSScriptStep.expect(pattern: "welcome", isRegex: false, timeoutMs: 0)
        let rx = WSScriptStep.expect(pattern: #"^\{"ok":true"#, isRegex: true, timeoutMs: 0)
        #expect(WSScriptMatch.matches("echo: welcome aboard", step: sub))
        #expect(!WSScriptMatch.matches("echo: goodbye", step: sub))
        #expect(WSScriptMatch.matches(#"{"ok":true}"#, step: rx))
        #expect(!WSScriptMatch.matches("anything", step: .send("x")))
    }

    @Test("blank input yields an empty script")
    func test_WSX008_empty() {
        #expect(WSScript.parse("\n  \n# only a comment\n").steps.isEmpty)
    }
}
