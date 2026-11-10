import Foundation
import GulpCore
import Testing

@testable import GulpFuzzer

// F07 FUZ-001…FUZ-003, FUZ-010…FUZ-014, FUZ-020…FUZ-024: the Fuzzer's core.

func text(_ bytes: [UInt8]) -> String { String(decoding: bytes, as: UTF8.self) }

@Suite("GulpFuzzer — positions, payloads, attack types, analysis")
struct FuzzerCoreTests {
    @Test("FUZ-001/003: § markers split the request; payloads are spliced raw; auto-mark and clear")
    func test_FUZ001_positions() throws {
        let template = try FuzzTemplate(Array("GET /§a§?x=§1§&y=§§ HTTP/1.1\r\nHost: lab\r\n\r\n".utf8))
        #expect(template.positionCount == 3 && template.baseValues.map(text) == ["a", "1", ""])
        #expect(text(template.base) == "GET /a?x=1&y= HTTP/1.1\r\nHost: lab\r\n\r\n")
        #expect(
            text(template.render([Array("../".utf8), nil, Array("\r\n".utf8)]))
                == "GET /../?x=1&y=\r\n HTTP/1.1\r\nHost: lab\r\n\r\n")
        #expect(throws: FuzzTemplateError.self) { try FuzzTemplate(Array("a§b".utf8)) }
        let custom = try FuzzTemplate(Array("price=§10§ & id=^7^".utf8), marker: "^")
        #expect(custom.positionCount == 1 && text(custom.baseValues[0]) == "7")
        let request = RawRequest(
            Bytes(
                "POST /p?a=1&b=two HTTP/1.1\r\nHost: lab\r\nCookie: s=abc; t=9\r\nX-Api: k\r\n"
                    + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nu=x&v=y"))
        let marked = text(FuzzTemplate.autoMark(request))
        #expect(marked.contains("?a=§1§&b=§two§ ") && marked.contains("Cookie: s=§abc§; t=§9§\r\n"))
        #expect(
            marked.contains("X-Api: §k§") && marked.contains("Host: lab\r\n")
                && marked.hasSuffix("u=§x§&v=§y§"))
        #expect(marked.contains("Content-Length: 7\r\n"))
        #expect(FuzzTemplate.clear(Array(marked.utf8)) == request.bytes.rawBytes)
        #expect(text(FuzzTemplate.mark(Array("abcdef".utf8), 2..<4)) == "ab§cd§ef")
    }

    @Test("FUZ-002: sniper, battering ram, pitchfork and cluster bomb generate the right requests")
    func test_FUZ002_attackTypes() throws {
        let template = try FuzzTemplate(Array("u=§a§&p=§b§".utf8))
        let users = PayloadSet(.list(["alice", "bob"]))
        let passwords = PayloadSet(.list(["1", "2", "3"]))
        func run(_ type: AttackType, _ sets: [PayloadSet]) throws -> [String] {
            let plan = try AttackPlan(template: template, type: type, sets: sets)
            return plan.items().map { text(plan.request(for: $0)) }
        }
        #expect(try run(.sniper, [users]) == ["u=alice&p=b", "u=bob&p=b", "u=a&p=alice", "u=a&p=bob"])
        #expect(try run(.batteringRam, [users]) == ["u=alice&p=alice", "u=bob&p=bob"])
        #expect(try run(.pitchfork, [users, passwords]) == ["u=alice&p=1", "u=bob&p=2"])
        let bomb = try run(.clusterBomb, [users, passwords])
        #expect(bomb == ["u=alice&p=1", "u=alice&p=2", "u=alice&p=3", "u=bob&p=1", "u=bob&p=2", "u=bob&p=3"])
        let plan = try AttackPlan(template: template, type: .clusterBomb, sets: [users, passwords])
        #expect(plan.count == 6 && plan.items().map(\.seq) == [1, 2, 3, 4, 5, 6])
        #expect(try AttackPlan(template: template, type: .sniper, sets: [users]).count == 4)
        #expect(throws: FuzzTemplateError.self) {
            try AttackPlan(template: template, type: .pitchfork, sets: [users])
        }
        // Overflowing cluster bombs report Int.max instead of trapping.
        let huge = PayloadSet(
            .bruteForce(charset: "abcdefghijklmnopqrstuvwxyz0123456789", minLength: 1, maxLength: 12))
        #expect(try AttackPlan(template: template, type: .clusterBomb, sets: [huge, huge]).count == .max)
    }

    @Test("FUZ-010: numbers, dates, brute force, null, same-as-base and files")
    func test_FUZ010_sources() throws {
        func all(_ source: PayloadSource, base: String = "") -> [String] {
            source.payloads(base: Array(base.utf8)).map(text)
        }
        #expect(all(.numbers(from: 8, to: 12, step: 2, minDigits: 3, hex: false)) == ["008", "010", "012"])
        #expect(all(.numbers(from: 254, to: 256, step: 1, minDigits: 0, hex: true)) == ["fe", "ff", "100"])
        #expect(
            PayloadSource.numbers(from: 1, to: 100, step: 1, minDigits: 0, hex: false).count(base: []) == 100)
        let start = Date(timeIntervalSince1970: 1_767_225_600)  // 2026-01-01
        #expect(
            all(
                .dates(from: start, to: start.addingTimeInterval(2 * 86_400), stepDays: 1, format: "yyyyMMdd")
            ) == ["20260101", "20260102", "20260103"])
        #expect(
            all(.bruteForce(charset: "ab", minLength: 1, maxLength: 2)) == ["a", "b", "aa", "ab", "ba", "bb"])
        #expect(PayloadSource.bruteForce(charset: "ab", minLength: 1, maxLength: 2).count(base: []) == 6)
        #expect(all(.null(count: 3)) == ["", "", ""])
        #expect(all(.sameAsBase, base: "orig") == ["orig"])
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(
            "gulp-words-\(UUID().uuidString).txt")
        try "# comment\nadmin\n\nbackup\n".write(to: file, atomically: true, encoding: .utf8)
        #expect(
            all(.file(path: file.path)) == ["admin", "backup"]
                && PayloadSource.file(path: file.path).count(base: []) == 2)
    }

    @Test(
        "FUZ-012/013: processing — prefix/suffix, regex, case, encode, hash, skip, reverse, substring, tags")
    func test_FUZ012_processing() throws {
        func run(_ processors: [PayloadProcessor], _ input: String) throws -> String? {
            try PayloadPipeline(processors).process(Array(input.utf8)).map(text)
        }
        #expect(try run([.prefix("<"), .suffix(">")], "x") == "<x>")
        #expect(try run([.matchReplace(pattern: "[0-9]", replacement: "#")], "a1b2") == "a#b#")
        #expect(try run([.caseRule(.capitalize)], "admin") == "Admin")
        #expect(try run([.transform("url-encode-all", [:])], "a b") == "%61%20%62")
        #expect(try run([.transform("sha256", [:]), .substring(from: 0, length: 8)], "abc") == "ba7816bf")
        #expect(try run([.skipIf(pattern: "^#")], "#skip") == nil)
        #expect(try run([.reverse], "abc") == "cba")
        #expect(try run([.tags("«base64{admin:«var(payload)»}»")], "secret") == "YWRtaW46c2VjcmV0")
        #expect(throws: FuzzTemplateError.self) { try PayloadPipeline([.transform("nope", [:])]) }
        #expect(throws: FuzzTemplateError.self) { try PayloadPipeline([.skipIf(pattern: "(")]) }
        let preview = try PayloadPipeline([.caseRule(.upper)]).preview(.list(["a", "b", "c"]), count: 2)
        #expect(preview == ["A", "B"])
        // Skipped payloads aren't sent.
        let template = try FuzzTemplate(Array("§x§".utf8))
        let plan = try AttackPlan(
            template: template, type: .sniper,
            sets: [PayloadSet(.list(["a", "#b", "c"]), processors: [.skipIf(pattern: "^#")])])
        #expect(plan.items().map { text(plan.request(for: $0)) } == ["a", "c"])
    }

    @Test("FUZ-021…024: grep-match, grep-extract, reflection and baseline anomalies")
    func test_FUZ021_analysis() throws {
        let analyzer = try ResponseAnalyzer(
            matches: [GrepMatch("Invalid username"), .sqlErrors, GrepMatch("^HTTP/1.1 302", isRegex: true)],
            extracts: [
                .between(start: #"name="csrf" value=""#, end: "\""),
                .regex(pattern: #"rows=(\d+)"#, group: 1),
            ])
        let body =
            #"<input name="csrf" value="tok123"> invalid USERNAME &lt;b&gt; rows=42 near "x": SQLITE_ERROR"#
        let response = RawResponse(
            Bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: \(body.utf8.count)\r\n\r\n"
                    + body))
        let findings = analyzer.analyze(response, payloads: [Array("<b>".utf8)])
        #expect(findings.matches == [true, true, false])
        #expect(findings.extracts == ["tok123", "42"])
        #expect(findings.reflection == .encoded)
        #expect(analyzer.analyze(response, payloads: [Array("tok123".utf8)]).reflection == .raw)
        #expect(analyzer.analyze(nil, payloads: []).extracts == [nil, nil])
        #expect(throws: FuzzTemplateError.self) {
            try ResponseAnalyzer(matches: [GrepMatch("(", isRegex: true)], extracts: [])
        }
        let baseline = Baseline(status: 200, length: 1_000, timeMs: 20)
        #expect(baseline.anomalies(status: 200, length: 1_020, timeMs: 30, error: false).isEmpty)
        #expect(
            baseline.anomalies(status: 302, length: 1_100, timeMs: 900, error: false) == [
                .status, .length, .time,
            ])
        let histogram = lengthHistogram([10, 20, 10, 10, 30])
        #expect(histogram.first?.length == 10 && histogram.first?.count == 3)
    }
}
