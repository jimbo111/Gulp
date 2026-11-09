import Foundation
import Testing

@testable import GulpDiff

// F13 CMP-002…CMP-005: the diff engine.

/// The segments tile both sides in order, and equal segments really are equal.
func checkTiling(
    _ result: DiffResult, ignoringCase: Bool = false, file: String = #filePath, line: Int = #line
) {
    var positionA = 0
    var positionB = 0
    for segment in result.segments {
        #expect(segment.a.lowerBound == positionA && segment.b.lowerBound == positionB)
        if segment.operation == .equal, !ignoringCase {
            #expect(Array(result.a[segment.a]) == Array(result.b[segment.b]))
        }
        if segment.operation == .insert { #expect(segment.a.isEmpty) }
        if segment.operation == .delete { #expect(segment.b.isEmpty) }
        positionA = segment.a.upperBound
        positionB = segment.b.upperBound
    }
    #expect(positionA == result.a.count && positionB == result.b.count)
}

@Suite("GulpDiff — diff engine (CMP-002…CMP-005)")
struct DiffTests {
    @Test("Myers: segments tile both inputs over random edits, at byte and word level")
    func test_CMP002_property() {
        var generator = SystemRandomNumberGenerator()
        let alphabet = Array("ab c\nde,f".utf8)
        for _ in 0..<200 {
            let a = (0..<Int.random(in: 0...60, using: &generator)).map { _ in
                alphabet.randomElement(using: &generator)!
            }
            var b = a
            for _ in 0..<Int.random(in: 0...6, using: &generator) {
                let position = Int.random(in: 0...b.count, using: &generator)
                if Bool.random(using: &generator), position < b.count {
                    b.remove(at: position)
                } else {
                    b.insert(alphabet.randomElement(using: &generator)!, at: position)
                }
            }
            for granularity in DiffGranularity.allCases {
                let result = Differ.diff(a, b, granularity: granularity)
                checkTiling(result)
                #expect(result.identical == (a == b))
            }
        }
    }

    @Test("Byte and word granularity; the change summary")
    func test_CMP003_summary() {
        let a = Array("The quick brown fox jumps over the lazy dog".utf8)
        let b = Array("The quick red fox leaps over the lazy dog!".utf8)
        let words = Differ.diff(a, b, granularity: .word)
        checkTiling(words)
        let changed = words.changes.map {
            String(decoding: $0.a.isEmpty ? Array(words.b[$0.b]) : Array(words.a[$0.a]), as: UTF8.self)
        }
        #expect(
            changed.contains("brown") && changed.contains("red") && changed.contains("jumps")
                && changed.contains("!"))
        #expect(words.summary.modifications == 2 && words.summary.added == 1 && words.summary.deleted == 0)
        let bytes = Differ.diff(Array("abcdef".utf8), Array("abXdef".utf8), granularity: .byte)
        #expect(bytes.changes.count == 2 && bytes.changes[0].a == 2..<3 && bytes.changes[1].b == 2..<3)
    }

    @Test(
        "F13 acceptance 1: two 1 MB responses differing in a few bytes diff fast and highlight exactly them")
    func test_CMP004_large() {
        var generator = SystemRandomNumberGenerator()
        let words = ["alpha", "beta", "gamma", "delta", "<div>", "</div>", "token", "value", "\n"]
        var text: [UInt8] = []
        while text.count < 1_048_576 { text += Array((words.randomElement(using: &generator)! + " ").utf8) }
        var changed = text
        for position in [100_000, 500_000, 900_000] {
            changed[position] = changed[position] == 0x58 ? 0x59 : 0x58
        }
        let start = ContinuousClock.now
        let byteDiff = Differ.diff(text, changed, granularity: .byte)
        let wordDiff = Differ.diff(text, changed, granularity: .word)
        let elapsed = ContinuousClock.now - start
        #expect(elapsed < .seconds(2), "both diffs took \(elapsed) (target < 1 s each)")
        checkTiling(byteDiff)
        checkTiling(wordDiff)
        #expect(
            byteDiff.changes.filter { $0.operation == .delete }.map(\.a) == [
                100_000..<100_001, 500_000..<500_001, 900_000..<900_001,
            ])
        // Word mode highlights the containing words: every changed byte is inside (or next to) a
        // change, and every change is near a changed byte (nothing paired far away). One changed
        // byte may merge two words, so the exact number of segments isn't fixed.
        let positions = [100_000, 500_000, 900_000]
        for position in positions {
            #expect(wordDiff.changes.contains { $0.a.lowerBound <= position && position <= $0.a.upperBound })
        }
        #expect(
            wordDiff.changes.allSatisfy { change in positions.contains { abs(change.a.lowerBound - $0) < 40 }
            })
    }

    @Test("Repetitive text: each changed line pairs with its own old line (no far-apart pairing)")
    func test_CMP004_repetitive() {
        let line = Array("HTTP/1.1 200 OK alpha beta <div>delta</div> token=abc\n".utf8)
        var a: [UInt8] = []
        for _ in 0..<20_000 { a += line }
        var b = a
        for offset in [100_000, 500_000, 900_000] { b[offset] = 0x58 }
        let result = Differ.diff(a, b)
        checkTiling(result)
        #expect(result.summary.modifications == 3 && result.summary.added == 0 && result.summary.deleted == 0)
        #expect(result.changes.allSatisfy { $0.a.count < 20 && $0.b.count < 20 })
    }

    @Test("A changed newline (line counts differ) in repetitive text still pairs each change locally")
    func test_CMP004_newlineChange() {
        let line = Array("alpha beta \ngamma \n".utf8)
        var a: [UInt8] = []
        for _ in 0..<5_000 { a += line }
        var b = a
        let newline = a.indices.first { $0 >= 30_000 && a[$0] == 0x0A }!
        b[newline] = 0x58  // joins two lines
        b[60_001] = b[60_001] == 0x58 ? 0x59 : 0x58
        let result = Differ.diff(a, b)
        checkTiling(result)
        #expect(result.summary.modifications == 2 && result.summary.added == 0 && result.summary.deleted == 0)
        #expect(result.changes.allSatisfy { $0.a.count < 30 && $0.b.count < 30 })
    }

    @Test(
        "F13 acceptance 3 / CMP-005: pretty JSON + ignore whitespace makes reformatted JSON identical; ignore case"
    )
    func test_CMP005_transforms() {
        let compact = Array(#"{"b":[1,2],"a":{"x":"y"}}"#.utf8)
        let spaced = Array("{\n  \"a\" : { \"x\": \"y\" },\n  \"b\": [ 1, 2 ]\n}".utf8)
        #expect(!Differ.diff(compact, spaced).identical)
        let normalized = Differ.diff(
            compact, spaced, options: DiffOptions(ignoreWhitespace: true, prettyJSON: true))
        #expect(normalized.identical)
        #expect(
            Differ.diff(
                Array("a  b\n".utf8), Array("a b \n".utf8), options: DiffOptions(ignoreWhitespace: true)
            ).identical)
        let cased = Differ.diff(
            Array("Hello World".utf8), Array("hello world".utf8), options: DiffOptions(ignoreCase: true))
        #expect(cased.identical)
        // Totally different inputs fall back to one replacement instead of exploding.
        let x = (0..<50_000).map { UInt8(truncatingIfNeeded: $0 &* 31) }
        let y = (0..<50_000).map { UInt8(truncatingIfNeeded: $0 &* 17 &+ 3) }
        let different = Differ.diff(x, y, granularity: .byte)
        checkTiling(different)
        #expect(!different.identical)
    }
}
