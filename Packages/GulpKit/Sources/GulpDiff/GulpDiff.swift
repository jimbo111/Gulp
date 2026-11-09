// GulpDiff — the Comparer's diff engine (F13 CMP-002…CMP-005): Myers O(ND) over a generic element,
// used for bytes and for word tokens, with ranges back into the original bytes for precise
// highlighting.
//
// Large inputs (CMP-004, 1 MB in < 1 s): the common prefix and suffix are cut off first; what's
// left is diffed line by line (lines hashed to Ints), and only the changed line blocks are refined
// at word or byte level. Myers needs O(D²) memory to backtrack, so the edit distance is capped:
// past the cap a block is reported as one replacement instead of exploding (huge, totally
// different inputs).

import Foundation

/// What a segment of the diff is.
public enum DiffOperation: String, Sendable, Hashable {
    /// The same on both sides.
    case equal
    /// Only on the right (B).
    case insert
    /// Only on the left (A).
    case delete
}

/// One run of the diff, as byte ranges into the compared texts.
public struct DiffSegment: Sendable, Hashable {
    /// Equal, insert or delete.
    public var operation: DiffOperation
    /// The range in A (empty for inserts).
    public var a: Range<Int>
    /// The range in B (empty for deletes).
    public var b: Range<Int>
}

/// Diff granularity (CMP-002).
public enum DiffGranularity: String, Sendable, Hashable, CaseIterable {
    /// Words, whitespace runs and punctuation (good for text and HTML).
    case word
    /// Single bytes (precise; binary data).
    case byte
}

/// Pre-diff transforms (CMP-005).
public struct DiffOptions: Sendable, Hashable {
    /// Treat whitespace differences as equal (word mode).
    public var ignoreWhitespace = false
    /// Compare case-insensitively (ASCII).
    public var ignoreCase = false
    /// Pretty-print JSON on both sides first (sorted keys), when both parse.
    public var prettyJSON = false

    /// Options.
    public init(ignoreWhitespace: Bool = false, ignoreCase: Bool = false, prettyJSON: Bool = false) {
        self.ignoreWhitespace = ignoreWhitespace
        self.ignoreCase = ignoreCase
        self.prettyJSON = prettyJSON
    }
}

/// A finished diff.
public struct DiffResult: Sendable {
    /// The left text as compared (after transforms).
    public var a: [UInt8]
    /// The right text as compared.
    public var b: [UInt8]
    /// Every segment, in order.
    public var segments: [DiffSegment]

    /// Nothing differs.
    public var identical: Bool { segments.allSatisfy { $0.operation == .equal } }

    /// The changes: a delete next to an insert is one modification (CMP-003's summary).
    public var summary: (modifications: Int, added: Int, deleted: Int) {
        var modifications = 0
        var added = 0
        var deleted = 0
        var index = 0
        let changes = segments
        while index < changes.count {
            let operation = changes[index].operation
            if operation != .equal, index + 1 < changes.count, changes[index + 1].operation != .equal,
                changes[index + 1].operation != operation
            {
                modifications += 1
                index += 2
                continue
            }
            if operation == .insert { added += 1 }
            if operation == .delete { deleted += 1 }
            index += 1
        }
        return (modifications, added, deleted)
    }

    /// The changed segments only (for next/previous-change navigation).
    public var changes: [DiffSegment] { segments.filter { $0.operation != .equal } }
}

/// Diffs bytes.
public enum Differ {
    /// Myers edit distance cap per block (beyond it the block is one replacement).
    public static let maxEditDistance = 1_500

    /// Diff `a` and `b` at `granularity` after `options`' transforms.
    public static func diff(
        _ a: [UInt8], _ b: [UInt8], granularity: DiffGranularity = .word, options: DiffOptions = DiffOptions()
    ) -> DiffResult {
        var left = a
        var right = b
        if options.prettyJSON, let prettyLeft = pretty(left), let prettyRight = pretty(right) {
            left = prettyLeft
            right = prettyRight
        }
        let compareLeft = options.ignoreCase ? lower(left) : left
        let compareRight = options.ignoreCase ? lower(right) : right
        var segments: [DiffSegment] = []
        // 1. Common prefix and suffix.
        let limit = min(compareLeft.count, compareRight.count)
        var prefix = 0
        while prefix < limit, compareLeft[prefix] == compareRight[prefix] { prefix += 1 }
        var suffix = 0
        while suffix < limit - prefix,
            compareLeft[compareLeft.count - 1 - suffix] == compareRight[compareRight.count - 1 - suffix]
        {
            suffix += 1
        }
        // Back up to a token boundary so word mode doesn't split a word in the middle.
        if granularity == .word {
            while prefix > 0, isWordByte(compareLeft[prefix - 1]),
                (prefix < compareLeft.count && isWordByte(compareLeft[prefix]))
                    || (prefix < compareRight.count && isWordByte(compareRight[prefix]))
            {
                prefix -= 1
            }
            while suffix > 0, isWordByte(compareLeft[compareLeft.count - suffix]),
                (compareLeft.count - suffix - 1 >= prefix
                    && isWordByte(compareLeft[compareLeft.count - suffix - 1]))
                    || (compareRight.count - suffix - 1 >= prefix
                        && isWordByte(compareRight[compareRight.count - suffix - 1]))
            {
                suffix -= 1
            }
        }
        if prefix > 0 { segments.append(DiffSegment(operation: .equal, a: 0..<prefix, b: 0..<prefix)) }
        let middleA = prefix..<(compareLeft.count - suffix)
        let middleB = prefix..<(compareRight.count - suffix)
        // 2. Lines, then refine the changed blocks.
        segments += diffLines(
            compareLeft, middleA, compareRight, middleB, granularity: granularity, options: options)
        if suffix > 0 {
            segments.append(
                DiffSegment(
                    operation: .equal, a: (compareLeft.count - suffix)..<compareLeft.count,
                    b: (compareRight.count - suffix)..<compareRight.count))
        }
        return DiffResult(a: left, b: right, segments: merge(segments))
    }

    // MARK: lines

    static func diffLines(
        _ a: [UInt8], _ ra: Range<Int>, _ b: [UInt8], _ rb: Range<Int>, granularity: DiffGranularity,
        options: DiffOptions
    ) -> [DiffSegment] {
        if ra.isEmpty && rb.isEmpty { return [] }
        let linesA = lines(a, ra)
        let linesB = lines(b, rb)
        var ids: [ArraySlice<UInt8>: Int] = [:]
        func id(_ text: ArraySlice<UInt8>) -> Int {
            if let known = ids[text] { return known }
            let next = ids.count
            ids[text] = next
            return next
        }
        let keysA = linesA.map { id(a[$0]) }
        let keysB = linesB.map { id(b[$0]) }
        var segments: [DiffSegment] = []
        var pendingA: [Range<Int>] = []
        var pendingB: [Range<Int>] = []
        var positionA = ra.lowerBound
        var positionB = rb.lowerBound
        func flushChange() {
            guard !pendingA.isEmpty || !pendingB.isEmpty else { return }
            let blockA =
                (pendingA.first?.lowerBound ?? pendingA.last?.upperBound ?? positionA)
                ..<(pendingA.last?.upperBound ?? positionA)
            let blockB =
                (pendingB.first?.lowerBound ?? pendingB.last?.upperBound ?? positionB)
                ..<(pendingB.last?.upperBound ?? positionB)
            segments += refine(a, blockA, b, blockB, granularity: granularity, options: options)
            pendingA = []
            pendingB = []
        }
        for step in myers(keysA, keysB) {
            switch step.operation {
            case .equal:
                flushChange()
                let rangeA = linesA[step.a.lowerBound].lowerBound..<linesA[step.a.upperBound - 1].upperBound
                let rangeB = linesB[step.b.lowerBound].lowerBound..<linesB[step.b.upperBound - 1].upperBound
                segments.append(DiffSegment(operation: .equal, a: rangeA, b: rangeB))
                positionA = rangeA.upperBound
                positionB = rangeB.upperBound
            case .delete:
                pendingA += step.a.map { linesA[$0] }
            case .insert:
                pendingB += step.b.map { linesB[$0] }
            }
        }
        flushChange()
        return segments
    }

    /// Line ranges (each including its newline) covering `range`.
    static func lines(_ bytes: [UInt8], _ range: Range<Int>) -> [Range<Int>] {
        var result: [Range<Int>] = []
        var start = range.lowerBound
        var index = range.lowerBound
        while index < range.upperBound {
            if bytes[index] == 0x0A {
                result.append(start..<(index + 1))
                start = index + 1
            }
            index += 1
        }
        if start < range.upperBound { result.append(start..<range.upperBound) }
        return result
    }

    // MARK: refining a changed block

    static func refine(
        _ a: [UInt8], _ ra: Range<Int>, _ b: [UInt8], _ rb: Range<Int>, granularity: DiffGranularity,
        options: DiffOptions
    ) -> [DiffSegment] {
        let tokensA = granularity == .word ? tokens(a, ra) : ra.map { $0..<($0 + 1) }
        let tokensB = granularity == .word ? tokens(b, rb) : rb.map { $0..<($0 + 1) }
        let skipWhitespace = options.ignoreWhitespace && granularity == .word
        let keptA = skipWhitespace ? tokensA.filter { !isSpaceToken(a, $0) } : tokensA
        let keptB = skipWhitespace ? tokensB.filter { !isSpaceToken(b, $0) } : tokensB
        var ids: [ArraySlice<UInt8>: Int] = [:]
        func id(_ text: ArraySlice<UInt8>) -> Int {
            if let known = ids[text] { return known }
            let next = ids.count
            ids[text] = next
            return next
        }
        let keysA = keptA.map { id(a[$0]) }
        let keysB = keptB.map { id(b[$0]) }
        if keysA.isEmpty && keysB.isEmpty {
            // Only whitespace changed and it is ignored.
            return ra.isEmpty && rb.isEmpty ? [] : [DiffSegment(operation: .equal, a: ra, b: rb)]
        }
        var result: [DiffSegment] = []
        for step in myers(keysA, keysB) {
            let rangeA =
                step.a.isEmpty
                ? (step.a.lowerBound < keptA.count ? keptA[step.a.lowerBound].lowerBound : ra.upperBound)..<(step
                    .a.lowerBound < keptA.count ? keptA[step.a.lowerBound].lowerBound : ra.upperBound)
                : keptA[step.a.lowerBound].lowerBound..<keptA[step.a.upperBound - 1].upperBound
            let rangeB =
                step.b.isEmpty
                ? (step.b.lowerBound < keptB.count ? keptB[step.b.lowerBound].lowerBound : rb.upperBound)..<(step
                    .b.lowerBound < keptB.count ? keptB[step.b.lowerBound].lowerBound : rb.upperBound)
                : keptB[step.b.lowerBound].lowerBound..<keptB[step.b.upperBound - 1].upperBound
            result.append(DiffSegment(operation: step.operation, a: rangeA, b: rangeB))
        }
        return result
    }

    /// Words (letters, digits, `_` and non-ASCII bytes), runs of whitespace, single punctuation.
    static func tokens(_ bytes: [UInt8], _ range: Range<Int>) -> [Range<Int>] {
        var result: [Range<Int>] = []
        var index = range.lowerBound
        while index < range.upperBound {
            let start = index
            let byte = bytes[index]
            if isWordByte(byte) {
                while index < range.upperBound, isWordByte(bytes[index]) { index += 1 }
            } else if isSpace(byte) {
                while index < range.upperBound, isSpace(bytes[index]) { index += 1 }
            } else {
                index += 1
            }
            result.append(start..<index)
        }
        return result
    }

    static func isWordByte(_ byte: UInt8) -> Bool {
        (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
            || byte == 0x5F
            || byte >= 0x80
    }

    static func isSpace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    static func isSpaceToken(_ bytes: [UInt8], _ range: Range<Int>) -> Bool {
        !range.isEmpty && isSpace(bytes[range.lowerBound])
    }

    // MARK: Myers

    /// One run of a Myers edit script, as index ranges into the two sequences.
    struct Step: Equatable {
        var operation: DiffOperation
        var a: Range<Int>
        var b: Range<Int>
    }

    /// The shortest edit script from `a` to `b` (Myers 1986), runs merged. Past `maxEditDistance`
    /// the whole input is one delete + insert.
    static func myers(_ a: [Int], _ b: [Int]) -> [Step] {
        let n = a.count
        let m = b.count
        if n == 0 && m == 0 { return [] }
        if n == 0 { return [Step(operation: .insert, a: 0..<0, b: 0..<m)] }
        if m == 0 { return [Step(operation: .delete, a: 0..<n, b: 0..<0)] }
        let maxD = min(n + m, maxEditDistance)
        let offset = maxD + 1
        var v = [Int](repeating: 0, count: 2 * maxD + 3)
        var trace: [[Int]] = []
        var found = false
        search: for d in 0...maxD {
            trace.append(v)
            for k in stride(from: -d, through: d, by: 2) {
                var x: Int
                if k == -d || (k != d && v[offset + k - 1] < v[offset + k + 1]) {
                    x = v[offset + k + 1]
                } else {
                    x = v[offset + k - 1] + 1
                }
                var y = x - k
                while x < n, y < m, a[x] == b[y] {
                    x += 1
                    y += 1
                }
                v[offset + k] = x
                if x >= n && y >= m {
                    found = true
                    break search
                }
            }
        }
        guard found else {
            return [
                Step(operation: .delete, a: 0..<n, b: 0..<0), Step(operation: .insert, a: n..<n, b: 0..<m),
            ]
        }
        // Backtrack through the saved V arrays.
        var steps: [Step] = []
        var x = n
        var y = m
        for d in stride(from: trace.count - 1, through: 0, by: -1) {
            let vd = trace[d]
            let k = x - y
            let previousK: Int
            if d == 0 {
                previousK = 0
            } else if k == -d || (k != d && vd[offset + k - 1] < vd[offset + k + 1]) {
                previousK = k + 1
            } else {
                previousK = k - 1
            }
            let previousX = d == 0 ? 0 : vd[offset + previousK]
            let previousY = previousX - previousK
            // Diagonal (equal) run.
            while x > previousX && y > previousY {
                steps.append(Step(operation: .equal, a: (x - 1)..<x, b: (y - 1)..<y))
                x -= 1
                y -= 1
            }
            if d > 0 {
                if x == previousX {
                    steps.append(Step(operation: .insert, a: x..<x, b: (y - 1)..<y))
                } else {
                    steps.append(Step(operation: .delete, a: (x - 1)..<x, b: y..<y))
                }
                x = previousX
                y = previousY
            }
        }
        // Merge adjacent steps of the same kind.
        var merged: [Step] = []
        for step in steps.reversed() {
            if var last = merged.last, last.operation == step.operation,
                last.a.upperBound == step.a.lowerBound, last.b.upperBound == step.b.lowerBound
            {
                last.a = last.a.lowerBound..<step.a.upperBound
                last.b = last.b.lowerBound..<step.b.upperBound
                merged[merged.count - 1] = last
            } else {
                merged.append(step)
            }
        }
        return merged
    }

    // MARK: helpers

    static func merge(_ segments: [DiffSegment]) -> [DiffSegment] {
        var result: [DiffSegment] = []
        for segment in segments where !(segment.a.isEmpty && segment.b.isEmpty) {
            if var last = result.last, last.operation == segment.operation,
                last.a.upperBound == segment.a.lowerBound,
                last.b.upperBound == segment.b.lowerBound
            {
                last.a = last.a.lowerBound..<segment.a.upperBound
                last.b = last.b.lowerBound..<segment.b.upperBound
                result[result.count - 1] = last
            } else {
                result.append(segment)
            }
        }
        return result
    }

    static func lower(_ bytes: [UInt8]) -> [UInt8] {
        bytes.map { $0 >= 0x41 && $0 <= 0x5A ? $0 + 32 : $0 }
    }

    static func pretty(_ bytes: [UInt8]) -> [UInt8]? {
        guard let object = try? JSONSerialization.jsonObject(with: Data(bytes), options: [.fragmentsAllowed]),
            let data = try? JSONSerialization.data(
                withJSONObject: object,
                options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes])
        else { return nil }
        return [UInt8](data)
    }
}

/// Namespace and module marker for the `GulpDiff` module.
public enum GulpDiff {
    /// The module's name, used in diagnostics.
    public static let moduleName = "GulpDiff"
}
