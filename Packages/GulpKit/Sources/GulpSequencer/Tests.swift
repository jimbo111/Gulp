// GulpSequencer — the randomness test battery (F11 SEQ-005). Bit-level tests follow the NIST SP 800-22
// family (frequency, block frequency, runs, longest run, approximate entropy, cumulative sums) plus a
// poker / 4-bit chi-square (the FIPS 140-2 poker test, generalized); the character-level test is a
// per-position uniformity chi-square. Each test returns a p-value and a pass/fail; a token source is
// random when every test passes. The significance level is family-wise: with k tests each is judged
// at alpha / k (Bonferroni), so a truly random source fails any test with probability at most alpha.
// (Judging each at alpha would fail one of 8 about 8% of the time and downgrade a perfect CSPRNG.) Formulas are the published ones so each
// test can be checked against reference vectors (SEQ acceptance 3).

import Foundation

/// One test's outcome.
public struct RandomnessTest: Sendable, Codable {
    /// The test's display name.
    public let name: String
    /// The test's p-value in `[0, 1]`, or nil when there were too few bits to run it.
    public let pValue: Double?
    /// Whether the p-value met the significance level (a skipped test counts as passed).
    public let passed: Bool
    /// A short detail for the report, such as the counts behind the statistic or why it was skipped.
    public let note: String

    static func skipped(_ name: String, _ note: String) -> RandomnessTest {
        RandomnessTest(name: name, pValue: nil, passed: true, note: note)
    }
}

/// The bit-level and character-level tests.
enum Battery {
    /// Standard normal CDF, `Φ(x)`.
    static func phi(_ x: Double) -> Double { 0.5 * Stats.erfc(-x / 2.0.squareRoot()) }

    static func all(
        bits: [Bool], symbols: [[Int]], alphabetSize: Int, alpha: Double, bitLevel: Bool
    ) -> [RandomnessTest] {
        // Bit-level tests only run for exact power-of-two encodings (hex, base64), where each symbol
        // maps cleanly to its bits; for decimal/alphanumeric the per-position symbol test carries it.
        var tests: [RandomnessTest] = []
        let alpha = alpha / Double(bitLevel ? 8 : 1)  // per test; keep in step with the list below
        if bitLevel {
            tests += [
                monobitFrequency(bits, alpha: alpha),
                blockFrequency(bits, alpha: alpha),
                runs(bits, alpha: alpha),
                longestRun(bits, alpha: alpha),
                pokerChiSquare(bits, alpha: alpha),
                approximateEntropy(bits, alpha: alpha),
                cumulativeSums(bits, alpha: alpha),
            ]
        }
        tests.append(perPositionUniformity(symbols, alphabetSize: alphabetSize, alpha: alpha))
        return tests
    }

    // MARK: bit-level

    /// SP 800-22 §2.1 — the proportion of ones is close to one half.
    static func monobitFrequency(_ bits: [Bool], alpha: Double) -> RandomnessTest {
        let n = bits.count
        guard n >= 100 else { return .skipped("Monobit frequency", "needs ≥100 bits (have \(n))") }
        let s = bits.reduce(0) { $0 + ($1 ? 1 : -1) }
        let p = Stats.erfc(abs(Double(s)) / (Double(n) * 2).squareRoot())
        return RandomnessTest(
            name: "Monobit frequency", pValue: p, passed: p >= alpha,
            note: "ones are \(bits.filter { $0 }.count)/\(n)")
    }

    /// SP 800-22 §2.2 — each block of M bits has a proportion of ones close to one half.
    static func blockFrequency(_ bits: [Bool], alpha: Double) -> RandomnessTest {
        let n = bits.count
        let m = max(20, n / 100)  // aim for ~100 blocks, at least 20 bits each
        let blocks = n / m
        guard blocks >= 1, n >= 100 else {
            return .skipped("Block frequency", "needs ≥100 bits (have \(n))")
        }
        var chiSq = 0.0
        for b in 0..<blocks {
            let ones = bits[(b * m)..<((b + 1) * m)].filter { $0 }.count
            let pi = Double(ones) / Double(m)
            chiSq += (pi - 0.5) * (pi - 0.5)
        }
        chiSq *= 4 * Double(m)
        let p = Stats.chiSquareP(chiSq, df: blocks)
        return RandomnessTest(
            name: "Block frequency", pValue: p, passed: p >= alpha, note: "\(blocks) blocks of \(m) bits")
    }

    /// SP 800-22 §2.3 — the number of runs (maximal same-value stretches) is as expected.
    static func runs(_ bits: [Bool], alpha: Double) -> RandomnessTest {
        let n = bits.count
        guard n >= 100 else { return .skipped("Runs", "needs ≥100 bits (have \(n))") }
        let ones = bits.filter { $0 }.count
        let pi = Double(ones) / Double(n)
        guard abs(pi - 0.5) < 2 / Double(n).squareRoot() else {
            return RandomnessTest(
                name: "Runs", pValue: 0, passed: false, note: "monobit precondition failed (pi=\(pi))")
        }
        var v = 1
        for i in 1..<n where bits[i] != bits[i - 1] { v += 1 }
        let num = abs(Double(v) - 2 * Double(n) * pi * (1 - pi))
        let den = 2 * (2 * Double(n)).squareRoot() * pi * (1 - pi)
        let p = Stats.erfc(num / den)
        return RandomnessTest(name: "Runs", pValue: p, passed: p >= alpha, note: "\(v) runs")
    }

    /// SP 800-22 §2.4 — the longest run of ones within M-bit blocks (M=8 variant, n≥128).
    static func longestRun(_ bits: [Bool], alpha: Double) -> RandomnessTest {
        let n = bits.count
        guard n >= 128 else { return .skipped("Longest run of ones", "needs ≥128 bits (have \(n))") }
        let m = 8
        let blocks = n / m
        // Classes for M=8: longest ≤1, =2, =3, ≥4.
        var counts = [0, 0, 0, 0]
        for b in 0..<blocks {
            var longest = 0, current = 0
            for bit in bits[(b * m)..<((b + 1) * m)] {
                current = bit ? current + 1 : 0
                longest = max(longest, current)
            }
            switch longest {
            case 0, 1: counts[0] += 1
            case 2: counts[1] += 1
            case 3: counts[2] += 1
            default: counts[3] += 1
            }
        }
        let pi = [0.2148, 0.3672, 0.2305, 0.1875]
        var chiSq = 0.0
        for i in 0..<4 {
            let expected = Double(blocks) * pi[i]
            chiSq += (Double(counts[i]) - expected) * (Double(counts[i]) - expected) / expected
        }
        let p = Stats.chiSquareP(chiSq, df: 3)
        return RandomnessTest(
            name: "Longest run of ones", pValue: p, passed: p >= alpha, note: "\(blocks) blocks of 8 bits")
    }

    /// FIPS 140-2 poker, generalized — 4-bit groups are uniformly distributed (chi-square, 15 df).
    static func pokerChiSquare(_ bits: [Bool], alpha: Double) -> RandomnessTest {
        let groups = bits.count / 4
        guard groups >= 100 else { return .skipped("Poker (4-bit)", "needs ≥400 bits (have \(bits.count))") }
        var counts = [Int](repeating: 0, count: 16)
        for g in 0..<groups {
            var value = 0
            for k in 0..<4 { value = (value << 1) | (bits[g * 4 + k] ? 1 : 0) }
            counts[value] += 1
        }
        let expected = Double(groups) / 16
        let sumSq = counts.reduce(0.0) { $0 + Double($1 * $1) }
        let chiSq = (16.0 / Double(groups)) * sumSq - Double(groups)
        let p = Stats.chiSquareP(chiSq, df: 15)
        _ = expected
        return RandomnessTest(name: "Poker (4-bit)", pValue: p, passed: p >= alpha, note: "\(groups) groups")
    }

    /// SP 800-22 §2.12 — approximate entropy: overlapping m- and (m+1)-bit patterns are as frequent
    /// as randomness predicts.
    static func approximateEntropy(_ bits: [Bool], alpha: Double) -> RandomnessTest {
        let n = bits.count
        let m = 2
        guard n >= 100 else { return .skipped("Approximate entropy", "needs ≥100 bits (have \(n))") }
        func phiM(_ blockLen: Int) -> Double {
            guard blockLen > 0 else { return 0 }
            let size = 1 << blockLen
            var counts = [Int](repeating: 0, count: size)
            for i in 0..<n {
                var value = 0
                for j in 0..<blockLen { value = (value << 1) | (bits[(i + j) % n] ? 1 : 0) }
                counts[value] += 1
            }
            var sum = 0.0
            for c in counts where c > 0 {
                let pr = Double(c) / Double(n)
                sum += pr * log(pr)
            }
            return sum
        }
        let apEn = phiM(m) - phiM(m + 1)
        let chiSq = 2 * Double(n) * (log(2.0) - apEn)
        let p = Stats.chiSquareP(chiSq, df: 1 << (m - 1))
        return RandomnessTest(
            name: "Approximate entropy", pValue: p, passed: p >= alpha,
            note: String(format: "ApEn=%.4f", apEn))
    }

    /// SP 800-22 §2.13 — cumulative sums: the random walk of ±1 steps does not drift too far.
    static func cumulativeSums(_ bits: [Bool], alpha: Double) -> RandomnessTest {
        let n = bits.count
        guard n >= 100 else { return .skipped("Cumulative sums", "needs ≥100 bits (have \(n))") }
        var partial = 0, z = 0
        for bit in bits {
            partial += bit ? 1 : -1
            z = max(z, abs(partial))
        }
        guard z > 0 else {
            return RandomnessTest(name: "Cumulative sums", pValue: 0, passed: false, note: "no variation")
        }
        let sqrtN = Double(n).squareRoot()
        let zd = Double(z)
        var sum1 = 0.0
        var k = Int((-Double(n) / zd + 1) / 4)
        while k <= Int((Double(n) / zd - 1) / 4) {
            sum1 +=
                phi((4 * Double(k) + 1) * zd / sqrtN) - phi((4 * Double(k) - 1) * zd / sqrtN)
            k += 1
        }
        var sum2 = 0.0
        k = Int((-Double(n) / zd - 3) / 4)
        while k <= Int((Double(n) / zd - 1) / 4) {
            sum2 +=
                phi((4 * Double(k) + 3) * zd / sqrtN) - phi((4 * Double(k) + 1) * zd / sqrtN)
            k += 1
        }
        let p = 1 - sum1 + sum2
        return RandomnessTest(
            name: "Cumulative sums", pValue: min(max(p, 0), 1), passed: p >= alpha, note: "max excursion \(z)"
        )
    }

    // MARK: character-level

    /// Per-position uniformity: at each character position, the symbol distribution is uniform over
    /// the alphabet (aggregated chi-square across positions).
    static func perPositionUniformity(_ symbols: [[Int]], alphabetSize: Int, alpha: Double)
        -> RandomnessTest
    {
        guard alphabetSize >= 2, let length = symbols.map(\.count).min(), length >= 1 else {
            return .skipped("Per-position uniformity", "not enough structure")
        }
        let count = symbols.count
        guard count >= 20 else {
            return .skipped("Per-position uniformity", "needs ≥20 tokens (have \(count))")
        }
        var chiSq = 0.0
        var df = 0
        let expected = Double(count) / Double(alphabetSize)
        for position in 0..<length {
            var counts = [Int](repeating: 0, count: alphabetSize)
            for token in symbols where position < token.count { counts[token[position]] += 1 }
            for c in counts { chiSq += (Double(c) - expected) * (Double(c) - expected) / expected }
            df += alphabetSize - 1
        }
        let p = Stats.chiSquareP(chiSq, df: df)
        return RandomnessTest(
            name: "Per-position uniformity", pValue: p, passed: p >= alpha,
            note: "\(length) positions over \(alphabetSize) symbols")
    }
}
