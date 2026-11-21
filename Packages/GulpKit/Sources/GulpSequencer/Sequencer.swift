// GulpSequencer — token randomness analysis (F11). Collect many security-sensitive tokens (session
// cookies, CSRF/reset tokens, API keys) and estimate how much of each is actually unpredictable, with
// a statistical battery and an overall verdict. This is the pure-Swift, Linux-testable core; capture
// (sending through the engine) and the UI build on it.

import Foundation

/// The overall quality verdict for a token source.
public enum TokenVerdict: String, Sendable, Codable {
    case excellent = "Excellent"
    case good = "Good"
    case reasonable = "Reasonable"
    case poor = "Poor"
    case extremelyPoor = "Extremely poor"

    init(ratio: Double) {
        switch ratio {
        case 0.95...: self = .excellent
        case 0.85..<0.95: self = .good
        case 0.65..<0.85: self = .reasonable
        case 0.40..<0.65: self = .poor
        default: self = .extremelyPoor
        }
    }
}

/// The result of analyzing a set of tokens (SEQ-005/006).
public struct SequencerReport: Sendable, Codable {
    /// How many non-empty tokens were analyzed.
    public let sampleCount: Int
    /// How many of them were distinct.
    public let uniqueCount: Int
    /// The detected character encoding of the varying region.
    public let encoding: TokenEncoding
    /// Constant framing stripped from the front of every token.
    public let strippedPrefix: String
    /// Constant framing stripped from the back of every token.
    public let strippedSuffix: String
    /// The symbol length of the varying region actually analyzed (the common/shortest region).
    public let regionSymbolLength: Int
    /// The information capacity of the varying region in bits (symbols × bits per symbol).
    public let regionBits: Int
    /// The conservative headline estimate of effective entropy, in bits.
    public let estimatedBits: Double
    /// The Shannon per-bit upper bound, in bits (always ≥ `estimatedBits`).
    public let shannonBits: Double
    /// The overall verdict, from `estimatedBits` as a share of `regionBits`.
    public let verdict: TokenVerdict
    /// Each battery test's result (empty when the token does not vary).
    public let tests: [RandomnessTest]
    /// Caveats for the reader: stripped framing, varying length, too few samples, duplicates.
    public let warnings: [String]

    /// A one-line summary like "Poor — ~18.2 of 64 bits (3,000 samples)".
    public var summary: String {
        String(
            format: "%@ — ~%.1f of %d bits (%d samples)", verdict.rawValue, estimatedBits, regionBits,
            sampleCount)
    }
}

/// Token randomness analysis.
public enum Sequencer {
    /// The recommended minimum sample count for trustworthy results (SEQ-009).
    public static let recommendedSamples = 100

    /// Analyze `tokens` and return the verdict, entropy estimate and the per-test results.
    /// `alpha` is the family-wise significance level (default 0.01): each of the k tests is judged at
    /// `alpha / k`, so a truly random source fails any test with probability at most `alpha`.
    public static func analyze(tokens rawTokens: [String], alpha: Double = 0.01) -> SequencerReport {
        let tokens = rawTokens.filter { !$0.isEmpty }
        let unique = Set(tokens).count
        var warnings: [String] = []

        // A constant (or near-constant) token has no randomness: say so without the full battery.
        guard tokens.count >= 2, unique >= 2 else {
            return SequencerReport(
                sampleCount: tokens.count, uniqueCount: unique, encoding: .other, strippedPrefix: "",
                strippedSuffix: "", regionSymbolLength: 0, regionBits: 0, estimatedBits: 0, shannonBits: 0,
                verdict: .extremelyPoor, tests: [], warnings: ["the token does not vary — no randomness"])
        }

        let model = BitModel(tokens: tokens)
        if !model.strippedPrefix.isEmpty || !model.strippedSuffix.isEmpty {
            warnings.append(
                "stripped constant framing: prefix \"\(model.strippedPrefix)\", suffix \"\(model.strippedSuffix)\""
            )
        }
        let lengths = Set(model.regions.map(\.count))
        if lengths.count > 1 { warnings.append("token length varies (\(lengths.sorted())) — itself a smell") }
        if tokens.count < recommendedSamples {
            warnings.append("only \(tokens.count) samples; ~\(recommendedSamples)+ gives trustworthy results")
        }
        if unique < tokens.count { warnings.append("\(tokens.count - unique) duplicate tokens") }

        let symbolMatrix = model.regions.map { model.symbols($0) }
        let alphabetSize = model.alphabet.count
        let bitLevel =
            [TokenEncoding.hex, .base64, .base64url].contains(model.encoding)
            && alphabetSize <= (1 << model.bitsPerSymbol)
        let concatenated = bitLevel ? model.regions.flatMap { model.bits($0) } : []
        let tests = Battery.all(
            bits: concatenated, symbols: symbolMatrix, alphabetSize: alphabetSize, alpha: alpha,
            bitLevel: bitLevel)

        // Character-level entropy over the common region: for each position, the Shannon and
        // (conservative) min-entropy of its symbol distribution. This is alphabet-correct for any
        // encoding. The estimate is then scaled by the battery pass rate so a structured token (e.g. a
        // counter) is rated low even where a single position looks uniform.
        let minSymbols = model.regions.map(\.count).min() ?? 0
        let bitsPerSymbol = alphabetSize > 1 ? log2(Double(alphabetSize)) : 0
        var shannon = 0.0
        for position in 0..<minSymbols {
            var counts = [Int](repeating: 0, count: alphabetSize)
            var total = 0
            for token in symbolMatrix where position < token.count {
                counts[token[position]] += 1
                total += 1
            }
            guard total > 0 else { continue }
            for c in counts where c > 0 {
                let p = Double(c) / Double(total)
                shannon -= p * log2(p)
            }
        }
        let run = tests.filter { $0.pValue != nil }
        let passRate = run.isEmpty ? 1 : Double(run.filter(\.passed).count) / Double(run.count)
        let capacity = Double(minSymbols) * bitsPerSymbol
        // Headline "effective entropy": the per-position Shannon entropy, scaled down by the fraction
        // of battery tests that pass so structural weakness a single position can't see is penalized.
        let estimated = shannon * passRate
        let ratio = capacity > 0 ? estimated / capacity : 0

        return SequencerReport(
            sampleCount: tokens.count, uniqueCount: unique, encoding: model.encoding,
            strippedPrefix: model.strippedPrefix, strippedSuffix: model.strippedSuffix,
            regionSymbolLength: minSymbols, regionBits: Int(capacity.rounded()), estimatedBits: estimated,
            shannonBits: shannon, verdict: TokenVerdict(ratio: ratio), tests: tests, warnings: warnings)
    }
}
