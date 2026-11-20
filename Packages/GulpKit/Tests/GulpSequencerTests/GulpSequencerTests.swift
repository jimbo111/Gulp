import Foundation
import GulpTestSupport
import Testing

@testable import GulpSequencer

@Suite("GulpSequencer scaffolding")
struct GulpSequencerScaffolding {
    @Test("module marker is wired")
    func moduleMarker() {
        #expect(GulpSequencer.moduleName == "GulpSequencer")
    }
}

@Suite("Sequencer — numerical helpers (F11 §4)")
struct StatsTests {
    @Test("regularizedGammaQ matches closed forms: Q(1,x)=e^-x and Q(½,x)=erfc(√x)")
    func gammaIdentities() {
        for x in [0.25, 1.0, 2.5, 7.0, 15.0] {
            #expect(abs(Stats.regularizedGammaQ(1, x) - exp(-x)) < 1e-9)
            #expect(abs(Stats.regularizedGammaQ(0.5, x) - Stats.erfc(x.squareRoot())) < 1e-9)
        }
    }

    @Test("chi-square p-values bracket the mean of the distribution")
    func chiSquare() {
        // For df degrees of freedom the mean statistic is df, where Q ≈ 0.5-ish (slightly below).
        #expect(Stats.chiSquareP(0, df: 4) == 1)
        #expect(Stats.chiSquareP(1000, df: 4) < 1e-6)
        let atMean = Stats.chiSquareP(15, df: 15)
        #expect(atMean > 0.3 && atMean < 0.6)
    }
}

@Suite("Sequencer — the randomness battery (SEQ-005)")
struct BatteryTests {
    /// SEQ acceptance 3: every bit-level test passes on a known-good random stream.
    @Test("a high-quality pseudo-random stream passes every bit test")
    func randomPasses() {
        var rng = SplitMix64(seed: 0xDEAD_BEEF)
        var bits: [Bool] = []
        while bits.count < 20_000 {
            let v = rng.next()
            for i in 0..<64 { bits.append((v >> i) & 1 == 1) }
        }
        for test in Battery.all(bits: bits, symbols: [], alphabetSize: 0, alpha: 0.01, bitLevel: true)
        where test.pValue != nil {
            #expect(test.passed, "\(test.name) failed on random: p=\(test.pValue ?? -1)")
        }
    }

    /// SEQ acceptance 3: biased and structured streams fail the right tests.
    @Test("a biased (70% ones) stream fails the frequency tests")
    func biasedFails() {
        var rng = SplitMix64(seed: 7)
        // ~70% ones: set a bit when (next % 10) < 7.
        let bits = (0..<20_000).map { _ in rng.next() % 10 < 7 }
        let tests = Battery.all(bits: bits, symbols: [], alphabetSize: 0, alpha: 0.01, bitLevel: true)
        let monobit = tests.first { $0.name == "Monobit frequency" }
        #expect(monobit?.passed == false)
    }

    @Test("a constant-and-alternating structured stream fails runs or approximate entropy")
    func structuredFails() {
        // 0101…: perfectly balanced ones (monobit passes) but no randomness — runs/ApEn catch it.
        let bits = (0..<20_000).map { $0 % 2 == 0 }
        let tests = Battery.all(bits: bits, symbols: [], alphabetSize: 0, alpha: 0.01, bitLevel: true)
        #expect(tests.contains { !$0.passed }, "a periodic stream should fail at least one test")
    }
}

@Suite("Sequencer — verdicts (SEQ-006, F11 acceptance 1–2)")
struct VerdictTests {
    /// F11 acceptance 2: a CSPRNG token is rated Excellent with an estimate near its bit length.
    @Test("CSPRNG hex tokens are rated Excellent with an estimate near the true bit length")
    func strongTokens() {
        var rng = SplitMix64(seed: 123)
        let tokens = (0..<3_000).map { _ in rng.hexToken(16) }  // 16 hex = 64 bits
        let report = Sequencer.analyze(tokens: tokens)
        #expect(
            report.verdict == .excellent,
            "\(report.summary) — \(report.tests.map { "\($0.name):\($0.passed)" })")
        #expect(report.regionBits == 64)
        #expect(report.estimatedBits > 55, "estimate \(report.estimatedBits) should be near 64")
    }

    /// F11 acceptance 1: a counter/time-derived token is rated Poor with a low estimate; the constant
    /// framing (the high digits that never change) is stripped and reported.
    @Test("a counter-derived token is rated Poor and its constant framing is stripped")
    func weakTokens() {
        // "sess-" + a zero-padded counter from a fixed base: the leading digits are constant.
        let tokens = (0..<3_000).map { i in String(format: "sess-%08d", 100_000 + i) }
        let report = Sequencer.analyze(tokens: tokens)
        #expect(report.verdict == .poor || report.verdict == .extremelyPoor, "\(report.summary)")
        #expect(report.strippedPrefix.contains("sess-"))
        #expect(report.estimatedBits < Double(report.regionBits) * 0.5)
    }

    @Test("a constant token is Extremely poor without running the battery")
    func constantToken() {
        let report = Sequencer.analyze(tokens: Array(repeating: "same-token", count: 500))
        #expect(report.verdict == .extremelyPoor)
        #expect(report.estimatedBits == 0)
        #expect(report.tests.isEmpty)
    }

    @Test("too few samples is flagged as a warning")
    func fewSamples() {
        var rng = SplitMix64(seed: 9)
        let report = Sequencer.analyze(tokens: (0..<30).map { _ in rng.hexToken(16) })
        #expect(report.warnings.contains { $0.contains("samples") })
    }
}

@Suite("Sequencer — token extraction (SEQ-001)")
struct ExtractionTests {
    @Test("a cookie is read by name from Set-Cookie; a regex capture reads the body")
    func extraction() {
        let response = Array(
            ("HTTP/1.1 200 OK\r\nSet-Cookie: other=1; Path=/\r\nSet-Cookie: SID=abc123; HttpOnly\r\n"
                + "Content-Type: text/html\r\n\r\n{\"csrf\":\"tok-999\"}").utf8)
        #expect(TokenLocation.cookie("SID").extract(fromResponse: response) == "abc123")
        #expect(TokenLocation.cookie("missing").extract(fromResponse: response) == nil)
        #expect(TokenLocation.regex("\"csrf\":\"([^\"]+)\"").extract(fromResponse: response) == "tok-999")
    }
}
