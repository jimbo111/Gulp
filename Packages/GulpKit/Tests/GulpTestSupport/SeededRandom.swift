// GulpTestSupport — shared helpers for the test targets. Randomized tests must be reproducible: an
// unseeded generator turns a rare input into a flaky red that nobody can replay. Every test that needs
// randomness uses `SplitMix64(seed:)` (Scripts/rules-check.sh bans `SystemRandomNumberGenerator()` and
// generator-less `.random(in:)` / `.randomElement()` under Tests/).

import Foundation

/// A deterministic SplitMix64 PRNG: reproducible from its seed, and good enough for fuzz inputs.
public struct SplitMix64: RandomNumberGenerator, Sendable {
    /// The internal state (advances on every draw).
    public var state: UInt64

    /// A generator seeded with `seed`; the same seed always yields the same sequence.
    public init(seed: UInt64) { state = seed }

    /// The next 64 random bits.
    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    /// A lowercase hex token of `symbols` characters.
    public mutating func hexToken(_ symbols: Int) -> String {
        var out = ""
        while out.count < symbols { out += String(format: "%016llx", next()) }
        return String(out.prefix(symbols))
    }
}
