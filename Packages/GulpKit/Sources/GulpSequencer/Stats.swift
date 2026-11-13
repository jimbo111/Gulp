// GulpSequencer — numerical helpers for the randomness tests (F11 §4). `erfc` comes from the C math
// library; the regularized incomplete gamma function (for chi-square p-values) is implemented here
// with the standard series / continued-fraction split (Numerical Recipes), so the module stays pure
// Swift and testable on Linux.

import Foundation

/// Statistical helpers used by the test battery.
enum Stats {
    /// The complementary error function, `erfc(x)` (from the platform math library).
    static func erfc(_ x: Double) -> Double { Foundation.erfc(x) }

    /// The regularized upper incomplete gamma function `Q(a, x) = Γ(a, x) / Γ(a)`, `a > 0`, `x ≥ 0`.
    /// A chi-square statistic `s` with `k` degrees of freedom has p-value `Q(k/2, s/2)`.
    static func regularizedGammaQ(_ a: Double, _ x: Double) -> Double {
        guard x >= 0, a > 0 else { return .nan }
        if x == 0 { return 1 }
        if x < a + 1 {
            return 1 - lowerSeries(a, x)  // the series converges fast below the peak
        }
        return upperContinuedFraction(a, x)  // the continued fraction converges fast above it
    }

    /// `P(a, x) = γ(a, x) / Γ(a)` via its power series (used for `x < a + 1`).
    private static func lowerSeries(_ a: Double, _ x: Double) -> Double {
        var ap = a
        var sum = 1.0 / a
        var term = sum
        for _ in 0..<1000 {
            ap += 1
            term *= x / ap
            sum += term
            if abs(term) < abs(sum) * 1e-15 { break }
        }
        return sum * exp(-x + a * log(x) - lgamma(a))
    }

    /// `Q(a, x)` via the Lentz continued fraction (used for `x ≥ a + 1`).
    private static func upperContinuedFraction(_ a: Double, _ x: Double) -> Double {
        let tiny = 1e-300
        var b = x + 1 - a
        var c = 1 / tiny
        var d = 1 / b
        var h = d
        for i in 1..<1000 {
            let an = -Double(i) * (Double(i) - a)
            b += 2
            d = an * d + b
            if abs(d) < tiny { d = tiny }
            c = b + an / c
            if abs(c) < tiny { c = tiny }
            d = 1 / d
            let delta = d * c
            h *= delta
            if abs(delta - 1) < 1e-15 { break }
        }
        return exp(-x + a * log(x) - lgamma(a)) * h
    }

    /// The p-value of a chi-square statistic `s` with `df` degrees of freedom.
    static func chiSquareP(_ s: Double, df: Int) -> Double {
        guard df > 0 else { return .nan }
        return regularizedGammaQ(Double(df) / 2, s / 2)
    }

    /// Shannon entropy (in bits) of a boolean sequence given the count of ones and the total.
    static func binaryEntropy(ones: Int, total: Int) -> Double {
        guard total > 0, ones > 0, ones < total else { return 0 }
        let p = Double(ones) / Double(total)
        return -(p * log2(p) + (1 - p) * log2(1 - p))
    }
}
