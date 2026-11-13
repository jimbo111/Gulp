// GulpScanner — server-side parameter pollution analysis (F23 ADV-022). Sending a parameter twice
// (`?x=a&x=b`) makes different stacks behave differently: first-wins, last-wins, concatenation, or an
// array. A mismatch between a front-end/WAF and the app's choice is what enables filter bypasses, so
// Gulp classifies the app's handling as an observation. Pure classification, so it is unit-tested; the
// CLI sends the probes.

import Foundation

/// How a server handled a duplicated parameter.
public enum ParamHandling: String, Sendable {
    case firstWins = "first-wins"
    case lastWins = "last-wins"
    case concatenated
    case both
    case unknown
}

/// Classify server-side parameter pollution.
public enum ParamPollution {
    /// Given the body when the first value alone is sent (`baseline`) and when the value is duplicated
    /// with a `canary` (`dup`), classify how the duplicate was handled.
    public static func classify(firstValue: String, canary: String, baseline: String, dup: String)
        -> ParamHandling
    {
        let hasFirst = dup.contains(firstValue)
        let hasCanary = dup.contains(canary)
        if hasFirst && hasCanary {
            // Concatenated if they appear adjacent (comma/semicolon-joined), otherwise both are present.
            if dup.contains("\(firstValue),\(canary)") || dup.contains("\(firstValue);\(canary)") {
                return .concatenated
            }
            return .both
        }
        if hasCanary, !hasFirst { return .lastWins }
        if hasFirst, !hasCanary { return .firstWins }
        _ = baseline
        return .unknown
    }

    /// Whether the handling is a notable pollution quirk (anything but a plain first-wins reflection).
    public static func isQuirk(_ handling: ParamHandling) -> Bool {
        switch handling {
        case .lastWins, .concatenated, .both: return true
        case .firstWins, .unknown: return false
        }
    }
}
