// GulpCodec — scripted WebSocket message sequences (F15 §2.3, WSX-008). A stateful protocol often needs
// "send A, wait for a frame matching X, then send B" over one connection (a handshake, a subscribe/ack,
// a login challenge). This models such a sequence as an ordered list of steps that a runner drives over
// a single `openWebSocket` connection; the step model and the match evaluation are pure and tested,
// while the live I/O lives in the CLI/macro runner.

import Foundation

/// One step of a scripted WebSocket sequence.
public enum WSScriptStep: Sendable, Equatable {
    /// Send a text frame.
    case send(String)
    /// Wait for the next received frame and require it to match (substring, or regex when `isRegex`).
    /// `timeoutMs` bounds the wait.
    case expect(pattern: String, isRegex: Bool, timeoutMs: Int)
}

/// An ordered scripted WebSocket sequence.
public struct WSScript: Sendable, Equatable {
    /// The steps, in order.
    public let steps: [WSScriptStep]

    /// A script.
    public init(steps: [WSScriptStep]) {
        self.steps = steps
    }

    /// Parse a simple line-based script. Blank lines and `#` comments are ignored. Each line is one of:
    /// - `send <text>` — send a text frame (the rest of the line, verbatim).
    /// - `expect <substring>` — the next frame must contain `<substring>`.
    /// - `expect-regex <pattern>` — the next frame must match `<pattern>`.
    /// An optional trailing `@<ms>` on an expect line sets its timeout (default 2000 ms).
    public static func parse(_ text: String) -> WSScript {
        var steps: [WSScriptStep] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if let rest = dropPrefix("send ", line) {
                steps.append(.send(rest))
            } else if let rest = dropPrefix("expect-regex ", line) {
                let (pattern, timeout) = splitTimeout(rest)
                steps.append(.expect(pattern: pattern, isRegex: true, timeoutMs: timeout))
            } else if let rest = dropPrefix("expect ", line) {
                let (pattern, timeout) = splitTimeout(rest)
                steps.append(.expect(pattern: pattern, isRegex: false, timeoutMs: timeout))
            }
        }
        return WSScript(steps: steps)
    }

    private static func dropPrefix(_ prefix: String, _ line: String) -> String? {
        line.hasPrefix(prefix) ? String(line.dropFirst(prefix.count)) : nil
    }

    /// Split a trailing `@<ms>` timeout off an expect pattern (default 2000 ms).
    private static func splitTimeout(_ text: String) -> (pattern: String, timeoutMs: Int) {
        guard let at = text.lastIndex(of: "@"), let ms = Int(text[text.index(after: at)...]) else {
            return (text, 2000)
        }
        return (String(text[..<at]).trimmingCharacters(in: .whitespaces), ms)
    }
}

/// Evaluates whether a received frame satisfies an `expect` step.
public enum WSScriptMatch {
    /// Whether `frame` satisfies `step`. A `send` step never "matches" (it is not a wait).
    public static func matches(_ frame: String, step: WSScriptStep) -> Bool {
        guard case .expect(let pattern, let isRegex, _) = step else { return false }
        if isRegex {
            return frame.range(of: pattern, options: .regularExpression) != nil
        }
        return frame.contains(pattern)
    }
}
