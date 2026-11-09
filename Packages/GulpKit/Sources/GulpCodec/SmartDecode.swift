// GulpCodec — Smart Decode (F12 DEC-003): find the chain of decodings that turns an opaque value
// into something readable (e.g. URL → Base64 → gzip → JSON) and report it as explicit steps the
// user can accept into the stacked editor.
//
// Greedy with a depth cap: at each level the detectors run in priority order and the first whose
// decoding succeeds *and* looks better is taken. "Better" means: a known magic number (gzip, zlib,
// PNG, PDF, ZIP), parseable JSON, or a jump in the share of printable text. JWTs end the chain
// (`jwt-decode` shows header and payload).

import Foundation

/// What Smart Decode found.
public struct SmartDecodeResult: Sendable, Equatable {
    /// The steps, in order.
    public var steps: [TransformStep]
    /// The value after the last step.
    public var output: [UInt8]
    /// The step names, e.g. `["url-decode", "base64-decode", "gunzip"]`.
    public var chain: [String] { steps.map(\.name) }
}

/// Smart Decode.
public enum SmartDecode {
    /// Steps at most.
    public static let maxDepth = 10

    /// Decode `input` as far as the detectors go.
    public static func run(_ input: [UInt8]) -> SmartDecodeResult {
        var value = input
        var steps: [TransformStep] = []
        while steps.count < maxDepth, let (step, next) = nextStep(value) {
            steps.append(step)
            value = next
            if step.name == "jwt-decode" { break }
        }
        return SmartDecodeResult(steps: steps, output: value)
    }

    static func nextStep(_ value: [UInt8]) -> (TransformStep, [UInt8])? {
        let trimmed = trim(value)
        guard !trimmed.isEmpty else { return nil }
        let text = String(decoding: trimmed, as: UTF8.self)
        func attempt(_ name: String, _ input: [UInt8], _ accept: ([UInt8]) -> Bool) -> (
            TransformStep, [UInt8]
        )? {
            guard let output = try? Transforms.named(name)?.apply(input), !output.isEmpty, output != input,
                accept(output)
            else { return nil }
            return (TransformStep(name), output)
        }
        // Compressed data first: magic numbers are unambiguous.
        if trimmed.starts(with: [0x1F, 0x8B]) { return attempt("gunzip", trimmed) { _ in true } }
        if trimmed.count > 2, trimmed[0] == 0x78, [0x01, 0x5E, 0x9C, 0xDA].contains(trimmed[1]) {
            if let step = attempt("zlib-decompress", trimmed, { _ in true }) { return step }
        }
        guard isMostlyText(trimmed) else { return nil }
        if text.range(
            of: #"^(Bearer\s+)?eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$"#,
            options: .regularExpression) != nil
        {
            return attempt("jwt-decode", trimmed) { _ in true }
        }
        if text.range(of: "%[0-9A-Fa-f]{2}", options: .regularExpression) != nil {
            if let step = attempt("url-decode", trimmed, { _ in true }) { return step }
        }
        if text.range(of: "&(#x?[0-9A-Fa-f]+|[a-z]+);", options: .regularExpression) != nil {
            if let step = attempt("html-decode", trimmed, { _ in true }) { return step }
        }
        if text.range(of: #"\\(u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2}|u\{)"#, options: .regularExpression) != nil {
            if let step = attempt("unicode-unescape", trimmed, { _ in true }) { return step }
        }
        if trimmed.count >= 8, trimmed.count.isMultiple(of: 2),
            text.range(of: "^[0-9A-Fa-f]+$", options: .regularExpression) != nil,
            let step = attempt("hex-decode", trimmed, looksDecoded)
        {
            return step
        }
        if trimmed.count >= 8, text.range(of: "^[A-Za-z0-9+/]+={0,2}$", options: .regularExpression) != nil,
            let step = attempt("base64-decode", trimmed, looksDecoded)
        {
            return step
        }
        if trimmed.count >= 8, text.range(of: "^[A-Za-z0-9_-]+={0,2}$", options: .regularExpression) != nil,
            let step = attempt("base64url-decode", trimmed, looksDecoded)
        {
            return step
        }
        if trimmed.count >= 8, text.range(of: "^[A-Z2-7]+=*$", options: .regularExpression) != nil,
            let step = attempt("base32-decode", trimmed, looksDecoded)
        {
            return step
        }
        return nil
    }

    static func trim(_ value: [UInt8]) -> [UInt8] {
        let isSpace: (UInt8) -> Bool = { $0 == 0x20 || $0 == 0x0A || $0 == 0x0D || $0 == 0x09 }
        guard let first = value.firstIndex(where: { !isSpace($0) }),
            let last = value.lastIndex(where: { !isSpace($0) })
        else { return [] }
        return Array(value[first...last])
    }

    /// Share of bytes that are printable ASCII or whitespace.
    static func printableShare(_ bytes: [UInt8]) -> Double {
        guard !bytes.isEmpty else { return 0 }
        let printable = bytes.filter { ($0 >= 0x20 && $0 < 0x7F) || $0 == 0x0A || $0 == 0x0D || $0 == 0x09 }
            .count
        return Double(printable) / Double(bytes.count)
    }

    static func isMostlyText(_ bytes: [UInt8]) -> Bool {
        printableShare(bytes) > 0.95 || String(bytes: bytes, encoding: .utf8) != nil && !bytes.contains(0)
    }

    static let magic: [[UInt8]] = [
        [0x1F, 0x8B], [0x89, 0x50, 0x4E, 0x47], [0x25, 0x50, 0x44, 0x46], [0x50, 0x4B, 0x03, 0x04],
        [0xFF, 0xD8, 0xFF], [0x47, 0x49, 0x46, 0x38],
    ]

    /// A decoding worth taking: known magic, a zlib header, JSON, or (mostly) printable text.
    static func looksDecoded(_ output: [UInt8]) -> Bool {
        if magic.contains(where: { output.starts(with: $0) }) { return true }
        if output.count > 2, output[0] == 0x78, [0x01, 0x5E, 0x9C, 0xDA].contains(output[1]) { return true }
        if (try? JSONSerialization.jsonObject(with: Data(output), options: [.fragmentsAllowed]))
            is [String: Any]
        {
            return true
        }
        if (try? JSONSerialization.jsonObject(with: Data(output), options: [.fragmentsAllowed])) is [Any] {
            return true
        }
        return printableShare(output) >= 0.97 && String(bytes: output, encoding: .utf8) != nil
    }
}
