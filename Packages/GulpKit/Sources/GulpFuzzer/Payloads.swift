// GulpFuzzer — payload sources and processing (F07 FUZ-010…FUZ-014). Sources generate lazily, so
// huge sets (a brute-forcer, a big wordlist) never materialise; counts are computed up front for the
// progress bar. Processing is an ordered pipeline per set, built on the Decoder's transforms (F12)
// and Transform Tags (FUZ-013).

import Foundation
import GulpCodec

/// Where a set's payloads come from (FUZ-010).
public enum PayloadSource: Sendable, Hashable, Codable {
    /// A typed or pasted list.
    case list([String])
    /// A wordlist file, one payload per line (empty lines and `#` comments skipped).
    case file(path: String)
    /// Numbers from…to by step, zero-padded to `minDigits`, decimal or hex.
    case numbers(from: Int, to: Int, step: Int, minDigits: Int, hex: Bool)
    /// Dates from…to every `stepDays`, formatted (`yyyy-MM-dd`…).
    case dates(from: Date, to: Date, stepDays: Int, format: String)
    /// Every string over `charset` with length minLength…maxLength.
    case bruteForce(charset: String, minLength: Int, maxLength: Int)
    /// `count` empty payloads (repeat the base request).
    case null(count: Int)
    /// The position's own base value (once).
    case sameAsBase
    /// FUZ-014: the value grep-extracted (extract #`extractIndex`) from the previous response;
    /// `initial` for the first request; `count` requests. Runs the attack one request at a time.
    case recursiveGrep(extractIndex: Int, initial: String, count: Int)

    /// How many payloads (saturating at Int.max).
    public func count(base: [UInt8]) -> Int {
        switch self {
        case .list(let items): return items.count
        case .file(let path): return (try? Self.lines(path).count) ?? 0
        case .numbers(let from, let to, let step, _, _):
            guard step != 0, (step > 0 && from <= to) || (step < 0 && from >= to) else {
                return from == to ? 1 : 0
            }
            return (to - from) / step + 1
        case .dates(let from, let to, let stepDays, _):
            guard stepDays > 0, from <= to else { return 0 }
            return Int(to.timeIntervalSince(from) / Double(stepDays * 86_400)) + 1
        case .bruteForce(let charset, let minLength, let maxLength):
            let size = charset.unicodeScalars.count
            var total = 0
            for length in max(0, minLength)...max(minLength, maxLength) {
                let (power, overflow) = Self.power(size, length)
                if overflow { return .max }
                let (sum, sumOverflow) = total.addingReportingOverflow(power)
                if sumOverflow { return .max }
                total = sum
            }
            return total
        case .null(let count): return max(0, count)
        case .sameAsBase: return 1
        case .recursiveGrep(_, _, let count): return max(0, count)
        }
    }

    static func power(_ base: Int, _ exponent: Int) -> (Int, Bool) {
        var result = 1
        for _ in 0..<exponent {
            let (next, overflow) = result.multipliedReportingOverflow(by: base)
            if overflow { return (.max, true) }
            result = next
        }
        return (result, false)
    }

    /// The payloads, lazily (`base` is the position's base value).
    public func payloads(base: [UInt8]) -> AnySequence<[UInt8]> {
        switch self {
        case .list(let items): return AnySequence(items.lazy.map { Array($0.utf8) })
        case .file(let path): return AnySequence(((try? Self.lines(path)) ?? []).lazy.map { Array($0.utf8) })
        case .numbers(let from, let to, let step, let minDigits, let hex):
            let count = self.count(base: base)
            return AnySequence(
                (0..<count).lazy.map { index in
                    let value = from + index * step
                    var text = String(abs(value), radix: hex ? 16 : 10)
                    if text.count < minDigits {
                        text = String(repeating: "0", count: minDigits - text.count) + text
                    }
                    return Array(((value < 0 ? "-" : "") + text).utf8)
                })
        case .dates(let from, _, let stepDays, let format):
            let count = self.count(base: base)
            return AnySequence(
                (0..<count).lazy.map { index in
                    let formatter = DateFormatter()
                    formatter.locale = Locale(identifier: "en_US_POSIX")
                    formatter.timeZone = TimeZone(identifier: "UTC")
                    formatter.dateFormat = format
                    return Array(
                        formatter.string(from: from.addingTimeInterval(Double(index * stepDays * 86_400)))
                            .utf8)
                })
        case .bruteForce(let charset, let minLength, let maxLength):
            let alphabet = charset.unicodeScalars.map { Array(String($0).utf8) }
            return AnySequence(
                BruteForceSequence(alphabet: alphabet, minLength: max(0, minLength), maxLength: maxLength))
        case .null(let count): return AnySequence((0..<max(0, count)).lazy.map { _ in [] })
        case .sameAsBase: return AnySequence([base])
        case .recursiveGrep(_, let initial, let count):
            // Placeholders: the runner substitutes the extracted value (see FuzzAttack).
            return AnySequence((0..<max(0, count)).lazy.map { _ in Array(initial.utf8) })
        }
    }

    /// The lines of a wordlist (cached per path for the attack's duration by the caller).
    static func lines(_ path: String) throws -> [String] {
        let text = try String(contentsOfFile: (path as NSString).expandingTildeInPath, encoding: .utf8)
        return text.split(whereSeparator: \.isNewline).map(String.init).filter {
            !$0.isEmpty && !$0.hasPrefix("#")
        }
    }
}

/// Every string over an alphabet, shortest first (an odometer).
struct BruteForceSequence: Sequence {
    let alphabet: [[UInt8]]
    let minLength: Int
    let maxLength: Int

    func makeIterator() -> AnyIterator<[UInt8]> {
        var length = minLength
        var digits = [Int](repeating: 0, count: minLength)
        var done = alphabet.isEmpty && minLength > 0 || maxLength < minLength
        return AnyIterator {
            guard !done else { return nil }
            let value = digits.flatMap { alphabet[$0] }
            // Advance the odometer.
            var position = digits.count - 1
            while position >= 0 {
                digits[position] += 1
                if digits[position] < alphabet.count { break }
                digits[position] = 0
                position -= 1
            }
            if position < 0 {
                length += 1
                if length > maxLength || alphabet.isEmpty {
                    done = true
                } else {
                    digits = [Int](repeating: 0, count: length)
                }
            }
            return value
        }
    }
}

/// Case rules for the processing pipeline.
public enum CaseRule: String, Sendable, Hashable, Codable, CaseIterable {
    case upper, lower, capitalize
}

/// One processing step (FUZ-012, FUZ-013).
public enum PayloadProcessor: Sendable, Hashable, Codable {
    /// Add text before.
    case prefix(String)
    /// Add text after.
    case suffix(String)
    /// Regex replace.
    case matchReplace(pattern: String, replacement: String)
    /// Change case.
    case caseRule(CaseRule)
    /// Any Decoder operation by name (url-encode, base64, sha256, html-encode…), with arguments.
    case transform(String, [String: String])
    /// Skip payloads that match.
    case skipIf(pattern: String)
    /// Reverse the bytes.
    case reverse
    /// Keep `length` bytes from `from` (nil: to the end).
    case substring(from: Int, length: Int?)
    /// A Transform Tag template where `«var(payload)»` is the payload, e.g.
    /// `«base64{admin:«var(payload)»}»` (FUZ-013).
    case tags(String)
}

/// A compiled processing pipeline.
public struct PayloadPipeline: Sendable {
    let processors: [PayloadProcessor]
    let regexes: [Int: NSRegularExpression]

    /// Compile `processors` (invalid regexes throw).
    public init(_ processors: [PayloadProcessor]) throws {
        self.processors = processors
        var regexes: [Int: NSRegularExpression] = [:]
        for (index, processor) in processors.enumerated() {
            switch processor {
            case .matchReplace(let pattern, _), .skipIf(let pattern):
                do {
                    regexes[index] = try NSRegularExpression(pattern: pattern)
                } catch {
                    throw FuzzTemplateError(message: "processor \(index + 1): invalid regex \(pattern)")
                }
            case .transform(let name, _):
                guard Transforms.named(name) != nil else {
                    throw FuzzTemplateError(message: "processor \(index + 1): unknown operation \(name)")
                }
            default: break
            }
        }
        self.regexes = regexes
    }

    /// The processed payload, or nil when a skip rule drops it.
    public func process(_ payload: [UInt8]) throws -> [UInt8]? {
        var value = payload
        for (index, processor) in processors.enumerated() {
            switch processor {
            case .prefix(let text): value = Array(text.utf8) + value
            case .suffix(let text): value += Array(text.utf8)
            case .matchReplace(_, let replacement):
                let text = String(decoding: value, as: UTF8.self)
                value = Array(
                    regexes[index]!.stringByReplacingMatches(
                        in: text, range: NSRange(text.startIndex..., in: text), withTemplate: replacement
                    ).utf8)
            case .caseRule(let rule):
                let text = String(decoding: value, as: UTF8.self)
                switch rule {
                case .upper: value = Array(text.uppercased().utf8)
                case .lower: value = Array(text.lowercased().utf8)
                case .capitalize: value = Array((text.prefix(1).uppercased() + text.dropFirst()).utf8)
                }
            case .transform(let name, let arguments):
                value = try Transforms.require(name).apply(value, arguments)
            case .skipIf:
                let text = String(decoding: value, as: UTF8.self)
                if regexes[index]!.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil {
                    return nil
                }
            case .reverse: value.reverse()
            case .substring(let from, let length):
                let start = min(max(0, from), value.count)
                let end = length.map { min(value.count, start + max(0, $0)) } ?? value.count
                value = Array(value[start..<end])
            case .tags(let template):
                let state = TagState(variables: ["payload": String(decoding: value, as: UTF8.self)])
                value = try TransformTags().evaluate(Array(template.utf8), state: state)
            }
        }
        return value
    }

    /// The first `count` processed payloads of `source` (FUZ-012's live preview).
    public func preview(_ source: PayloadSource, base: [UInt8] = [], count: Int = 20) -> [String] {
        var result: [String] = []
        for payload in source.payloads(base: base) {
            guard result.count < count else { break }
            if let processed = try? process(payload) {
                result.append(String(decoding: processed, as: UTF8.self))
            }
        }
        return result
    }
}

/// One payload set: a source and its processing (FUZ-010, FUZ-012).
public struct PayloadSet: Sendable, Hashable, Codable {
    /// Where payloads come from.
    public var source: PayloadSource
    /// Processing, in order.
    public var processors: [PayloadProcessor]

    /// A set.
    public init(_ source: PayloadSource, processors: [PayloadProcessor] = []) {
        self.source = source
        self.processors = processors
    }
}
