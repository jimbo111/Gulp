// GulpSequencer — turn captured tokens into the character- and bit-level sequences the battery runs
// on (F11 §4, SEQ-004/007). Constant framing (a fixed prefix/suffix many tokens share) is stripped so
// only the varying region is analyzed, and the character alphabet drives how many bits each symbol
// carries.

import Foundation

/// The detected character encoding of a token set (for the report and for bit extraction).
public enum TokenEncoding: String, Sendable, Codable {
    case hex
    case base64url
    case base64
    case decimal
    case alphanumeric
    case other

    /// Bits of information each symbol of the alphabet can carry (conservative: `floor(log2 size)`).
    var bitsPerSymbol: Int {
        switch self {
        case .hex: return 4
        case .base64, .base64url: return 6
        case .decimal: return 3
        case .alphanumeric: return 5
        case .other: return 8
        }
    }
}

/// The varying region of a token set and how to read it as symbols and bits.
public struct BitModel: Sendable {
    /// The detected character encoding of the varying region.
    public let encoding: TokenEncoding
    /// The sorted alphabet actually used in the varying region.
    public let alphabet: [Character]
    /// Constant characters stripped from the front of every token (SEQ-007).
    public let strippedPrefix: String
    /// Constant characters stripped from the back of every token (SEQ-007).
    public let strippedSuffix: String
    /// The varying region of each input token, in order.
    public let regions: [String]

    private let index: [Character: Int]
    /// Bits each symbol carries under `encoding`.
    public var bitsPerSymbol: Int { encoding.bitsPerSymbol }

    init(tokens: [String]) {
        let prefix = BitModel.commonPrefix(tokens)
        let suffix = BitModel.commonSuffix(tokens, afterPrefix: prefix.count)
        strippedPrefix = prefix
        strippedSuffix = suffix
        regions = tokens.map { token in
            let start = token.index(token.startIndex, offsetBy: prefix.count)
            let end = token.index(token.endIndex, offsetBy: -suffix.count)
            return start <= end ? String(token[start..<end]) : ""
        }
        let used = Set(regions.joined())
        alphabet = used.sorted()
        index = Dictionary(uniqueKeysWithValues: alphabet.enumerated().map { ($0.element, $0.offset) })
        encoding = BitModel.detect(used)
    }

    /// Symbol indices of a region (each symbol's position in the alphabet).
    public func symbols(_ region: String) -> [Int] { region.compactMap { index[$0] } }

    /// The region as a bit sequence: each symbol contributes `bitsPerSymbol` bits of its index.
    public func bits(_ region: String) -> [Bool] {
        let width = bitsPerSymbol
        var out: [Bool] = []
        out.reserveCapacity(region.count * width)
        for character in region {
            let value = index[character] ?? 0
            for shift in stride(from: width - 1, through: 0, by: -1) {
                out.append((value >> shift) & 1 == 1)
            }
        }
        return out
    }

    static func detect(_ used: Set<Character>) -> TokenEncoding {
        let hex = Set("0123456789abcdefABCDEF")
        let digits = Set("0123456789")
        let b64url = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let b64 = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        let alnum = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        if used.isSubset(of: digits) { return .decimal }
        if used.isSubset(of: hex) { return .hex }
        if used.isSubset(of: b64url) && !used.isSubset(of: alnum) { return .base64url }
        if used.isSubset(of: b64) && !used.isSubset(of: alnum) { return .base64 }
        if used.isSubset(of: alnum) { return .alphanumeric }
        return .other
    }

    static func commonPrefix(_ tokens: [String]) -> String {
        guard let first = tokens.first else { return "" }
        var prefix = Array(first)
        for token in tokens.dropFirst() {
            let chars = Array(token)
            var i = 0
            while i < prefix.count, i < chars.count, prefix[i] == chars[i] { i += 1 }
            prefix = Array(prefix[..<i])
            if prefix.isEmpty { break }
        }
        return String(prefix)
    }

    static func commonSuffix(_ tokens: [String], afterPrefix prefixLen: Int) -> String {
        guard let first = tokens.first else { return "" }
        // Never let the suffix overlap the prefix on the shortest token.
        let maxLen = (tokens.map(\.count).min() ?? 0) - prefixLen
        guard maxLen > 0 else { return "" }
        var suffix = Array(first.reversed())
        for token in tokens.dropFirst() {
            let chars = Array(token.reversed())
            var i = 0
            while i < suffix.count, i < chars.count, suffix[i] == chars[i] { i += 1 }
            suffix = Array(suffix[..<i])
            if suffix.isEmpty { break }
        }
        if suffix.count > maxLen { suffix = Array(suffix[..<maxLen]) }
        return String(suffix.reversed())
    }
}
