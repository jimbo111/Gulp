// GulpTLS — host names as they go into certificates (F02 §5): lowercase, no trailing dot, IDNs in
// A-label (punycode) form, and IP literals recognised so they get an IP SAN (TLS-012).

/// What a leaf certificate is minted for.
public enum CertificateSubject: Sendable, Hashable, CustomStringConvertible {
    /// A DNS name, normalised (lowercase, no trailing dot, A-labels).
    case dns(String)
    /// An IPv4 (4 bytes) or IPv6 (16 bytes) address.
    case ip([UInt8], text: String)

    /// Parse a host from SNI, a CONNECT line or a URL. Brackets around IPv6 literals are accepted.
    public init(host: String) {
        var host = host
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        if let bytes = IPAddressParser.ipv4(host) ?? IPAddressParser.ipv6(host) {
            self = .ip(bytes, text: host.lowercased())
        } else {
            self = .dns(HostName.normalize(host))
        }
    }

    /// The cache key and certificate common name.
    public var description: String {
        switch self {
        case .dns(let name): name
        case .ip(_, let text): text
        }
    }
}

/// Host-name normalisation for certificate SANs and cache keys.
public enum HostName {
    /// Lowercase, strip one trailing dot, and convert non-ASCII labels to `xn--` A-labels.
    public static func normalize(_ host: String) -> String {
        var host = host
        if host.hasSuffix(".") { host.removeLast() }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false).map { label -> String in
            let lower = label.lowercased()
            if lower.unicodeScalars.allSatisfy(\.isASCII) { return lower }
            return "xn--" + Punycode.encode(lower)
        }
        return labels.joined(separator: ".")
    }
}

/// RFC 3492 punycode encoder (the A-label body, without the `xn--` prefix).
public enum Punycode {
    private static let base = 36
    private static let tMin = 1
    private static let tMax = 26
    private static let skew = 38
    private static let damp = 700
    private static let initialBias = 72
    private static let initialN = 128

    /// Encode a Unicode label.
    public static func encode(_ input: String) -> String {
        let scalars = input.unicodeScalars.map { Int($0.value) }
        var output = scalars.filter { $0 < 0x80 }.map { Character(UnicodeScalar(UInt8($0))) }
        let basicCount = output.count
        var handled = basicCount
        if basicCount > 0 { output.append("-") }
        var n = initialN
        var delta = 0
        var bias = initialBias
        while handled < scalars.count {
            let next = scalars.filter { $0 >= n }.min() ?? n
            delta += (next - n) * (handled + 1)
            n = next
            for scalar in scalars {
                if scalar < n { delta += 1 }
                if scalar == n {
                    var q = delta
                    var k = base
                    while true {
                        let t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias)
                        if q < t { break }
                        output.append(digit(t + (q - t) % (base - t)))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(digit(q))
                    bias = adapt(delta, handled + 1, handled == basicCount)
                    delta = 0
                    handled += 1
                }
            }
            delta += 1
            n += 1
        }
        return String(output)
    }

    private static func digit(_ value: Int) -> Character {
        Character(UnicodeScalar(UInt8(value < 26 ? value + 97 : value + 22)))
    }

    private static func adapt(_ delta: Int, _ count: Int, _ first: Bool) -> Int {
        var delta = first ? delta / damp : delta / 2
        delta += delta / count
        var k = 0
        while delta > ((base - tMin) * tMax) / 2 {
            delta /= base - tMin
            k += base
        }
        return k + (base - tMin + 1) * delta / (delta + skew)
    }
}

/// IP literal parsing without platform sockets APIs.
enum IPAddressParser {
    static func ipv4(_ text: String) -> [UInt8]? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var bytes: [UInt8] = []
        for part in parts {
            guard !part.isEmpty, part.count <= 3, part.allSatisfy(\.isASCIIDigit),
                let value = UInt8(part)
            else { return nil }
            bytes.append(value)
        }
        return bytes
    }

    static func ipv6(_ text: String) -> [UInt8]? {
        guard text.contains(":") else { return nil }
        var text = Substring(text)
        if let percent = text.firstIndex(of: "%") { text = text[..<percent] }  // zone id
        var tail: [UInt8] = []
        // An embedded IPv4 tail (::ffff:1.2.3.4).
        if let lastColon = text.lastIndex(of: ":"), text[text.index(after: lastColon)...].contains(".") {
            guard let v4 = ipv4(String(text[text.index(after: lastColon)...])) else { return nil }
            tail = v4
            text = text[...lastColon]
            if text.hasSuffix(":"), !text.hasSuffix("::") { text = text.dropLast() }
        }
        var halves = [String(text)]
        if let gap = text.firstRange(of: "::") {
            let after = text[gap.upperBound...]
            guard after.firstRange(of: "::") == nil else { return nil }
            halves = [String(text[..<gap.lowerBound]), String(after)]
        }
        func groups(_ part: String) -> [UInt16]? {
            if part.isEmpty { return [] }
            var result: [UInt16] = []
            for group in part.split(separator: ":", omittingEmptySubsequences: false) {
                guard !group.isEmpty, group.count <= 4, let value = UInt16(group, radix: 16) else {
                    return nil
                }
                result.append(value)
            }
            return result
        }
        guard let head = groups(halves[0]) else { return nil }
        let rest = halves.count == 2 ? groups(halves[1]) : []
        guard let rest else { return nil }
        let tailGroups = tail.count / 2
        let explicit = head.count + rest.count + tailGroups
        let all: [UInt16]
        if halves.count == 2 {
            guard explicit < 8 else { return nil }
            all = head + Array(repeating: 0, count: 8 - explicit) + rest
        } else {
            guard explicit == 8 else { return nil }
            all = head
        }
        return all.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xFF)] } + tail
    }
}

extension Character {
    fileprivate var isASCIIDigit: Bool { ("0"..."9").contains(self) }
}
