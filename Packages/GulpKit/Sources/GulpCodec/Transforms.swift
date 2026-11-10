// GulpCodec — the Decoder's operations (F12 §3, DEC-001/002/005) in one registry that the Decoder
// steps, the Inspector popover, Transform Tags (DEC-020) and Fuzzer payload processors all use.
// Every operation works on bytes; text views are for display only. Reversible pairs name their
// inverse and round-trip (F12 acceptance 4).
//
// Hashes and HMACs produce lowercase hex text (what people paste and compare); `raw=true` gives the
// digest bytes. Brotli and zstd are not available (no library in the dependency set; doc 07).

import Crypto
import Foundation

/// What an operation does (DEC-002's step kinds).
public enum TransformKind: String, Sendable, Hashable, CaseIterable {
    /// Encode-as.
    case encode
    /// Decode-as.
    case decode
    /// Hash or HMAC.
    case hash
    /// Convert (case, reverse, escape for a context…).
    case convert
}

/// One registered operation.
public struct Transform: Sendable {
    /// Stable name (used by tags, the CLI and saved chains), e.g. `base64-decode`.
    public let name: String
    /// What it does.
    public let kind: TransformKind
    /// A one-line description.
    public let summary: String
    /// The operation that undoes it, if any.
    public let inverse: String?
    /// Argument names it accepts (`key`, `plus`, …).
    public let arguments: [String]
    let body: @Sendable ([UInt8], [String: String]) throws -> [UInt8]

    /// Apply to `input` with named `arguments`.
    public func apply(_ input: [UInt8], _ arguments: [String: String] = [:]) throws -> [UInt8] {
        try body(input, arguments)
    }
}

/// One step of a chain: an operation and its arguments.
public struct TransformStep: Sendable, Hashable, Codable {
    /// The operation's name.
    public var name: String
    /// Its arguments.
    public var arguments: [String: String]

    /// A step.
    public init(_ name: String, _ arguments: [String: String] = [:]) {
        self.name = name
        self.arguments = arguments
    }
}

/// The registry of operations.
public enum Transforms {
    /// Every operation, by name.
    public static let all: [String: Transform] = {
        var map: [String: Transform] = [:]
        for transform in list { map[transform.name] = transform }
        return map
    }()

    /// The operation named `name`.
    public static func named(_ name: String) -> Transform? { all[name.lowercased()] }

    /// Apply `steps` in order; returns every intermediate value (the input first), so a stacked
    /// editor can show each level (DEC-001).
    public static func run(_ input: [UInt8], _ steps: [TransformStep]) throws -> [[UInt8]] {
        var values = [input]
        for (index, step) in steps.enumerated() {
            guard let transform = named(step.name) else {
                throw CodecError("Step \(index + 1): unknown operation \"\(step.name)\".")
            }
            do {
                values.append(try transform.apply(values[values.count - 1], step.arguments))
            } catch let error as CodecError {
                throw CodecError("Step \(index + 1) (\(step.name)): \(error.message)")
            }
        }
        return values
    }

    /// The steps that undo `steps` (each inverted, in reverse order), or nil if one has no inverse.
    public static func reversed(_ steps: [TransformStep]) -> [TransformStep]? {
        var result: [TransformStep] = []
        for step in steps.reversed() {
            guard let inverse = named(step.name)?.inverse else { return nil }
            result.append(TransformStep(inverse, step.arguments))
        }
        return result
    }

    static func op(
        _ name: String, _ kind: TransformKind, _ summary: String, inverse: String? = nil,
        arguments: [String] = [],
        _ body: @escaping @Sendable ([UInt8], [String: String]) throws -> [UInt8]
    ) -> Transform {
        Transform(
            name: name, kind: kind, summary: summary, inverse: inverse, arguments: arguments, body: body)
    }

    static func flag(_ arguments: [String: String], _ name: String) -> Bool {
        ["1", "true", "yes"].contains(arguments[name]?.lowercased() ?? "")
    }

    static let list: [Transform] = [
        // URL
        op("url-encode", .encode, "Percent-encode reserved and non-ASCII bytes", inverse: "url-decode") {
            input, _ in
            URLCodec.encode(input, all: false)
        },
        op("url-encode-all", .encode, "Percent-encode every byte", inverse: "url-decode") { input, _ in
            URLCodec.encode(input, all: true)
        },
        op(
            "url-decode", .decode, "Decode %XX (plus=true: + as space)", inverse: "url-encode",
            arguments: ["plus"]
        ) {
            input, arguments in URLCodec.decode(input, plusAsSpace: flag(arguments, "plus"))
        },
        // HTML
        op("html-encode", .encode, "Escape & < > \" ' as entities", inverse: "html-decode") { input, _ in
            HTMLCodec.encode(input)
        },
        op("html-decode", .decode, "Decode named and numeric entities", inverse: "html-encode") { input, _ in
            HTMLCodec.decode(input)
        },
        // Base64 family
        op("base64", .encode, "Base64", inverse: "base64-decode") { input, _ in
            Array(Data(input).base64EncodedString().utf8)
        },
        op("base64-decode", .decode, "Base64 (padding and whitespace optional)", inverse: "base64") {
            input, _ in
            try Base64.decode(input, url: false)
        },
        op("base64url", .encode, "Base64URL without padding", inverse: "base64url-decode") { input, _ in
            Base64.encodeURL(input)
        },
        op("base64url-decode", .decode, "Base64URL", inverse: "base64url") { input, _ in
            try Base64.decode(input, url: true)
        },
        op("base32", .encode, "Base32 (RFC 4648)", inverse: "base32-decode") { input, _ in
            Base32.encode(input)
        },
        op("base32-decode", .decode, "Base32 (RFC 4648)", inverse: "base32") { input, _ in
            try Base32.decode(input)
        },
        op("base58", .encode, "Base58 (Bitcoin alphabet)", inverse: "base58-decode") { input, _ in
            Base58.encode(input)
        },
        op("base58-decode", .decode, "Base58 (Bitcoin alphabet)", inverse: "base58") { input, _ in
            try Base58.decode(input)
        },
        // Hex and per-byte numbers
        op("hex", .encode, "Lowercase hex", inverse: "hex-decode") { input, _ in Array(Hex.encode(input).utf8)
        },
        op("hex-decode", .decode, "Hex (spaces, colons and 0x allowed)", inverse: "hex") { input, _ in
            try Hex.decode(input)
        },
        op("decimal", .encode, "Each byte as decimal", inverse: "decimal-decode") { input, _ in
            Array(input.map { String($0) }.joined(separator: " ").utf8)
        },
        op("decimal-decode", .decode, "Decimal byte values", inverse: "decimal") { input, _ in
            try Numbers.decode(input, radix: 10)
        },
        op("octal", .encode, "Each byte as octal", inverse: "octal-decode") { input, _ in
            Array(input.map { String($0, radix: 8) }.joined(separator: " ").utf8)
        },
        op("octal-decode", .decode, "Octal byte values", inverse: "octal") { input, _ in
            try Numbers.decode(input, radix: 8)
        },
        op("binary", .encode, "Each byte as 8 bits", inverse: "binary-decode") { input, _ in
            Array(
                input.map {
                    String(repeating: "0", count: 8 - String($0, radix: 2).count) + String($0, radix: 2)
                }
                .joined(separator: " ").utf8)
        },
        op("binary-decode", .decode, "Binary byte values", inverse: "binary") { input, _ in
            try Numbers.decode(input, radix: 2)
        },
        // Escapes
        op("unicode-escape", .encode, "Non-ASCII as \\uXXXX", inverse: "unicode-unescape") { input, _ in
            Escapes.unicode(input)
        },
        op("unicode-unescape", .decode, "Decode \\uXXXX, \\u{…}, \\xNN", inverse: "unicode-escape") {
            input, _ in
            Escapes.unescape(input)
        },
        op("js-escape", .encode, "JavaScript string escape", inverse: "js-unescape") { input, _ in
            Escapes.js(input)
        },
        op("js-unescape", .decode, "JavaScript string unescape", inverse: "js-escape") { input, _ in
            Escapes.unescape(input)
        },
        op("css-escape", .encode, "CSS escape (\\HEX )", inverse: "css-unescape") { input, _ in
            Escapes.css(input)
        },
        op("css-unescape", .decode, "CSS unescape", inverse: "css-escape") { input, _ in
            Escapes.cssUnescape(input)
        },
        op("json-escape", .encode, "JSON string escape", inverse: "json-unescape") { input, _ in
            Escapes.json(input)
        },
        op("json-unescape", .decode, "JSON string unescape", inverse: "json-escape") { input, _ in
            Escapes.unescape(input)
        },
        op("json-pretty", .convert, "Pretty-print JSON") { input, _ in try JSONText.pretty(input) },
        op("json-minify", .convert, "Minify JSON") { input, _ in try JSONText.minify(input) },
        op("sql-escape", .convert, "Double single quotes") { input, _ in
            Array(String(decoding: input, as: UTF8.self).replacingOccurrences(of: "'", with: "''").utf8)
        },
        op("shell-escape", .convert, "Quote as one POSIX shell argument") { input, _ in
            Array(
                ("'" + String(decoding: input, as: UTF8.self).replacingOccurrences(of: "'", with: "'\\''")
                    + "'").utf8)
        },
        op("regex-escape", .convert, "Escape regex metacharacters") { input, _ in
            let special = Set("\\^$.|?*+()[]{}/")
            return Array(
                String(decoding: input, as: UTF8.self).map { special.contains($0) ? "\\\($0)" : String($0) }
                    .joined().utf8)
        },
        // Compression
        op("gzip", .encode, "gzip", inverse: "gunzip") { input, _ in try Compression.compress(input, .gzip) },
        op("gunzip", .decode, "gzip (or zlib)", inverse: "gzip") { input, _ in
            try Compression.decompress(input, .gzip)
        },
        op("zlib", .encode, "zlib (deflate with header)", inverse: "zlib-decompress") { input, _ in
            try Compression.compress(input, .zlib)
        },
        op("zlib-decompress", .decode, "zlib (or gzip)", inverse: "zlib") { input, _ in
            try Compression.decompress(input, .zlib)
        },
        op("deflate", .encode, "Raw DEFLATE", inverse: "inflate") { input, _ in
            try Compression.compress(input, .raw)
        },
        op("inflate", .decode, "Raw DEFLATE", inverse: "deflate") { input, _ in
            try Compression.decompress(input, .raw)
        },
        // JWT
        op("jwt-decode", .decode, "Header and payload of a JWT as JSON") { input, _ in
            try JWT.decodeForDisplay(String(decoding: input, as: UTF8.self))
        },
        // Hashes
        op("md5", .hash, "MD5", arguments: ["raw"]) { input, arguments in
            Hashes.out(Array(Insecure.MD5.hash(data: input)), arguments)
        },
        op("sha1", .hash, "SHA-1", arguments: ["raw"]) { input, arguments in
            Hashes.out(Array(Insecure.SHA1.hash(data: input)), arguments)
        },
        op("sha256", .hash, "SHA-256", arguments: ["raw"]) { input, arguments in
            Hashes.out(Array(SHA256.hash(data: input)), arguments)
        },
        op("sha384", .hash, "SHA-384", arguments: ["raw"]) { input, arguments in
            Hashes.out(Array(SHA384.hash(data: input)), arguments)
        },
        op("sha512", .hash, "SHA-512", arguments: ["raw"]) { input, arguments in
            Hashes.out(Array(SHA512.hash(data: input)), arguments)
        },
        op("sha3-256", .hash, "SHA3-256", arguments: ["raw"]) { input, arguments in
            Hashes.out(SHA3.hash(input, bits: 256), arguments)
        },
        op("sha3-512", .hash, "SHA3-512", arguments: ["raw"]) { input, arguments in
            Hashes.out(SHA3.hash(input, bits: 512), arguments)
        },
        op("crc32", .hash, "CRC-32", arguments: ["raw"]) { input, arguments in
            let value = Compression.crc32(input)
            return Hashes.out([24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> $0) }, arguments)
        },
        op("hmac-md5", .hash, "HMAC-MD5 (key=…)", arguments: ["key", "raw"]) { input, arguments in
            Hashes.out(
                Array(HMAC<Insecure.MD5>.authenticationCode(for: input, using: Hashes.key(arguments))),
                arguments)
        },
        op("hmac-sha1", .hash, "HMAC-SHA1 (key=…)", arguments: ["key", "raw"]) { input, arguments in
            Hashes.out(
                Array(HMAC<Insecure.SHA1>.authenticationCode(for: input, using: Hashes.key(arguments))),
                arguments)
        },
        op("hmac-sha256", .hash, "HMAC-SHA256 (key=…)", arguments: ["key", "raw"]) { input, arguments in
            Hashes.out(
                Array(HMAC<SHA256>.authenticationCode(for: input, using: Hashes.key(arguments))), arguments)
        },
        op("hmac-sha512", .hash, "HMAC-SHA512 (key=…)", arguments: ["key", "raw"]) { input, arguments in
            Hashes.out(
                Array(HMAC<SHA512>.authenticationCode(for: input, using: Hashes.key(arguments))), arguments)
        },
        // Converters (byte-wise: case and XOR act on bytes, not code points)
        op("upper", .convert, "ASCII upper case") { input, _ in
            input.map { $0 >= 0x61 && $0 <= 0x7A ? $0 - 32 : $0 }
        },
        op("lower", .convert, "ASCII lower case") { input, _ in
            input.map { $0 >= 0x41 && $0 <= 0x5A ? $0 + 32 : $0 }
        },
        op("reverse", .convert, "Reverse the bytes", inverse: "reverse") { input, _ in input.reversed() },
        op("rot13", .convert, "ROT13", inverse: "rot13") { input, _ in
            input.map { byte in
                switch byte {
                case 0x41...0x5A: (byte - 0x41 + 13) % 26 + 0x41
                case 0x61...0x7A: (byte - 0x61 + 13) % 26 + 0x61
                default: byte
                }
            }
        },
        op(
            "xor", .convert, "XOR with key=… (hex=true: key is hex)", inverse: "xor",
            arguments: ["key", "hex"]
        ) {
            input, arguments in
            let key =
                flag(arguments, "hex")
                ? try Hex.decode(Array((arguments["key"] ?? "").utf8)) : Hashes.key(arguments).bytes
            guard !key.isEmpty else { throw CodecError("xor needs a key") }
            return input.enumerated().map { $0.element ^ key[$0.offset % key.count] }
        },
    ]
}

extension SymmetricKey {
    var bytes: [UInt8] { withUnsafeBytes { Array($0) } }
}

enum Hashes {
    static func out(_ digest: [UInt8], _ arguments: [String: String]) -> [UInt8] {
        Transforms.flag(arguments, "raw") ? digest : Array(Hex.encode(digest).utf8)
    }

    static func key(_ arguments: [String: String]) -> SymmetricKey {
        SymmetricKey(data: Array((arguments["key"] ?? "").utf8))
    }
}

enum URLCodec {
    static let unreserved = Set(
        Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~".utf8))

    static func encode(_ input: [UInt8], all: Bool) -> [UInt8] {
        var output: [UInt8] = []
        for byte in input {
            if !all && unreserved.contains(byte) {
                output.append(byte)
            } else {
                output += Array(String(format: "%%%02X", byte).utf8)
            }
        }
        return output
    }

    static func decode(_ input: [UInt8], plusAsSpace: Bool) -> [UInt8] {
        var output: [UInt8] = []
        var index = 0
        while index < input.count {
            let byte = input[index]
            if byte == 0x25, index + 2 < input.count, let high = Hex.value(input[index + 1]),
                let low = Hex.value(input[index + 2])
            {
                output.append(high << 4 | low)
                index += 3
            } else {
                output.append(plusAsSpace && byte == 0x2B ? 0x20 : byte)
                index += 1
            }
        }
        return output
    }
}

enum Hex {
    static func encode(_ bytes: [UInt8]) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var output = [UInt8]()
        output.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            output.append(digits[Int(byte >> 4)])
            output.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: output, as: UTF8.self)
    }

    static func value(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: byte - 0x30
        case 0x41...0x46: byte - 0x41 + 10
        case 0x61...0x66: byte - 0x61 + 10
        default: nil
        }
    }

    static func decode(_ input: [UInt8]) throws -> [UInt8] {
        var text = String(decoding: input, as: UTF8.self).replacingOccurrences(of: "0x", with: "")
            .replacingOccurrences(of: "\\x", with: "")
        text.removeAll { $0 == " " || $0 == ":" || $0.isNewline || $0 == "\t" || $0 == "-" }
        let digits = Array(text.utf8)
        guard digits.count.isMultiple(of: 2) else { throw CodecError("odd number of hex digits") }
        var output: [UInt8] = []
        output.reserveCapacity(digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let high = value(digits[index]), let low = value(digits[index + 1]) else {
                throw CodecError("not hex at position \(index)")
            }
            output.append(high << 4 | low)
        }
        return output
    }
}

enum Numbers {
    static func decode(_ input: [UInt8], radix: Int) throws -> [UInt8] {
        try String(decoding: input, as: UTF8.self).split(whereSeparator: { " ,\n\t".contains($0) }).map {
            part in
            guard let value = UInt8(part, radix: radix) else { throw CodecError("\"\(part)\" is not a byte") }
            return value
        }
    }
}

enum Base64 {
    static func decode(_ input: [UInt8], url: Bool) throws -> [UInt8] {
        var text = String(decoding: input, as: UTF8.self).filter { !$0.isWhitespace }
        if url || text.contains("-") || text.contains("_") {
            text = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        }
        text = text.trimmingCharacters(in: CharacterSet(charactersIn: "="))
        while !text.count.isMultiple(of: 4) { text += "=" }
        guard let data = Data(base64Encoded: text) else { throw CodecError("not valid Base64") }
        return [UInt8](data)
    }

    static func encodeURL(_ input: [UInt8]) -> [UInt8] {
        Array(
            Data(input).base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "").utf8)
    }
}

enum Base32 {
    static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    static func encode(_ input: [UInt8]) -> [UInt8] {
        var output: [UInt8] = []
        var buffer = 0
        var bits = 0
        for byte in input {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                output.append(alphabet[(buffer >> (bits - 5)) & 31])
                bits -= 5
            }
        }
        if bits > 0 { output.append(alphabet[(buffer << (5 - bits)) & 31]) }
        while !output.count.isMultiple(of: 8) { output.append(0x3D) }
        return output
    }

    static func decode(_ input: [UInt8]) throws -> [UInt8] {
        var output: [UInt8] = []
        var buffer = 0
        var bits = 0
        for byte in input where byte != 0x3D && byte != 0x20 && byte != 0x0A {
            let upper = byte >= 0x61 && byte <= 0x7A ? byte - 32 : byte
            guard let value = alphabet.firstIndex(of: upper) else { throw CodecError("not valid Base32") }
            buffer = (buffer << 5) | value
            bits += 5
            if bits >= 8 {
                output.append(UInt8((buffer >> (bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        return output
    }
}

enum Base58 {
    static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

    static func encode(_ input: [UInt8]) -> [UInt8] {
        let zeros = input.prefix { $0 == 0 }.count
        var digits: [UInt8] = []  // base-58 digits, little-endian
        for byte in input {
            var carry = Int(byte)
            for index in digits.indices {
                carry += Int(digits[index]) << 8
                digits[index] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }
        return Array(repeating: alphabet[0], count: zeros) + digits.reversed().map { alphabet[Int($0)] }
    }

    static func decode(_ input: [UInt8]) throws -> [UInt8] {
        let text = input.filter { $0 != 0x20 && $0 != 0x0A }
        let zeros = text.prefix { $0 == alphabet[0] }.count
        var bytes: [UInt8] = []  // little-endian
        for character in text {
            guard let value = alphabet.firstIndex(of: character) else { throw CodecError("not valid Base58") }
            var carry = value
            for index in bytes.indices {
                carry += Int(bytes[index]) * 58
                bytes[index] = UInt8(carry & 0xFF)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xFF))
                carry >>= 8
            }
        }
        return Array(repeating: 0, count: zeros) + bytes.reversed()
    }
}

enum HTMLCodec {
    static let named: [String: String] = [
        "amp": "&", "lt": "<", "gt": ">", "quot": "\"", "apos": "'", "nbsp": "\u{00A0}", "copy": "©",
        "reg": "®",
        "euro": "€", "hellip": "…", "mdash": "—", "ndash": "–", "laquo": "«", "raquo": "»",
    ]

    static func encode(_ input: [UInt8]) -> [UInt8] {
        var output: [UInt8] = []
        for byte in input {
            switch byte {
            case 0x26: output += Array("&amp;".utf8)
            case 0x3C: output += Array("&lt;".utf8)
            case 0x3E: output += Array("&gt;".utf8)
            case 0x22: output += Array("&quot;".utf8)
            case 0x27: output += Array("&#x27;".utf8)
            default: output.append(byte)
            }
        }
        return output
    }

    static func decode(_ input: [UInt8]) -> [UInt8] {
        let text = String(decoding: input, as: UTF8.self)
        guard text.contains("&") else { return input }
        var result = ""
        var index = text.startIndex
        while index < text.endIndex {
            guard text[index] == "&", let semicolon = text[index...].prefix(12).firstIndex(of: ";") else {
                result.append(text[index])
                index = text.index(after: index)
                continue
            }
            let entity = String(text[text.index(after: index)..<semicolon])
            var replacement: String?
            if entity.hasPrefix("#x") || entity.hasPrefix("#X") {
                replacement = UInt32(entity.dropFirst(2), radix: 16).flatMap(Unicode.Scalar.init).map {
                    String($0)
                }
            } else if entity.hasPrefix("#") {
                replacement = UInt32(entity.dropFirst(), radix: 10).flatMap(Unicode.Scalar.init).map {
                    String($0)
                }
            } else {
                replacement = named[entity]
            }
            if let replacement {
                result += replacement
                index = text.index(after: semicolon)
            } else {
                result.append("&")
                index = text.index(after: index)
            }
        }
        return Array(result.utf8)
    }
}

enum Escapes {
    static func unicode(_ input: [UInt8]) -> [UInt8] {
        var result = ""
        for scalar in String(decoding: input, as: UTF8.self).unicodeScalars {
            if scalar == "\\" {
                result += "\\\\"  // so unescaping restores a literal backslash
            } else if scalar.isASCII {
                result.unicodeScalars.append(scalar)
            } else if scalar.value <= 0xFFFF {
                result += String(format: "\\u%04x", scalar.value)
            } else {
                // UTF-16 surrogate pair, as JavaScript and JSON write it.
                let value = scalar.value - 0x10000
                result += String(format: "\\u%04x\\u%04x", 0xD800 + (value >> 10), 0xDC00 + (value & 0x3FF))
            }
        }
        return Array(result.utf8)
    }

    static func js(_ input: [UInt8]) -> [UInt8] {
        var result = ""
        for scalar in String(decoding: input, as: UTF8.self).unicodeScalars {
            switch scalar {
            case "\\": result += "\\\\"
            case "\"": result += "\\\""
            case "'": result += "\\'"
            case "\n": result += "\\n"
            case "\r": result += "\\r"
            case "\t": result += "\\t"
            case "<": result += "\\x3c"  // keep it safe inside <script>
            default:
                if scalar.value < 0x20 {
                    result += String(format: "\\x%02x", scalar.value)
                } else if scalar.isASCII {
                    result.unicodeScalars.append(scalar)
                } else {
                    result += String(decoding: unicode(Array(String(scalar).utf8)), as: UTF8.self)
                }
            }
        }
        return Array(result.utf8)
    }

    static func json(_ input: [UInt8]) -> [UInt8] {
        var result = ""
        for scalar in String(decoding: input, as: UTF8.self).unicodeScalars {
            switch scalar {
            case "\\": result += "\\\\"
            case "\"": result += "\\\""
            case "\n": result += "\\n"
            case "\r": result += "\\r"
            case "\t": result += "\\t"
            default:
                if scalar.value < 0x20 {
                    result += String(format: "\\u%04x", scalar.value)
                } else {
                    result.unicodeScalars.append(scalar)
                }
            }
        }
        return Array(result.utf8)
    }

    /// `\uXXXX` (with surrogate pairs), `\u{X…}`, `\xNN`, `\n`, `\r`, `\t`, `\0`, `\'`, `\"`, `\\`, `\/`.
    static func unescape(_ input: [UInt8]) -> [UInt8] {
        let text = Array(String(decoding: input, as: UTF8.self).unicodeScalars)
        var result = String.UnicodeScalarView()
        var index = 0
        var pendingHigh: UInt32?
        func hexValue(_ from: Int, _ count: Int) -> UInt32? {
            guard from + count <= text.count else { return nil }
            return UInt32(String(String.UnicodeScalarView(text[from..<from + count])), radix: 16)
        }
        while index < text.count {
            let scalar = text[index]
            guard scalar == "\\", index + 1 < text.count else {
                result.append(scalar)
                index += 1
                continue
            }
            let next = text[index + 1]
            var consumed = 2
            var value: UInt32?
            switch next {
            case "u":
                if index + 2 < text.count, text[index + 2] == "{",
                    let close = text[(index + 3)...].firstIndex(of: "}")
                {
                    value = UInt32(String(String.UnicodeScalarView(text[(index + 3)..<close])), radix: 16)
                    consumed = close - index + 1
                } else if let hex = hexValue(index + 2, 4) {
                    value = hex
                    consumed = 6
                }
            case "x":
                if let hex = hexValue(index + 2, 2) {
                    value = hex
                    consumed = 4
                }
            case "n": value = 0x0A
            case "r": value = 0x0D
            case "t": value = 0x09
            case "0": value = 0
            case "b": value = 0x08
            case "f": value = 0x0C
            case "\\", "'", "\"", "/": value = next.value
            default: break
            }
            guard let value else {
                result.append(scalar)
                index += 1
                continue
            }
            if (0xD800...0xDBFF).contains(value) {
                pendingHigh = value
            } else if (0xDC00...0xDFFF).contains(value), let high = pendingHigh {
                let combined = 0x10000 + ((high - 0xD800) << 10) + (value - 0xDC00)
                Unicode.Scalar(combined).map { result.append($0) }
                pendingHigh = nil
            } else if let decoded = Unicode.Scalar(value) {
                result.append(decoded)
            }
            index += consumed
        }
        return Array(String(result).utf8)
    }

    static func css(_ input: [UInt8]) -> [UInt8] {
        var result = ""
        for scalar in String(decoding: input, as: UTF8.self).unicodeScalars {
            let alphanumeric = scalar.isASCII && (CharacterSet.alphanumerics.contains(scalar))
            result += alphanumeric ? String(scalar) : String(format: "\\%x ", scalar.value)
        }
        return Array(result.utf8)
    }

    static func cssUnescape(_ input: [UInt8]) -> [UInt8] {
        let text = String(decoding: input, as: UTF8.self)
        guard let pattern = try? NSRegularExpression(pattern: #"\\([0-9a-fA-F]{1,6}) ?|\\(.)"#) else {
            return input
        }
        var result = ""
        var last = text.startIndex
        for match in pattern.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            guard let range = Range(match.range, in: text) else { continue }
            result += text[last..<range.lowerBound]
            if let hex = Range(match.range(at: 1), in: text), let value = UInt32(text[hex], radix: 16),
                let scalar = Unicode.Scalar(value)
            {
                result.unicodeScalars.append(scalar)
            } else if let literal = Range(match.range(at: 2), in: text) {
                result += text[literal]
            }
            last = range.upperBound
        }
        result += text[last...]
        return Array(result.utf8)
    }
}

enum JSONText {
    static func pretty(_ input: [UInt8]) throws -> [UInt8] {
        guard let object = try? JSONSerialization.jsonObject(with: Data(input), options: [.fragmentsAllowed])
        else {
            throw CodecError("not valid JSON")
        }
        return [UInt8](
            try JSONSerialization.data(
                withJSONObject: object,
                options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes]))
    }

    static func minify(_ input: [UInt8]) throws -> [UInt8] {
        guard let object = try? JSONSerialization.jsonObject(with: Data(input), options: [.fragmentsAllowed])
        else {
            throw CodecError("not valid JSON")
        }
        return [UInt8](
            try JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes]))
    }
}
