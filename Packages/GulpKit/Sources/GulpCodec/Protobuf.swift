// GulpCodec — the protobuf wire format without a schema (F33 GRP-002). A message is a list of
// (field number, wire type, value) triples; decoding keeps every field's exact bytes, so encoding an
// unedited message reproduces the input byte for byte (unknown fields, odd varint encodings and field
// order included). Only an edited field — and the length prefixes that enclose it — is re-encoded.

import Foundation

/// A protobuf wire type.
public enum ProtoWireType: UInt8, Sendable, Hashable, Codable {
    /// Varint (int32/64, uint, sint (zigzag), bool, enum).
    case varint = 0
    /// 8 bytes (fixed64, sfixed64, double).
    case fixed64 = 1
    /// Length-delimited (string, bytes, nested message, packed repeated).
    case lengthDelimited = 2
    /// Deprecated group start.
    case startGroup = 3
    /// Deprecated group end.
    case endGroup = 4
    /// 4 bytes (fixed32, sfixed32, float).
    case fixed32 = 5
}

/// A field's value as on the wire.
public indirect enum ProtoValue: Sendable, Hashable {
    /// A varint.
    case varint(UInt64)
    /// 8 little-endian bytes.
    case fixed64(UInt64)
    /// 4 little-endian bytes.
    case fixed32(UInt32)
    /// Length-delimited bytes (a string, bytes, a nested message or a packed list).
    case bytes([UInt8])
    /// A deprecated group's fields.
    case group([ProtoField])

    /// The wire type that carries this value.
    public var wireType: ProtoWireType {
        switch self {
        case .varint: .varint
        case .fixed64: .fixed64
        case .fixed32: .fixed32
        case .bytes: .lengthDelimited
        case .group: .startGroup
        }
    }
}

/// One field occurrence.
public struct ProtoField: Sendable, Hashable {
    /// Field number.
    public var number: Int
    /// The value.
    public var value: ProtoValue
    /// The exact bytes decoded (tag and value); nil once the field is edited.
    public var raw: [UInt8]?

    /// A field (no raw bytes: it is encoded from `value`).
    public init(_ number: Int, _ value: ProtoValue, raw: [UInt8]? = nil) {
        self.number = number
        self.value = value
        self.raw = raw
    }

    /// The wire type.
    public var wireType: ProtoWireType { value.wireType }
}

/// A decoded message: its fields in wire order.
public struct ProtoMessage: Sendable, Hashable {
    /// Fields in the order they appeared.
    public var fields: [ProtoField]

    /// A message.
    public init(_ fields: [ProtoField] = []) {
        self.fields = fields
    }

    /// The first field numbered `number`.
    public func field(_ number: Int) -> ProtoField? { fields.first { $0.number == number } }

    /// The bytes (exact for unedited fields).
    public var encoded: [UInt8] { Protobuf.encode(self) }
}

/// Why bytes don't decode as a message.
public struct ProtoDecodeError: Error, Sendable, Hashable, CustomStringConvertible {
    /// What went wrong.
    public var message: String
    /// Where (byte offset).
    public var offset: Int

    /// "message at offset".
    public var description: String { "\(message) at byte \(offset)" }
}

/// How a length-delimited value reads best (GRP-002).
public enum ProtoReading: Sendable, Hashable {
    /// A nested message.
    case message(ProtoMessage)
    /// UTF-8 text.
    case string(String)
    /// Opaque bytes.
    case bytes([UInt8])
    /// A packed list of varints.
    case packedVarints([UInt64])
}

/// The protobuf wire codec.
public enum Protobuf {
    /// Nested messages deeper than this are left as bytes (F33 §5).
    public static let maxDepth = 32

    /// Decode `bytes` as a message; every byte must belong to a field.
    public static func decode(_ bytes: [UInt8], depth: Int = 0) throws(ProtoDecodeError) -> ProtoMessage {
        var index = 0
        var fields: [ProtoField] = []
        while index < bytes.count {
            fields.append(try field(bytes, &index, depth: depth, endGroup: nil))
        }
        return ProtoMessage(fields)
    }

    static func field(_ bytes: [UInt8], _ index: inout Int, depth: Int, endGroup: Int?)
        throws(ProtoDecodeError)
        -> ProtoField
    {
        let start = index
        let key = try varint(bytes, &index)
        let number = Int(key >> 3)
        guard number >= 1, number <= 536_870_911 else {
            throw ProtoDecodeError(message: "invalid field number \(number)", offset: start)
        }
        guard let wireType = ProtoWireType(rawValue: UInt8(key & 7)) else {
            throw ProtoDecodeError(message: "invalid wire type \(key & 7)", offset: start)
        }
        let value: ProtoValue
        switch wireType {
        case .varint: value = .varint(try varint(bytes, &index))
        case .fixed64:
            guard index + 8 <= bytes.count else {
                throw ProtoDecodeError(message: "truncated fixed64", offset: index)
            }
            value = .fixed64(littleEndian(bytes[index..<(index + 8)]))
            index += 8
        case .fixed32:
            guard index + 4 <= bytes.count else {
                throw ProtoDecodeError(message: "truncated fixed32", offset: index)
            }
            value = .fixed32(UInt32(littleEndian(bytes[index..<(index + 4)])))
            index += 4
        case .lengthDelimited:
            let length = try varint(bytes, &index)
            guard length <= UInt64(bytes.count - index) else {
                throw ProtoDecodeError(message: "length \(length) runs past the end", offset: index)
            }
            value = .bytes(Array(bytes[index..<(index + Int(length))]))
            index += Int(length)
        case .startGroup:
            guard depth < maxDepth else {
                throw ProtoDecodeError(message: "groups nested too deeply", offset: start)
            }
            var inner: [ProtoField] = []
            while true {
                guard index < bytes.count else {
                    throw ProtoDecodeError(message: "unterminated group", offset: start)
                }
                let peek = index
                let innerKey = try varint(bytes, &index)
                if innerKey & 7 == 4 {
                    guard Int(innerKey >> 3) == number else {
                        throw ProtoDecodeError(message: "mismatched group end", offset: peek)
                    }
                    break
                }
                index = peek
                inner.append(try field(bytes, &index, depth: depth + 1, endGroup: number))
            }
            value = .group(inner)
        case .endGroup:
            throw ProtoDecodeError(message: "unexpected group end", offset: start)
        }
        _ = endGroup
        return ProtoField(number, value, raw: Array(bytes[start..<index]))
    }

    /// Encode a message (raw bytes for unedited fields).
    public static func encode(_ message: ProtoMessage) -> [UInt8] {
        var out: [UInt8] = []
        for field in message.fields { out += encode(field) }
        return out
    }

    /// Encode one field.
    public static func encode(_ field: ProtoField) -> [UInt8] {
        if let raw = field.raw { return raw }
        let tag = { (type: ProtoWireType) in varint(UInt64(field.number) << 3 | UInt64(type.rawValue)) }
        switch field.value {
        case .varint(let v): return tag(.varint) + varint(v)
        case .fixed64(let v): return tag(.fixed64) + (0..<8).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) }
        case .fixed32(let v): return tag(.fixed32) + (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) }
        case .bytes(let b): return tag(.lengthDelimited) + varint(UInt64(b.count)) + b
        case .group(let inner):
            return tag(.startGroup) + inner.flatMap(encode) + tag(.endGroup)
        }
    }

    /// Read a varint at `index`.
    public static func varint(_ bytes: [UInt8], _ index: inout Int) throws(ProtoDecodeError) -> UInt64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        let start = index
        while true {
            guard index < bytes.count else {
                throw ProtoDecodeError(message: "truncated varint", offset: start)
            }
            let byte = bytes[index]
            index += 1
            guard shift < 64 else { throw ProtoDecodeError(message: "varint too long", offset: start) }
            result |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return result }
            shift += 7
        }
    }

    /// Encode a varint.
    public static func varint(_ value: UInt64) -> [UInt8] {
        var v = value
        var out: [UInt8] = []
        repeat {
            var byte = UInt8(v & 0x7F)
            v >>= 7
            if v != 0 { byte |= 0x80 }
            out.append(byte)
        } while v != 0
        return out
    }

    /// Zigzag-decode (sint32/sint64).
    public static func zigzag(_ v: UInt64) -> Int64 { Int64(bitPattern: (v >> 1) ^ (0 &- (v & 1))) }

    /// Zigzag-encode.
    public static func zigzag(_ v: Int64) -> UInt64 { UInt64(bitPattern: (v << 1) ^ (v >> 63)) }

    static func littleEndian(_ bytes: ArraySlice<UInt8>) -> UInt64 {
        bytes.enumerated().reduce(0) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) }
    }

    /// The best reading of a length-delimited value, and the others that also fit (GRP-002): text
    /// when it is printable UTF-8, else a nested message when it decodes, else packed varints, else
    /// bytes.
    public static func readings(_ bytes: [UInt8], depth: Int = 0) -> [ProtoReading] {
        var result: [ProtoReading] = []
        let text = printableText(bytes)
        let nested = depth < maxDepth && !bytes.isEmpty ? try? decode(bytes, depth: depth + 1) : nil
        if let text { result.append(.string(text)) }
        if let nested { result.append(.message(nested)) }
        if text == nil, nested == nil, !bytes.isEmpty, let packed = packedVarints(bytes) {
            result.append(.packedVarints(packed))
        }
        result.append(.bytes(bytes))
        return result
    }

    /// `bytes` as text if it is valid UTF-8 with no control characters other than whitespace.
    public static func printableText(_ bytes: [UInt8]) -> String? {
        guard let text = String(bytes: bytes, encoding: .utf8) else { return nil }
        let ok = text.unicodeScalars.allSatisfy { scalar in
            scalar.value >= 0x20 && scalar.value != 0x7F || scalar == "\n" || scalar == "\r" || scalar == "\t"
        }
        return ok ? text : nil
    }

    static func packedVarints(_ bytes: [UInt8]) -> [UInt64]? {
        var index = 0
        var values: [UInt64] = []
        while index < bytes.count {
            guard let v = try? varint(bytes, &index) else { return nil }
            values.append(v)
        }
        return values
    }
}

extension ProtoMessage {
    /// A copy with the field at `path` (field numbers, first occurrence at each level; nested
    /// messages are decoded on the way) replaced by `value`. Everything else keeps its bytes; the
    /// enclosing lengths are recomputed. Nil if the path doesn't exist or isn't a nested message.
    public func setting(_ path: [Int], to value: ProtoValue) -> ProtoMessage? {
        guard let first = path.first, let index = fields.firstIndex(where: { $0.number == first }) else {
            return nil
        }
        var copy = self
        if path.count == 1 {
            copy.fields[index] = ProtoField(first, value)
            return copy
        }
        guard case .bytes(let inner) = fields[index].value, let child = try? Protobuf.decode(inner),
            let updated = child.setting(Array(path.dropFirst()), to: value)
        else { return nil }
        copy.fields[index] = ProtoField(first, .bytes(updated.encoded))
        return copy
    }

    /// The value at `path` (first occurrence at each level).
    public func value(at path: [Int]) -> ProtoValue? {
        guard let first = path.first, let field = field(first) else { return nil }
        if path.count == 1 { return field.value }
        guard case .bytes(let inner) = field.value, let child = try? Protobuf.decode(inner) else {
            return nil
        }
        return child.value(at: Array(path.dropFirst()))
    }

    /// The schema-less text form, like `protoc --decode_raw` with type hints:
    /// `1: "hello"`, `2: 3`, `3 { 1: 7 }`.
    public func text(indent: String = "") -> String {
        var lines: [String] = []
        for field in fields {
            switch field.value {
            case .varint(let v):
                // An odd varint read as zigzag is negative: worth showing (even ones just halve).
                let hint = v & 1 == 1 && v < 1 << 32 ? "  (sint \(Protobuf.zigzag(v)))" : ""
                lines.append("\(indent)\(field.number): \(v)\(hint)")
            case .fixed64(let v):
                lines.append(
                    "\(indent)\(field.number): 0x\(String(v, radix: 16)) (fixed64; double \(Double(bitPattern: v)))"
                )
            case .fixed32(let v):
                lines.append(
                    "\(indent)\(field.number): 0x\(String(v, radix: 16)) (fixed32; float \(Float(bitPattern: v)))"
                )
            case .bytes(let bytes):
                switch Protobuf.readings(bytes).first {
                case .string(let s):
                    lines.append("\(indent)\(field.number): \(Self.quote(s))")
                case .message(let nested):
                    lines.append("\(indent)\(field.number) {")
                    lines.append(nested.text(indent: indent + "  "))
                    lines.append("\(indent)}")
                case .packedVarints(let values):
                    lines.append(
                        "\(indent)\(field.number): [\(values.map(String.init).joined(separator: ", "))] (packed)"
                    )
                default:
                    lines.append(
                        "\(indent)\(field.number): <\(bytes.map { String(format: "%02x", $0) }.joined())>")
                }
            case .group(let inner):
                lines.append("\(indent)\(field.number) (group) {")
                lines.append(ProtoMessage(inner).text(indent: indent + "  "))
                lines.append("\(indent)}")
            }
        }
        return lines.filter { !$0.isEmpty }.joined(separator: "\n")
    }

    static func quote(_ text: String) -> String {
        "\""
            + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n") + "\""
    }
}

extension ProtoValue {
    /// `text` as a value of wire type `wireType` — how an edited or fuzzed field keeps its type:
    /// a varint takes a decimal integer (negative numbers as two's complement) or `true`/`false`;
    /// fixed32/fixed64 take an integer or a decimal (stored as float/double bits); anything else,
    /// and text that doesn't parse, becomes length-delimited bytes (a deliberate type confusion when
    /// fuzzing a number field with text).
    public static func parsing(_ text: [UInt8], as wireType: ProtoWireType) -> ProtoValue {
        let string = String(decoding: text, as: UTF8.self)
        switch wireType {
        case .varint:
            if let v = UInt64(string) { return .varint(v) }
            if let v = Int64(string) { return .varint(UInt64(bitPattern: v)) }
            if string == "true" || string == "false" { return .varint(string == "true" ? 1 : 0) }
        case .fixed32:
            if let v = UInt32(string) { return .fixed32(v) }
            if let v = Int32(string) { return .fixed32(UInt32(bitPattern: v)) }
            if let v = Float(string) { return .fixed32(v.bitPattern) }
        case .fixed64:
            if let v = UInt64(string) { return .fixed64(v) }
            if let v = Int64(string) { return .fixed64(UInt64(bitPattern: v)) }
            if let v = Double(string) { return .fixed64(v.bitPattern) }
        default: break
        }
        return .bytes(text)
    }

    /// The value as editable text: a varint or fixed number in decimal, bytes as UTF-8 (lossy).
    public var editableText: String {
        switch self {
        case .varint(let v), .fixed64(let v): String(v)
        case .fixed32(let v): String(v)
        case .bytes(let b): String(decoding: b, as: UTF8.self)
        case .group(let fields): ProtoMessage(fields).text()
        }
    }
}
