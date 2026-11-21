// GulpCore — Bytes: the canonical byte buffer for raw HTTP messages (doc 04 §2).
//
// Raw bytes are the source of truth (AGENTS.md §4): Bytes stores exactly what was sent/received and
// never normalizes. It is a thin, value-semantic wrapper over [UInt8] with cheap slicing.

/// An immutable-by-default buffer of bytes with random access and cheap sub-ranges.
public struct Bytes: Sendable, Hashable, RandomAccessCollection {
    /// A single byte.
    public typealias Element = UInt8
    /// An offset into the buffer, from 0.
    public typealias Index = Int
    /// Slices are `Bytes` too, re-based to start at 0.
    public typealias SubSequence = Bytes

    @usableFromInline var storage: [UInt8]

    /// Create from a raw byte array.
    @inlinable public init(_ bytes: [UInt8]) { self.storage = bytes }
    /// Create an empty buffer.
    @inlinable public init() { self.storage = [] }
    /// Create from a string's UTF-8 encoding.
    @inlinable public init(_ string: String) { self.storage = Array(string.utf8) }

    /// Always 0, including for a slice.
    public var startIndex: Int { 0 }
    /// The byte count.
    public var endIndex: Int { storage.count }
    /// The next offset.
    @inlinable public func index(after i: Int) -> Int { i + 1 }
    /// The previous offset.
    @inlinable public func index(before i: Int) -> Int { i - 1 }

    /// The byte at `position`.
    @inlinable public subscript(position: Int) -> UInt8 { storage[position] }
    /// A copy of the bytes in `bounds`, as a new buffer starting at index 0.
    @inlinable public subscript(bounds: Range<Int>) -> Bytes { Bytes(Array(storage[bounds])) }

    /// The underlying array (copy).
    public var rawBytes: [UInt8] { storage }

    /// A UTF-8 string view for display. `lossy` (default) substitutes U+FFFD for invalid sequences;
    /// with `lossy: false` it returns nil when the bytes aren't valid UTF-8. Stdlib-only (no Foundation).
    public func string(lossy: Bool = true) -> String {
        String(decoding: storage, as: UTF8.self)  // always lossy; fine for display
    }
    /// Strict UTF-8 decode: nil if the bytes aren't valid UTF-8.
    public func validUTF8() -> String? {
        var s = ""; s.reserveCapacity(storage.count)
        var decoder = UTF8()
        var it = storage.makeIterator()
        loop: while true {
            switch decoder.decode(&it) {
            case .scalarValue(let v): s.unicodeScalars.append(v)
            case .emptyInput: break loop
            case .error: return nil
            }
        }
        return s
    }

    /// Replace a sub-range with new bytes in place (used by the edit path).
    public mutating func replaceSubrange(_ r: Range<Int>, with new: Bytes) {
        storage.replaceSubrange(r, with: new.storage)
    }

    /// Append bytes.
    public mutating func append(_ other: Bytes) { storage.append(contentsOf: other.storage) }
}

extension Bytes: ExpressibleByArrayLiteral {
    /// Create a buffer from a byte array literal, e.g. `[0x47, 0x45, 0x54]`.
    @inlinable public init(arrayLiteral elements: UInt8...) { self.storage = elements }
}
