// GulpCore — the structured form of an HTTP/2 request (doc 04 §3), used when a message cannot be
// expressed as HTTP/1-style text (raw H2 mode, HTTP-025). Sending it arrives with HTTP/2 in M3.

/// One HTTP/2 header field. A named struct, not a tuple, so arrays of it are `Codable`.
public struct H2Field: Sendable, Codable, Hashable {
    /// Field name as bytes, so names illegal in HTTP/1 (uppercase, colons) are representable.
    public var name: Bytes
    /// Field value as bytes (may contain CR/LF in raw mode).
    public var value: Bytes

    /// Create a field.
    public init(name: Bytes, value: Bytes) {
        self.name = name
        self.value = value
    }
}

extension Bytes: Codable {
    /// Decode from an array of byte values.
    public init(from decoder: any Decoder) throws {
        let values = try decoder.singleValueContainer().decode([UInt8].self)
        self.init(values)
    }

    /// Encode as an array of byte values.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(storage)
    }
}

/// An HTTP/2 request in structured form: ordered pseudo-headers, ordered headers, and a body.
public struct H2RequestSpec: Sendable, Codable, Hashable {
    /// Ordered pseudo-headers, e.g. `:method :scheme :authority :path`.
    public var pseudoHeaders: [H2Field]
    /// Ordered headers, case preserved (lowercased on the wire unless "raw case").
    public var headers: [H2Field]
    /// Request body.
    public var body: Bytes
    /// Optionally split the body into DATA frames of these sizes.
    public var dataFrameSplit: [Int]?

    /// Create a request spec.
    public init(
        pseudoHeaders: [H2Field], headers: [H2Field], body: Bytes = Bytes(), dataFrameSplit: [Int]? = nil
    ) {
        self.pseudoHeaders = pseudoHeaders
        self.headers = headers
        self.body = body
        self.dataFrameSplit = dataFrameSplit
    }
}
