// GulpTLS — a ClientHello sniffer (F01 PRX-006/PRX-008, F02 §4). Reads the server name (SNI) and
// the offered ALPN protocols from the first TLS records without consuming them, so the proxy can
// pick a certificate and mirror ALPN before handing the bytes to the real TLS handler.
//
// Concept: the ClientHello is sent in the clear (until Encrypted ClientHello is deployed), and it
// may be split across several TLS records. This parser reassembles the handshake message from the
// records it has and asks for more bytes when the message is incomplete.

/// What the client offered in its ClientHello.
public struct ClientHello: Sendable, Equatable {
    /// The SNI host name, if sent.
    public var serverName: String?
    /// ALPN protocol names in the client's preference order (empty if no ALPN extension).
    public var alpn: [String]
}

/// Result of sniffing the start of a connection.
public enum ClientHelloSniff: Sendable, Equatable {
    /// Not enough bytes yet.
    case needMoreData
    /// The stream does not start with a TLS handshake record.
    case notTLS
    /// A complete ClientHello.
    case hello(ClientHello)
    /// Starts like TLS but is not a well-formed ClientHello.
    case malformed
}

/// Parses a TLS ClientHello from buffered bytes.
public enum ClientHelloParser {
    /// The largest ClientHello the proxy will buffer before giving up.
    public static let maxBytes = 64 * 1_024

    /// Sniff `bytes` (the first bytes the client sent).
    public static func sniff(_ bytes: [UInt8]) -> ClientHelloSniff {
        guard let first = bytes.first else { return .needMoreData }
        guard first == 0x16 else { return .notTLS }
        // Reassemble the handshake layer from consecutive handshake records.
        var handshake: [UInt8] = []
        var offset = 0
        while offset + 5 <= bytes.count {
            guard bytes[offset] == 0x16, bytes[offset + 1] == 0x03 else { return .malformed }
            let length = Int(bytes[offset + 3]) << 8 | Int(bytes[offset + 4])
            guard offset + 5 + length <= bytes.count else { break }
            handshake += bytes[(offset + 5)..<(offset + 5 + length)]
            offset += 5 + length
            if handshake.count >= 4 {
                let messageLength = Int(handshake[1]) << 16 | Int(handshake[2]) << 8 | Int(handshake[3])
                if handshake.count >= 4 + messageLength { break }
            }
        }
        guard handshake.count >= 4 else { return bytes.count > maxBytes ? .malformed : .needMoreData }
        guard handshake[0] == 0x01 else { return .malformed }  // client_hello
        let messageLength = Int(handshake[1]) << 16 | Int(handshake[2]) << 8 | Int(handshake[3])
        guard handshake.count >= 4 + messageLength else {
            return bytes.count > maxBytes ? .malformed : .needMoreData
        }
        var reader = ByteReader(Array(handshake[4..<(4 + messageLength)]))
        return parseBody(&reader).map(ClientHelloSniff.hello) ?? .malformed
    }

    private static func parseBody(_ reader: inout ByteReader) -> ClientHello? {
        guard reader.skip(2 + 32),  // legacy_version, random
            let sessionID = reader.u8(), reader.skip(Int(sessionID)),
            let suites = reader.u16(), reader.skip(Int(suites)),
            let compression = reader.u8(), reader.skip(Int(compression))
        else { return nil }
        var hello = ClientHello(serverName: nil, alpn: [])
        guard reader.remaining > 0 else { return hello }  // no extensions
        guard let extensionsLength = reader.u16(), var extensions = reader.take(Int(extensionsLength)) else {
            return nil
        }
        while extensions.remaining > 0 {
            guard let type = extensions.u16(), let length = extensions.u16(),
                var body = extensions.take(Int(length))
            else { return nil }
            switch type {
            case 0x0000:  // server_name
                guard let listLength = body.u16(), var list = body.take(Int(listLength)) else { return nil }
                while list.remaining > 0 {
                    guard let nameType = list.u8(), let nameLength = list.u16(),
                        let name = list.take(Int(nameLength))
                    else { return nil }
                    if nameType == 0 { hello.serverName = String(decoding: name.bytes, as: UTF8.self) }
                }
            case 0x0010:  // application_layer_protocol_negotiation
                guard let listLength = body.u16(), var list = body.take(Int(listLength)) else { return nil }
                while list.remaining > 0 {
                    guard let length = list.u8(), let name = list.take(Int(length)) else { return nil }
                    hello.alpn.append(String(decoding: name.bytes, as: UTF8.self))
                }
            default:
                break
            }
        }
        return hello
    }
}

/// Bounds-checked big-endian reads.
struct ByteReader {
    let bytes: [UInt8]
    private var position = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var remaining: Int { bytes.count - position }

    mutating func u8() -> UInt8? {
        guard remaining >= 1 else { return nil }
        defer { position += 1 }
        return bytes[position]
    }

    mutating func u16() -> UInt16? {
        guard remaining >= 2 else { return nil }
        defer { position += 2 }
        return UInt16(bytes[position]) << 8 | UInt16(bytes[position + 1])
    }

    mutating func skip(_ count: Int) -> Bool {
        guard count >= 0, remaining >= count else { return false }
        position += count
        return true
    }

    /// The next `count` bytes as their own reader.
    mutating func take(_ count: Int) -> ByteReader? {
        guard count >= 0, remaining >= count else { return nil }
        defer { position += count }
        return ByteReader(Array(bytes[position..<(position + count)]))
    }
}
