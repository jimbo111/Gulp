// GulpCore — WebSocket framing (RFC 6455) for recording and tools (F01 PRX-030/PRX-031). The proxy
// forwards WebSocket bytes untouched; these types parse a copy of each direction so every message
// can be recorded with its frame boundaries.
//
// Concept: after `101 Switching Protocols` both directions are a stream of frames. Client frames are
// masked (XOR with a 4-byte key); a message is one or more data frames (the first carries the
// opcode, `continuation` frames follow, FIN marks the last); control frames (close/ping/pong) are
// always single frames and may appear between the fragments of a data message.

/// WebSocket opcodes.
public enum WSOpcode: UInt8, Sendable, Codable, CaseIterable {
    case continuation = 0, text = 1, binary = 2, close = 8, ping = 9, pong = 10

    /// Control frames (close, ping, pong) are never fragmented.
    public var isControl: Bool { rawValue >= 8 }
}

/// Direction of a WebSocket message (`ws_messages.direction`).
public enum WSDirection: Int, Sendable, Codable {
    /// Client → server.
    case toServer = 0
    /// Server → client.
    case toClient = 1
}

/// One frame as it appeared on the wire.
public struct WSFrame: Sendable, Equatable {
    /// Final fragment of its message.
    public var fin: Bool
    /// RSV1…RSV3 (RSV1 marks a compressed message with permessage-deflate).
    public var rsv: UInt8
    /// Raw opcode value (unknown opcodes are kept, not rejected).
    public var opcode: UInt8
    /// The masking key, if the frame was masked (client → server).
    public var maskKey: [UInt8]?
    /// The payload, unmasked.
    public var payload: [UInt8]
    /// Bytes this frame took on the wire.
    public var wireLength: Int
}

/// Frame boundaries kept with a recorded message (PRX-031 `frames_json`).
public struct WSFrameInfo: Sendable, Codable, Hashable {
    /// Final fragment.
    public var fin: Bool
    /// Raw opcode.
    public var opcode: UInt8
    /// RSV bits.
    public var rsv: UInt8
    /// Payload length.
    public var length: Int
    /// Whether the frame was masked.
    public var masked: Bool

    /// Create frame metadata.
    public init(fin: Bool, opcode: UInt8, rsv: UInt8, length: Int, masked: Bool) {
        self.fin = fin
        self.opcode = opcode
        self.rsv = rsv
        self.length = length
        self.masked = masked
    }
}

/// A whole message: a control frame, or a data message reassembled from its fragments.
public struct WSMessage: Sendable, Equatable {
    /// The message opcode (text, binary, close, ping, pong).
    public var opcode: UInt8
    /// The reassembled payload.
    public var payload: [UInt8]
    /// The frames it came in.
    public var frames: [WSFrameInfo]

    /// Create a message.
    public init(opcode: UInt8, payload: [UInt8], frames: [WSFrameInfo]) {
        self.opcode = opcode
        self.payload = payload
        self.frames = frames
    }
}

/// Incremental frame parser for one direction.
public struct WSFrameParser: Sendable {
    /// Payloads larger than this are treated as malformed (a recording safeguard; the bytes are
    /// still forwarded).
    public static let maxPayload = 64 * 1_024 * 1_024

    private var buffer: [UInt8] = []
    /// Set once the stream stopped making sense; no more frames are produced.
    public private(set) var failed = false

    /// A parser with no buffered bytes.
    public init() {}

    /// Feed bytes; returns every frame they completed.
    public mutating func feed(_ bytes: [UInt8]) -> [WSFrame] {
        guard !failed else { return [] }
        buffer += bytes
        var frames: [WSFrame] = []
        var offset = 0
        while let (frame, used) = Self.frame(in: buffer, at: offset) {
            if frame.payload.count > Self.maxPayload {
                failed = true
                break
            }
            frames.append(frame)
            offset += used
        }
        if offset > 0 { buffer.removeFirst(offset) }
        if buffer.count > Self.maxPayload + 14 { failed = true }
        return frames
    }

    /// The frame starting at `start`, or nil if it isn't complete yet.
    static func frame(in a: [UInt8], at start: Int) -> (WSFrame, Int)? {
        guard a.count - start >= 2 else { return nil }
        let first = a[start]
        let second = a[start + 1]
        var index = start + 2
        var length = Int(second & 0x7F)
        if length == 126 {
            guard a.count - index >= 2 else { return nil }
            length = Int(a[index]) << 8 | Int(a[index + 1])
            index += 2
        } else if length == 127 {
            guard a.count - index >= 8 else { return nil }
            var value: UInt64 = 0
            for byte in a[index..<(index + 8)] { value = value << 8 | UInt64(byte) }
            guard value <= UInt64(Int.max / 2) else { return nil }
            length = Int(value)
            index += 8
        }
        let masked = second & 0x80 != 0
        var key: [UInt8]?
        if masked {
            guard a.count - index >= 4 else { return nil }
            key = Array(a[index..<(index + 4)])
            index += 4
        }
        guard a.count - index >= length else { return nil }
        var payload = Array(a[index..<(index + length)])
        if let key {
            for i in payload.indices { payload[i] ^= key[i & 3] }
        }
        let frame = WSFrame(
            fin: first & 0x80 != 0, rsv: (first >> 4) & 0x07, opcode: first & 0x0F, maskKey: key,
            payload: payload, wireLength: index + length - start)
        return (frame, index + length - start)
    }
}

/// Reassembles messages from frames (control frames pass through between fragments).
public struct WSMessageAssembler: Sendable {
    private var opcode: UInt8?
    private var payload: [UInt8] = []
    private var frames: [WSFrameInfo] = []

    /// An assembler with no partial message.
    public init() {}

    /// Add a frame; returns the message it completed, if any.
    public mutating func add(_ frame: WSFrame) -> WSMessage? {
        let info = WSFrameInfo(
            fin: frame.fin, opcode: frame.opcode, rsv: frame.rsv, length: frame.payload.count,
            masked: frame.maskKey != nil)
        if frame.opcode >= 8 {
            return WSMessage(opcode: frame.opcode, payload: frame.payload, frames: [info])
        }
        if frame.opcode != WSOpcode.continuation.rawValue {
            opcode = frame.opcode
            payload = []
            frames = []
        }
        payload += frame.payload
        frames.append(info)
        guard frame.fin else { return nil }
        let message = WSMessage(opcode: opcode ?? frame.opcode, payload: payload, frames: frames)
        opcode = nil
        payload = []
        frames = []
        return message
    }
}

/// Frame encoding and the opening handshake's accept value.
public enum WebSocketWire {
    /// One frame. A client must pass a `mask` key (4 bytes); a server must not. `rsv` is RSV1…RSV3
    /// as a 3-bit value (RSV1 = 4 marks a permessage-deflate message).
    public static func frame(
        opcode: WSOpcode, payload: [UInt8], fin: Bool = true, mask: [UInt8]? = nil, rsv: UInt8 = 0
    ) -> [UInt8] {
        var out: [UInt8] = [(fin ? 0x80 : 0) | (rsv & 0x07) << 4 | opcode.rawValue]
        let maskBit: UInt8 = mask == nil ? 0 : 0x80
        switch payload.count {
        case ..<126:
            out.append(maskBit | UInt8(payload.count))
        case ..<65_536:
            out += [maskBit | 126, UInt8(payload.count >> 8), UInt8(payload.count & 0xFF)]
        default:
            out.append(maskBit | 127)
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8((payload.count >> shift) & 0xFF))
            }
        }
        if let mask {
            out += mask
            out += payload.enumerated().map { $0.element ^ mask[$0.offset & 3] }
        } else {
            out += payload
        }
        return out
    }

    /// `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key` (RFC 6455 §4.2.2).
    public static func accept(forKey key: String) -> String {
        base64(SHA1.digest(Array((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8)))
    }

    static func base64(_ bytes: [UInt8]) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        var out = ""
        var index = 0
        while index < bytes.count {
            let chunk = Array(bytes[index..<min(index + 3, bytes.count)])
            let second = chunk.count > 1 ? Int(chunk[1]) << 8 : 0
            let third = chunk.count > 2 ? Int(chunk[2]) : 0
            let value = (Int(chunk[0]) << 16) | second | third
            out.append(alphabet[(value >> 18) & 63])
            out.append(alphabet[(value >> 12) & 63])
            out.append(chunk.count > 1 ? alphabet[(value >> 6) & 63] : "=")
            out.append(chunk.count > 2 ? alphabet[value & 63] : "=")
            index += 3
        }
        return out
    }
}

/// SHA-1 (only for the WebSocket accept value, where RFC 6455 requires it).
enum SHA1 {
    static func digest(_ message: [UInt8]) -> [UInt8] {
        var h: [UInt32] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0]
        var data = message + [0x80]
        while data.count % 64 != 56 { data.append(0) }
        let bitLength = UInt64(message.count) * 8
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8((bitLength >> UInt64(shift)) & 0xFF))
        }
        for chunk in stride(from: 0, to: data.count, by: 64) {
            var w = [UInt32](repeating: 0, count: 80)
            for i in 0..<16 {
                let b = chunk + i * 4
                w[i] =
                    UInt32(data[b]) << 24 | UInt32(data[b + 1]) << 16 | UInt32(data[b + 2]) << 8
                    | UInt32(data[b + 3])
            }
            for i in 16..<80 {
                let x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
                w[i] = x << 1 | x >> 31
            }
            var (a, b, c, d, e) = (h[0], h[1], h[2], h[3], h[4])
            for i in 0..<80 {
                let (f, k): (UInt32, UInt32)
                switch i {
                case 0..<20: (f, k) = ((b & c) | (~b & d), 0x5A82_7999)
                case 20..<40: (f, k) = (b ^ c ^ d, 0x6ED9_EBA1)
                case 40..<60: (f, k) = ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC)
                default: (f, k) = (b ^ c ^ d, 0xCA62_C1D6)
                }
                let temp = (a << 5 | a >> 27) &+ f &+ e &+ k &+ w[i]
                (e, d, c, b, a) = (d, c, b << 30 | b >> 2, a, temp)
            }
            h[0] &+= a
            h[1] &+= b
            h[2] &+= c
            h[3] &+= d
            h[4] &+= e
        }
        return h.flatMap { word in
            [UInt8(word >> 24), UInt8((word >> 16) & 0xFF), UInt8((word >> 8) & 0xFF), UInt8(word & 0xFF)]
        }
    }
}
