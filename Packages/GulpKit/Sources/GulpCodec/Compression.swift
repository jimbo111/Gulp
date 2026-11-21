// GulpCodec — compression and checksums for the Decoder (F12 §3): gzip, zlib and raw DEFLATE both
// ways through the system zlib (decompression capped like F03's response limit, so a compression
// bomb fails instead of eating memory), CRC-32, and SHA-3 (Keccak-f[1600], FIPS 202) — swift-crypto
// has no SHA-3, and Decoder hashes must work on Linux too.

import CZlib
import Foundation

/// Why a codec failed.
public struct CodecError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The reason, for the user.
    public var message: String

    /// An error.
    public init(_ message: String) {
        self.message = message
    }

    /// A readable form of the error: its message.
    public var description: String { message }
}

/// zlib-backed compression.
public enum Compression {
    /// The container around DEFLATE data.
    public enum Wrapper: Sendable {
        /// gzip (RFC 1952).
        case gzip
        /// zlib (RFC 1950).
        case zlib
        /// Raw DEFLATE (RFC 1951).
        case raw

        var windowBits: Int32 {
            switch self {
            case .gzip: 15 + 16
            case .zlib: 15
            case .raw: -15
            }
        }
    }

    /// Decompressed output larger than this fails (F03's response limit).
    public static let defaultLimit = 50 * 1024 * 1024

    /// Compress `input`.
    public static func compress(_ input: [UInt8], _ wrapper: Wrapper, level: Int32 = Z_DEFAULT_COMPRESSION)
        throws
        -> [UInt8]
    {
        var stream = z_stream()
        guard
            deflateInit2_(
                &stream, level, Z_DEFLATED, wrapper.windowBits, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION,
                Int32(MemoryLayout<z_stream>.size)) == Z_OK
        else { throw CodecError("zlib initialisation failed") }
        defer { _ = deflateEnd(&stream) }
        var output: [UInt8] = []
        var source = input
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        var status = Z_OK
        source.withUnsafeMutableBufferPointer { inBuffer in
            stream.next_in = inBuffer.baseAddress
            stream.avail_in = uInt(inBuffer.count)
            repeat {
                let produced = chunk.withUnsafeMutableBufferPointer { outBuffer -> Int in
                    stream.next_out = outBuffer.baseAddress
                    stream.avail_out = uInt(outBuffer.count)
                    status = deflate(&stream, Z_FINISH)
                    return outBuffer.count - Int(stream.avail_out)
                }
                output.append(contentsOf: chunk[0..<produced])
            } while status == Z_OK
        }
        guard status == Z_STREAM_END else { throw CodecError("compression failed (zlib \(status))") }
        return output
    }

    /// Decompress `input` (for `.gzip`/`.zlib`, either header is accepted).
    public static func decompress(_ input: [UInt8], _ wrapper: Wrapper, limit: Int = defaultLimit) throws
        -> [UInt8]
    {
        var stream = z_stream()
        let bits: Int32 = wrapper == .raw ? -15 : 15 + 32  // +32: detect gzip or zlib
        guard inflateInit2_(&stream, bits, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw CodecError("zlib initialisation failed")
        }
        defer { _ = inflateEnd(&stream) }
        var output: [UInt8] = []
        var source = input
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        var status = Z_OK
        try source.withUnsafeMutableBufferPointer { inBuffer in
            stream.next_in = inBuffer.baseAddress
            stream.avail_in = uInt(inBuffer.count)
            while true {
                let produced = chunk.withUnsafeMutableBufferPointer { outBuffer -> Int in
                    stream.next_out = outBuffer.baseAddress
                    stream.avail_out = uInt(outBuffer.count)
                    status = inflate(&stream, Z_NO_FLUSH)
                    return outBuffer.count - Int(stream.avail_out)
                }
                output.append(contentsOf: chunk[0..<produced])
                if output.count > limit { throw CodecError("decompressed size exceeds \(limit) bytes") }
                if status == Z_STREAM_END { return }
                if status == Z_BUF_ERROR || (status == Z_OK && stream.avail_in == 0 && produced == 0) {
                    throw CodecError("compressed data is truncated")
                }
                guard status == Z_OK else { throw CodecError("not valid compressed data (zlib \(status))") }
            }
        }
        return output
    }

    /// CRC-32 (the gzip/zip polynomial).
    public static func crc32(_ input: [UInt8]) -> UInt32 {
        input.withUnsafeBufferPointer { buffer in
            UInt32(CZlib.crc32(0, buffer.baseAddress, uInt(buffer.count)))
        }
    }
}

/// SHA-3 (FIPS 202).
public enum SHA3 {
    /// SHA3-`bits` of `input` (224, 256, 384 or 512).
    public static func hash(_ input: [UInt8], bits: Int) -> [UInt8] {
        let rate = 200 - 2 * (bits / 8)
        var state = [UInt64](repeating: 0, count: 25)
        var message = input
        message.append(0x06)
        while message.count % rate != 0 { message.append(0) }
        message[message.count - 1] |= 0x80
        for block in stride(from: 0, to: message.count, by: rate) {
            for lane in 0..<(rate / 8) {
                var value: UInt64 = 0
                for byte in 0..<8 { value |= UInt64(message[block + lane * 8 + byte]) << (8 * UInt64(byte)) }
                state[lane] ^= value
            }
            keccak(&state)
        }
        var output: [UInt8] = []
        for lane in state {
            for byte in 0..<8 { output.append(UInt8(truncatingIfNeeded: lane >> (8 * UInt64(byte)))) }
            if output.count >= bits / 8 { break }
        }
        return Array(output.prefix(bits / 8))
    }

    static let roundConstants: [UInt64] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ]
    static let rotations: [UInt64] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
    ]

    static func rotate(_ value: UInt64, _ by: UInt64) -> UInt64 {
        by == 0 ? value : (value << by) | (value >> (64 - by))
    }

    static func keccak(_ a: inout [UInt64]) {
        var b = [UInt64](repeating: 0, count: 25)
        var c = [UInt64](repeating: 0, count: 5)
        for round in 0..<24 {
            for x in 0..<5 { c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
            for x in 0..<5 {
                let d = c[(x + 4) % 5] ^ rotate(c[(x + 1) % 5], 1)
                for y in stride(from: 0, to: 25, by: 5) { a[y + x] ^= d }
            }
            for x in 0..<5 {
                for y in 0..<5 {
                    // ρ and π: lane (x, y) moves to (y, 2x + 3y).
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = rotate(a[x + 5 * y], rotations[x + 5 * y])
                }
            }
            for x in 0..<5 {
                for y in stride(from: 0, to: 25, by: 5) {
                    a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5])
                }
            }
            a[0] ^= roundConstants[round]
        }
    }
}
