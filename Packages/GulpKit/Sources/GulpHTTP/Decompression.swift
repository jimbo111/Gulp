// GulpHTTP — decompression helpers for hooks and views (HTTP-007). The raw response is always kept
// exactly as received; these produce a decoded *copy* of the body.

import CZlib
import Foundation
import GulpCore

/// Why a body could not be decoded.
public enum ContentDecodingError: Error, Sendable, Equatable {
    /// A `Content-Encoding` this build cannot decode (brotli and zstd arrive in a later milestone).
    case unsupported(String)
    /// The compressed stream is corrupt.
    case corrupt(String)
    /// The stream ended before its end marker.
    case truncated
    /// The decoded body would exceed the limit.
    case tooLarge(limit: Int)
}

/// Body decoders for `Content-Encoding`.
public enum ContentDecoding {
    /// Decode `body` encoded with the comma-separated `contentEncoding` (applied in order, so they
    /// are undone last-first). `identity` is a no-op.
    public static func decode(
        _ body: Bytes, contentEncoding: String, limit: Int = 100 * 1024 * 1024
    ) throws -> Bytes {
        let codings = contentEncoding.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces).lowercased()
        }
        var bytes = body.rawBytes
        for coding in codings.reversed() where !coding.isEmpty {
            switch coding {
            case "identity":
                continue
            case "gzip", "x-gzip":
                bytes = try Zlib.inflate(bytes, format: .gzipOrZlib, limit: limit)
            case "deflate":
                // RFC 9110 deflate is zlib-wrapped, but some servers send raw DEFLATE; accept both.
                do {
                    bytes = try Zlib.inflate(bytes, format: .gzipOrZlib, limit: limit)
                } catch ContentDecodingError.corrupt(_) {
                    bytes = try Zlib.inflate(bytes, format: .raw, limit: limit)
                }
            default:
                throw ContentDecodingError.unsupported(coding)
            }
        }
        return Bytes(bytes)
    }
}

extension RawResponse {
    /// The body with transfer-coding (chunked) and content-codings (gzip/deflate) undone, for hooks
    /// and views. Nil when the response has no body.
    public func decodedBody(limit: Int = 100 * 1024 * 1024) throws -> Bytes? {
        let framed = parsed.dechunkedBody ?? bytes[parsed.body]
        guard !framed.isEmpty else { return nil }
        guard let encoding = headerValue("content-encoding")?.string() else { return framed }
        return try ContentDecoding.decode(framed, contentEncoding: encoding, limit: limit)
    }
}

/// A thin wrapper over the system zlib.
enum Zlib {
    enum Format {
        /// gzip or zlib wrapper, detected automatically.
        case gzipOrZlib
        /// Raw DEFLATE without a wrapper.
        case raw
    }

    static func inflate(_ input: [UInt8], format: Format, limit: Int) throws -> [UInt8] {
        var stream = z_stream()
        let windowBits: Int32 = format == .raw ? -15 : 15 + 32  // +32: auto-detect gzip/zlib header
        let initStatus = inflateInit2_(&stream, windowBits, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard initStatus == Z_OK else { throw ContentDecodingError.corrupt("zlib initialisation failed") }
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
                    status = CZlib.inflate(&stream, Z_NO_FLUSH)
                    return outBuffer.count - Int(stream.avail_out)
                }
                output.append(contentsOf: chunk[0..<produced])
                if output.count > limit { throw ContentDecodingError.tooLarge(limit: limit) }
                if status == Z_STREAM_END { return }
                if status == Z_BUF_ERROR || (status == Z_OK && stream.avail_in == 0 && produced == 0) {
                    throw ContentDecodingError.truncated
                }
                guard status == Z_OK else {
                    throw ContentDecodingError.corrupt("zlib error \(status)")
                }
            }
        }
        return output
    }
}
