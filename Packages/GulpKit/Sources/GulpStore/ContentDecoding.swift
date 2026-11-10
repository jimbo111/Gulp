// GulpStore — undo HTTP Content-Encoding (gzip, deflate) for search and GulpQL body matching
// (F05 §5, doc 04 §4 FTS). Raw bytes stay the truth; this only feeds the index and evaluators.

import CZlib
import Foundation

/// HTTP content decoding for search.
public enum ContentDecoding {
    /// Decode `body` for a `Content-Encoding` value (`gzip`, `x-gzip`, `deflate`; a list is undone
    /// right to left), stopping at `limit` output bytes. Nil for unknown encodings or bad data.
    public static func decode(_ body: [UInt8], encoding: String, limit: Int = 2 * 1024 * 1024) -> [UInt8]? {
        var bytes = body
        let codings = encoding.lowercased().split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        for coding in codings.reversed() where !coding.isEmpty && coding != "identity" {
            switch coding {
            case "gzip", "x-gzip", "deflate":
                // 15 + 32: zlib or gzip header, detected; raw deflate is retried below.
                if let out = inflate(bytes, windowBits: 15 + 32, limit: limit) {
                    bytes = out
                } else if coding == "deflate", let out = inflate(bytes, windowBits: -15, limit: limit) {
                    bytes = out
                } else {
                    return nil
                }
            default: return nil
            }
        }
        return bytes
    }

    static func inflate(_ input: [UInt8], windowBits: Int32, limit: Int) -> [UInt8]? {
        guard !input.isEmpty else { return [] }
        var stream = z_stream()
        guard inflateInit2_(&stream, windowBits, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK
        else {
            return nil
        }
        defer { inflateEnd(&stream) }
        var output: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        var source = input
        let status: Int32 = source.withUnsafeMutableBufferPointer { inBuffer in
            stream.next_in = inBuffer.baseAddress
            stream.avail_in = uInt(inBuffer.count)
            var result: Int32 = Z_OK
            while result == Z_OK, output.count < limit {
                result = chunk.withUnsafeMutableBufferPointer { outBuffer in
                    stream.next_out = outBuffer.baseAddress
                    stream.avail_out = uInt(outBuffer.count)
                    return CZlib.inflate(&stream, Z_NO_FLUSH)
                }
                let produced = chunk.count - Int(stream.avail_out)
                output.append(contentsOf: chunk[0..<produced])
                if result == Z_BUF_ERROR, stream.avail_in == 0 { break }  // truncated: keep what we have
            }
            return result
        }
        guard status == Z_OK || status == Z_STREAM_END || status == Z_BUF_ERROR, !output.isEmpty else {
            return nil
        }
        return output.count > limit ? Array(output[0..<limit]) : output
    }
}
