// GulpExtensions — JSON-RPC 2.0 over stdio with LSP-style length-prefixed framing (F18 EXT-002). Each
// message is `Content-Length: N\r\n\r\n` followed by N bytes of JSON. The framer and the encoder are
// pure and tested; the host wires them to a child process's stdio.

import Foundation

/// Encode and decode length-prefixed JSON-RPC frames.
public enum JSONRPCFraming {
    /// Frame one JSON object (already serialized) with its `Content-Length` header.
    public static func frame(_ json: Data) -> Data {
        var out = Data("Content-Length: \(json.count)\r\n\r\n".utf8)
        out.append(json)
        return out
    }
}

/// Incrementally extracts complete JSON frames from a byte stream.
public struct JSONRPCFramer: Sendable {
    private var buffer: [UInt8] = []

    public init() {}

    /// Feed bytes; returns every complete message body (the JSON `Data`) they completed.
    public mutating func feed(_ bytes: [UInt8]) -> [Data] {
        buffer += bytes
        var messages: [Data] = []
        while true {
            guard let headerEnd = range(of: Array("\r\n\r\n".utf8)) else { break }
            let header = String(decoding: buffer[..<headerEnd.lowerBound], as: UTF8.self)
            guard let length = contentLength(header) else {
                // Unparseable header: drop up to the separator and continue.
                buffer.removeSubrange(..<headerEnd.upperBound)
                continue
            }
            let bodyStart = headerEnd.upperBound
            guard buffer.count >= bodyStart + length else { break }  // wait for the whole body
            messages.append(Data(buffer[bodyStart..<(bodyStart + length)]))
            buffer.removeSubrange(..<(bodyStart + length))
        }
        return messages
    }

    private func contentLength(_ header: String) -> Int? {
        for line in header.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":", maxSplits: 1)
            if parts.count == 2,
                parts[0].trimmingCharacters(in: .whitespaces).lowercased() == "content-length"
            {
                return Int(parts[1].trimmingCharacters(in: .whitespaces))
            }
        }
        return nil
    }

    private func range(of needle: [UInt8]) -> Range<Int>? {
        guard buffer.count >= needle.count else { return nil }
        for index in 0...(buffer.count - needle.count)
        where Array(buffer[index..<(index + needle.count)]) == needle {
            return index..<(index + needle.count)
        }
        return nil
    }
}
