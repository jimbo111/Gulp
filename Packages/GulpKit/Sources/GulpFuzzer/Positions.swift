// GulpFuzzer — payload positions (F07 FUZ-001, FUZ-003): `§…§` markers in the base request's bytes.
// The bytes between a pair are the position's base value; `§§` is an empty insertion point. Payloads
// are spliced in as raw bytes at the marked ranges — the rest of the message is never re-parsed.
// A request that contains `§` itself can use another marker (FuzzSettings.marker).

import Foundation
import GulpCore

/// Why a template can't be used.
public struct FuzzTemplateError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The reason.
    public var message: String

    public var description: String { message }
}

/// A base request split at its payload positions.
public struct FuzzTemplate: Sendable, Hashable {
    /// The literal bytes around the positions (`positionCount + 1` pieces).
    public let segments: [[UInt8]]
    /// Each position's base value (the bytes between its markers).
    public let baseValues: [[UInt8]]
    /// Protobuf-field positions (GRP-005) instead of markers; nil for a marker template.
    public let rpc: RPCPositions?

    /// Number of positions.
    public var positionCount: Int { baseValues.count }

    /// The marker as bytes (default `§`, U+00A7).
    public static func markerBytes(_ marker: String = "§") -> [UInt8] { Array(marker.utf8) }

    /// Split `bytes` at `marker` pairs. An odd number of markers is an error.
    public init(_ bytes: [UInt8], marker: String = "§") throws {
        let token = Self.markerBytes(marker)
        guard !token.isEmpty else { throw FuzzTemplateError(message: "empty marker") }
        var pieces: [[UInt8]] = []
        var current: [UInt8] = []
        var index = 0
        while index < bytes.count {
            if index + token.count <= bytes.count, Array(bytes[index..<index + token.count]) == token {
                pieces.append(current)
                current = []
                index += token.count
            } else {
                current.append(bytes[index])
                index += 1
            }
        }
        pieces.append(current)
        guard pieces.count % 2 == 1 else {
            throw FuzzTemplateError(
                message:
                    "unbalanced \(marker) markers: every position needs an opening and a closing \(marker)")
        }
        segments = stride(from: 0, to: pieces.count, by: 2).map { pieces[$0] }
        baseValues = stride(from: 1, to: pieces.count, by: 2).map { pieces[$0] }
        rpc = nil
    }

    /// A template whose positions are protobuf fields of an RPC request (GRP-005).
    public init(rpc: RPCPositions) {
        segments = []
        baseValues = rpc.baseValues
        self.rpc = rpc
    }

    /// The request with `payloads` (one per position; nil keeps the base value) spliced in.
    public func render(_ payloads: [[UInt8]?]) -> [UInt8] {
        if let rpc { return rpc.render(payloads) }
        var output = segments[0]
        for position in 0..<positionCount {
            output += (position < payloads.count ? payloads[position] : nil) ?? baseValues[position]
            output += segments[position + 1]
        }
        return output
    }

    /// The base request (every position at its base value, markers removed).
    public var base: [UInt8] { render([]) }

    /// `bytes` with every marker removed (FUZ-001 "clear").
    public static func clear(_ bytes: [UInt8], marker: String = "§") -> [UInt8] {
        let token = markerBytes(marker)
        var output: [UInt8] = []
        var index = 0
        while index < bytes.count {
            if index + token.count <= bytes.count, Array(bytes[index..<index + token.count]) == token {
                index += token.count
            } else {
                output.append(bytes[index])
                index += 1
            }
        }
        return output
    }

    /// `bytes` with `range` wrapped in markers (FUZ-001 "add from selection").
    public static func mark(_ bytes: [UInt8], _ range: Range<Int>, marker: String = "§") -> [UInt8] {
        let token = markerBytes(marker)
        return Array(bytes[..<range.lowerBound]) + token + Array(bytes[range]) + token
            + Array(bytes[range.upperBound...])
    }

    /// Headers whose values aren't marked by `autoMark` (framing and routing).
    static let unmarkedHeaders: Set<String> = [
        "host", "content-length", "connection", "transfer-encoding", "accept-encoding", "upgrade",
    ]

    /// FUZ-001 "auto": mark every query and form parameter value, every cookie value and each
    /// header value (except framing/routing headers). The user prunes from there.
    public static func autoMark(_ request: RawRequest, marker: String = "§") -> [UInt8] {
        let bytes = request.bytes.rawBytes
        var ranges: [Range<Int>] = []
        let parsed = request.parsed
        // Query string values.
        let target = parsed.target
        if let question = bytes[target].firstIndex(of: 0x3F) {
            ranges += valueRanges(bytes, from: question + 1, to: target.upperBound, separator: 0x26)
        }
        for field in parsed.headers {
            let name = String(decoding: bytes[field.name], as: UTF8.self).lowercased()
            if name == "cookie" {
                ranges += valueRanges(
                    bytes, from: field.value.lowerBound, to: field.value.upperBound, separator: 0x3B)
            } else if !unmarkedHeaders.contains(name), !field.value.isEmpty {
                ranges.append(field.value)
            }
        }
        // Form body values.
        let type = request.headerValue("content-type")?.string().lowercased() ?? ""
        if type.contains("x-www-form-urlencoded"), !parsed.body.isEmpty {
            ranges += valueRanges(
                bytes, from: parsed.body.lowerBound, to: parsed.body.upperBound, separator: 0x26)
        }
        // Insert markers from the end so earlier offsets stay valid.
        var output = bytes
        let token = markerBytes(marker)
        for range in ranges.sorted(by: { $0.lowerBound > $1.lowerBound }) {
            output.insert(contentsOf: token, at: range.upperBound)
            output.insert(contentsOf: token, at: range.lowerBound)
        }
        return output
    }

    /// The value ranges of `name=value` pairs between `from` and `to`.
    static func valueRanges(_ bytes: [UInt8], from: Int, to: Int, separator: UInt8) -> [Range<Int>] {
        var ranges: [Range<Int>] = []
        var start = from
        while start < to {
            let end = bytes[start..<to].firstIndex(of: separator) ?? to
            if let equals = bytes[start..<end].firstIndex(of: 0x3D) {
                ranges.append((equals + 1)..<end)
            }
            start = end + 1
        }
        return ranges
    }
}
