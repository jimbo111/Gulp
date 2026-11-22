// GulpUI — the platform-independent half of the MessageEditor (doc 05 UI-010, UI-020): how bytes
// become editable text and back without losing any, and the Inspector's parsed view of a message.
// Kept free of AppKit so it is tested on Linux.

import Foundation
import GulpCore

/// How a message is shown as editable text (UI-010 Raw tab).
public enum MessageText {
    /// Valid UTF-8 is edited as UTF-8; anything else is edited byte-for-byte in a Latin-1 view
    /// (each byte one character), so saving never changes bytes the user didn't touch.
    public enum Encoding: Sendable, Equatable {
        case utf8
        case latin1
    }

    /// The text for `bytes` and the encoding used.
    public static func decode(_ bytes: [UInt8]) -> (text: String, encoding: Encoding) {
        let text = String(decoding: bytes, as: UTF8.self)
        if Array(text.utf8) == bytes { return (text, .utf8) }  // valid UTF-8 round-trips exactly
        // ISO-8859-1 maps byte N to U+00NN, so every byte sequence converts. Foundation does 5 MB in
        // a few ms; a per-scalar loop took ~340 ms in a debug build (doc 01 §9: < 300 ms first paint).
        guard let latin1 = String(bytes: bytes, encoding: .isoLatin1) else {
            preconditionFailure("ISO-8859-1 decodes every byte sequence")
        }
        return (latin1, .latin1)
    }

    /// The bytes for edited `text` in `encoding` (Latin-1 characters above U+00FF become UTF-8).
    public static func encode(_ text: String, _ encoding: Encoding) -> [UInt8] {
        switch encoding {
        case .utf8:
            return Array(text.utf8)
        case .latin1:
            var out: [UInt8] = []
            for scalar in text.unicodeScalars {
                if scalar.value < 0x100 {
                    out.append(UInt8(scalar.value))
                } else {
                    out += Array(String(scalar).utf8)
                }
            }
            return out
        }
    }
}

/// One name/value row in the Inspector.
public struct InspectorRow: Sendable, Hashable {
    /// Name.
    public var name: String
    /// Value (as written; URL-decoding is shown separately by the UI).
    public var value: String

    /// A row.
    public init(_ name: String, _ value: String) {
        self.name = name
        self.value = value
    }
}

/// The Inspector's parsed view of a message (UI-020).
public struct MessageInspection: Sendable, Equatable {
    /// Section title → rows, in display order.
    public var sections: [(title: String, rows: [InspectorRow])]

    /// Parse a request or response (decided by its first line).
    public init(_ bytes: [UInt8]) {
        sections = []
        let (end, terminator) = HTTP1.headerBlockEnd(bytes)
        guard terminator != 0 || !bytes.isEmpty else { return }
        let isResponse = bytes.starts(with: Array("HTTP/".utf8))
        if isResponse {
            let response = RawResponse(Bytes(bytes))
            let parsed = response.parsed
            sections.append(
                (
                    "Response",
                    [
                        InspectorRow("Protocol", response.bytes[parsed.version].string()),
                        InspectorRow("Status", String(parsed.statusCode)),
                    ]
                ))
            let headers = Self.headers(response.bytes, parsed.headers)
            sections.append(("Headers", headers))
            let setCookies = headers.filter { $0.name.lowercased() == "set-cookie" }
            let cookies = setCookies.map { row -> InspectorRow in
                let first = row.value.split(separator: ";", maxSplits: 1).first
                return Self.pair(first.map(String.init) ?? row.value)
            }
            if !cookies.isEmpty { sections.append(("Set-Cookie", cookies)) }
            return
        }
        let request = RawRequest(Bytes(bytes))
        let parsed = request.parsed
        let target = request.bytes[parsed.target].string()
        let parts = target.split(separator: "?", maxSplits: 1)
        sections.append(
            (
                "Request",
                [
                    InspectorRow("Method", request.bytes[parsed.method].string()),
                    InspectorRow("Path", parts.first.map(String.init) ?? target),
                    InspectorRow("Protocol", request.bytes[parsed.version].string()),
                ]
            ))
        if parts.count == 2 {
            sections.append(("Query parameters", Self.pairs(String(parts[1]), separator: "&")))
        }
        let headers = Self.headers(request.bytes, parsed.headers)
        let contentType =
            headers.first { $0.name.lowercased() == "content-type" }?.value.lowercased() ?? ""
        let body = end < bytes.count ? Array(bytes[end...]) : []
        if contentType.contains("application/x-www-form-urlencoded"), !body.isEmpty {
            let form = String(decoding: body, as: UTF8.self)
            sections.append(("Body parameters", Self.pairs(form, separator: "&")))
        }
        let cookies = headers.filter { $0.name.lowercased() == "cookie" }
            .flatMap { Self.pairs($0.value, separator: ";") }
        if !cookies.isEmpty { sections.append(("Cookies", cookies)) }
        sections.append(("Headers", headers))
    }

    static func headers(_ bytes: Bytes, _ fields: [HeaderField]) -> [InspectorRow] {
        fields.map { InspectorRow(bytes[$0.name].string(), bytes[$0.value].string()) }
    }

    static func pairs(_ text: String, separator: Character) -> [InspectorRow] {
        text.split(separator: separator).map { pair(String($0)) }
    }

    static func pair(_ text: String) -> InspectorRow {
        let trimmed = text.drop { $0 == " " }
        guard let equals = trimmed.firstIndex(of: "=") else { return InspectorRow(String(trimmed), "") }
        return InspectorRow(String(trimmed[..<equals]), String(trimmed[trimmed.index(after: equals)...]))
    }

    /// Equality by content (tuples aren't Equatable).
    public static func == (lhs: MessageInspection, rhs: MessageInspection) -> Bool {
        lhs.sections.count == rhs.sections.count
            && zip(lhs.sections, rhs.sections).allSatisfy { $0.title == $1.title && $0.rows == $1.rows }
    }
}
