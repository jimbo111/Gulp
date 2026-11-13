// GulpCodec — WebSocket sub-protocol decoding (F01 §2.4, WSX-006). Common real-time protocols wrap an
// editable payload (usually JSON) in a thin transport envelope: socket.io prefixes engine.io/socket.io
// packet-type digits, SignalR terminates each record with a 0x1e separator, graphql-ws and SignalR hub
// messages are JSON objects. Decoding splits the envelope from the payload so the WS history, Repeater
// and Fuzzer can show and edit the payload and re-encode it on send; unknown shapes fall back to raw.
// The split is byte-exact: `encode(decode(x)) == x`.

import Foundation
import GulpCore

/// A recognised WebSocket sub-protocol.
public enum WSSubprotocol: String, Sendable, CaseIterable, Equatable {
    /// socket.io over engine.io: numeric packet-type prefix then a JSON array.
    case socketIO = "socket.io"
    /// graphql-ws: a JSON object with a `type` (connection_init, subscribe, next, …).
    case graphqlWS = "graphql-ws"
    /// SignalR JSON hub protocol: a JSON record terminated by a 0x1e separator.
    case signalR = "SignalR"
    /// STOMP: a text frame (COMMAND, headers, blank line, body, NUL).
    case stomp = "STOMP"
    /// A bare JSON value.
    case json = "JSON"
    /// Anything else — shown as text (or hex when not UTF-8).
    case raw = "raw"
}

/// A decoded WebSocket message: the sub-protocol, the transport `envelopePrefix`/`envelopeSuffix`, and
/// the editable `payload` between them. `envelopePrefix + payload + envelopeSuffix` is the original
/// message, so an edited `payload` re-encodes exactly.
public struct WSDecodedMessage: Sendable, Equatable {
    /// The detected sub-protocol.
    public let subprotocol: WSSubprotocol
    /// Framing before the payload (e.g. socket.io's `42`).
    public let envelopePrefix: String
    /// The editable payload (usually JSON).
    public let payload: String
    /// Framing after the payload (e.g. SignalR's 0x1e separator).
    public let envelopeSuffix: String
    /// A pretty-printed view of the payload when it is JSON, else the payload unchanged (display only;
    /// not used for re-encoding).
    public let pretty: String

    /// A decoded message.
    public init(
        subprotocol: WSSubprotocol, envelopePrefix: String, payload: String, envelopeSuffix: String,
        pretty: String
    ) {
        self.subprotocol = subprotocol
        self.envelopePrefix = envelopePrefix
        self.payload = payload
        self.envelopeSuffix = envelopeSuffix
        self.pretty = pretty
    }
}

/// Detects, decodes and re-encodes common WebSocket sub-protocols (WSX-006).
public enum WSSubprotocolCodec {
    private static let graphqlTypes: Set<String> = [
        "connection_init", "connection_ack", "subscribe", "next", "error", "complete", "ping", "pong",
        "start", "stop", "data", "connection_terminate",
    ]
    private static let stompCommands: Set<String> = [
        "CONNECT", "STOMP", "CONNECTED", "SEND", "SUBSCRIBE", "UNSUBSCRIBE", "ACK", "NACK", "BEGIN",
        "COMMIT", "ABORT", "DISCONNECT", "MESSAGE", "RECEIPT", "ERROR",
    ]

    /// The sub-protocol of a message.
    public static func detect(_ bytes: [UInt8]) -> WSSubprotocol {
        decode(bytes).subprotocol
    }

    /// Decode a message into its envelope and editable payload.
    public static func decode(_ bytes: [UInt8]) -> WSDecodedMessage {
        guard let text = String(bytes: bytes, encoding: .utf8) else {
            return WSDecodedMessage(
                subprotocol: .raw, envelopePrefix: "", payload: hex(bytes), envelopeSuffix: "",
                pretty: hex(bytes))
        }

        // SignalR: a JSON record terminated by the 0x1e separator.
        if text.hasSuffix("\u{1e}") {
            let inner = String(text.dropLast())
            if isJSON(inner) {
                return WSDecodedMessage(
                    subprotocol: .signalR, envelopePrefix: "", payload: inner, envelopeSuffix: "\u{1e}",
                    pretty: prettyJSON(inner))
            }
        }

        // socket.io: engine.io/socket.io numeric packet prefix, optional namespace + ack id, then JSON.
        if let (prefix, payload) = socketIOSplit(text), isJSON(payload) {
            return WSDecodedMessage(
                subprotocol: .socketIO, envelopePrefix: prefix, payload: payload, envelopeSuffix: "",
                pretty: prettyJSON(payload))
        }

        // graphql-ws / bare JSON.
        if isJSON(text) {
            let sub: WSSubprotocol = isGraphQLWS(text) ? .graphqlWS : .json
            return WSDecodedMessage(
                subprotocol: sub, envelopePrefix: "", payload: text, envelopeSuffix: "",
                pretty: prettyJSON(text))
        }

        // STOMP: first line is a command and there's a blank-line header/body separator.
        if let newline = text.firstIndex(where: { $0 == "\n" || $0 == "\r" }) {
            let command = String(text[..<newline])
            if stompCommands.contains(command), text.contains("\n\n") || text.contains("\r\n\r\n") {
                return WSDecodedMessage(
                    subprotocol: .stomp, envelopePrefix: "", payload: text, envelopeSuffix: "",
                    pretty: text)
            }
        }

        return WSDecodedMessage(
            subprotocol: .raw, envelopePrefix: "", payload: text, envelopeSuffix: "", pretty: text)
    }

    /// Re-encode a (possibly edited) decoded message to the wire.
    public static func encode(_ decoded: WSDecodedMessage) -> [UInt8] {
        Array((decoded.envelopePrefix + decoded.payload + decoded.envelopeSuffix).utf8)
    }

    /// WSX-007: wrap each JSON string/number value in `decoded.payload` with `§…§` fuzz markers,
    /// returning a full message template (envelope + marked payload) ready for the WS Fuzzer. The
    /// envelope framing is never marked. Falls back to marking the whole payload for non-JSON shapes.
    public static func autoInsertionPoints(_ decoded: WSDecodedMessage, marker: String = "§") -> String {
        let marked = markJSONValues(decoded.payload, marker: marker) ?? (marker + decoded.payload + marker)
        return decoded.envelopePrefix + marked + decoded.envelopeSuffix
    }

    /// Wrap every JSON string and number *value* (not keys, not structural punctuation) in markers.
    /// Returns nil when `text` is not JSON.
    static func markJSONValues(_ text: String, marker: String) -> String? {
        guard let data = text.data(using: .utf8),
            (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) != nil,
            text.first == "[" || text.first == "{"
        else { return nil }
        var output = ""
        let scalars = Array(text)
        var index = 0
        var expectingValue = true  // after `[`, `,` in an array, or `:` in an object
        while index < scalars.count {
            let character = scalars[index]
            switch character {
            case "\"":
                // A JSON string: find its unescaped close quote.
                var end = index + 1
                while end < scalars.count {
                    if scalars[end] == "\\" {
                        end += 2
                        continue
                    }
                    if scalars[end] == "\"" { break }
                    end += 1
                }
                let token = String(scalars[index...min(end, scalars.count - 1)])
                // Is this string a value or an object key? A key is followed (after spaces) by `:`.
                var look = end + 1
                while look < scalars.count, scalars[look] == " " { look += 1 }
                let isKey = look < scalars.count && scalars[look] == ":"
                output += (expectingValue && !isKey) ? marker + token + marker : token
                index = end + 1
                expectingValue = false
            case "-", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9":
                if expectingValue {
                    var end = index
                    while end < scalars.count, "-+.eE0123456789".contains(scalars[end]) { end += 1 }
                    output += marker + String(scalars[index..<end]) + marker
                    index = end
                    expectingValue = false
                } else {
                    output.append(character)
                    index += 1
                }
            case "[", ",", ":":
                output.append(character)
                expectingValue = true
                index += 1
            case "{":
                output.append(character)
                expectingValue = false  // next token is a key
                index += 1
            case "}", "]":
                output.append(character)
                expectingValue = false
                index += 1
            default:
                output.append(character)
                index += 1
            }
        }
        return output
    }

    // MARK: helpers

    /// Split a socket.io frame into its numeric/namespace prefix and the JSON remainder.
    private static func socketIOSplit(_ text: String) -> (prefix: String, payload: String)? {
        var index = text.startIndex
        guard index < text.endIndex, text[index].isNumber else { return nil }
        // engine.io + socket.io packet-type digits.
        while index < text.endIndex, text[index].isNumber { index = text.index(after: index) }
        // Optional binary-attachment count terminator `-`.
        if index < text.endIndex, text[index] == "-" { index = text.index(after: index) }
        // Optional `/namespace,`.
        if index < text.endIndex, text[index] == "/" {
            while index < text.endIndex, text[index] != "," { index = text.index(after: index) }
            if index < text.endIndex { index = text.index(after: index) }  // the comma
        }
        // Optional ack id digits.
        while index < text.endIndex, text[index].isNumber { index = text.index(after: index) }
        guard index < text.endIndex, text[index] == "[" || text[index] == "{" else { return nil }
        guard index > text.startIndex else { return nil }  // require a real prefix
        return (String(text[..<index]), String(text[index...]))
    }

    private static func isJSON(_ text: String) -> Bool {
        guard let data = text.data(using: .utf8) else { return false }
        return (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) != nil
            && (text.first == "[" || text.first == "{")
    }

    private static func isGraphQLWS(_ text: String) -> Bool {
        guard let data = text.data(using: .utf8),
            let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
            let type = object["type"] as? String
        else { return false }
        return graphqlTypes.contains(type)
    }

    private static func prettyJSON(_ text: String) -> String {
        guard let data = text.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]),
            let pretty = try? JSONSerialization.data(
                withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
            let string = String(data: pretty, encoding: .utf8)
        else { return text }
        return string
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
