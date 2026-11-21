// GulpCore — Server-Sent Events for the History "Events" view (F05 HIS-007): an incremental
// `text/event-stream` parser (WHATWG HTML §9.2.6) and the event timeline of a recorded streamed
// response (each event with the time its bytes arrived; chunked bodies via `HTTP1.walkChunked`).

/// One dispatched SSE event.
public struct SSEEvent: Sendable, Equatable {
    /// The `id` field of this event's block, if any.
    public var id: String?
    /// The `event` field (nil means the default `message`).
    public var event: String?
    /// The data lines joined with newlines.
    public var data: String
    /// The `retry` field, if any.
    public var retry: Int?
    /// When its last byte arrived (ms since the send started), when known.
    public var receivedMs: Double?

    /// An event.
    public init(
        id: String? = nil, event: String? = nil, data: String, retry: Int? = nil, receivedMs: Double? = nil
    ) {
        self.id = id
        self.event = event
        self.data = data
        self.retry = retry
        self.receivedMs = receivedMs
    }
}

/// Incremental `text/event-stream` parser: feed body bytes in any pieces.
public struct SSEParser: Sendable {
    private var line: [UInt8] = []
    private var afterCR = false
    private var data: [String] = []
    private var sawData = false
    private var event: String?
    private var id: String?
    private var retry: Int?

    /// A parser at the start of a stream.
    public init() {}

    /// Feed bytes; returns the events they completed.
    public mutating func feed(_ bytes: [UInt8]) -> [SSEEvent] {
        var out: [SSEEvent] = []
        for byte in bytes {
            if afterCR {
                afterCR = false
                if byte == 0x0A { continue }  // CRLF: the line already ended at CR
            }
            switch byte {
            case 0x0D:
                afterCR = true
                endLine(&out)
            case 0x0A:
                endLine(&out)
            default:
                line.append(byte)
            }
        }
        return out
    }

    private mutating func endLine(_ out: inout [SSEEvent]) {
        defer { line = [] }
        if line.isEmpty {
            if sawData {
                out.append(SSEEvent(id: id, event: event, data: data.joined(separator: "\n"), retry: retry))
            }
            data = []
            sawData = false
            event = nil
            id = nil
            retry = nil
            return
        }
        if line.first == 0x3A { return }  // ":" comment
        let text = String(decoding: line, as: UTF8.self)
        var name = text
        var value = ""
        if let colon = text.firstIndex(of: ":") {
            name = String(text[..<colon])
            value = String(text[text.index(after: colon)...])
            if value.hasPrefix(" ") { value.removeFirst() }
        }
        switch name {
        case "data":
            data.append(value)
            sawData = true
        case "event": event = value
        case "id" where !value.contains("\0"): id = value
        case "retry": retry = Int(value)
        default: break
        }
    }
}

/// The events of a recorded `text/event-stream` response.
public enum SSETimeline {
    /// Whether `response` is an event stream.
    public static func isEventStream(_ response: RawResponse) -> Bool {
        response.headerValue("content-type")?.string().lowercased().hasPrefix("text/event-stream") == true
    }

    /// The response's events, each with the time its bytes arrived when `marks` (from
    /// `Timing.streamMarks`) line up with an HTTP/1 wire body; otherwise without times.
    public static func events(in response: RawResponse, marks: [StreamMark]?) -> [SSEEvent] {
        let wire = response.bytes.rawBytes
        let (headerEnd, terminator) = HTTP1.headerBlockEnd(wire)
        guard terminator != 0 else { return [] }
        // The payload as ranges of `wire`: each chunk's data up to where the framing ends or breaks
        // (the same walker every chunked view uses), or the whole body.
        var payload: [Range<Int>] = []
        if response.parsed.transferEncodingChunked {
            _ = HTTP1.walkChunked(wire, from: headerEnd, data: { payload.append($0) })
        } else {
            payload = [headerEnd..<wire.count]
        }
        var parser = SSEParser()
        let isHTTP1 = response.bytes[response.parsed.version].string().hasPrefix("HTTP/1")
        let encoded = response.headerValue("content-encoding") != nil
        guard let marks, !marks.isEmpty, isHTTP1, !encoded, let total = marks.last?.offset else {
            return parser.feed(payload.flatMap { wire[$0] })
        }
        // Marks count every byte received; bytes before this response (interim 1xx) come first.
        let shift = max(0, total - wire.count)
        var events: [SSEEvent] = []
        var position = headerEnd
        var next = 0  // the first payload range not wholly fed yet
        func take(upTo end: Int) -> [UInt8] {
            var out: [UInt8] = []
            while next < payload.count, payload[next].lowerBound < end {
                let range = payload[next]
                out += wire[max(range.lowerBound, position)..<min(range.upperBound, end)]
                guard range.upperBound <= end else { break }
                next += 1
            }
            return out
        }
        for mark in marks {
            let end = min(wire.count, max(headerEnd, mark.offset - shift))
            guard end > position else { continue }
            for var event in parser.feed(take(upTo: end)) {
                event.receivedMs = mark.ms
                events.append(event)
            }
            position = end
        }
        if position < wire.count { events += parser.feed(take(upTo: wire.count)) }
        return events
    }
}
