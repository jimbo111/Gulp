import Testing

@testable import GulpCore

// F05 HIS-007: the Events view — SSE parsing, chunked decoding, and event arrival times.

@Suite("GulpCore — Server-Sent Events (HIS-007)")
struct ServerSentEventsTests {
    @Test("SSE fields, comments, multi-line data, CR/LF/CRLF endings, and any split")
    func test_HIS007_sseParsing() {
        let stream =
            ": heartbeat\n\nid: 1\nevent: tick\ndata: a\ndata: b\n\r\n"
            + "data:no-space\rretry: 50\r\n\r\nevent: x\n\n"
        let bytes = Array(stream.utf8)
        var whole = SSEParser()
        let all = whole.feed(bytes)
        #expect(all.count == 2)  // the comment block and the data-less "event: x" dispatch nothing
        #expect(all[0] == SSEEvent(id: "1", event: "tick", data: "a\nb"))
        #expect(all[1] == SSEEvent(data: "no-space", retry: 50))
        var split = SSEParser()
        let pieces = bytes.map { split.feed([$0]) }.flatMap { $0 }
        #expect(pieces == all)
    }

    @Test("A chunked stream reads the same at any arrival split; BWS, extensions and trailers are skipped")
    func test_HIS007_chunkedAnySplit() {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
        let body = "5 ;ext=1\r\ndata:\r\n4\r\n a\n\n\r\n9\r\ndata: b\n\n\r\n0\r\nX-Trailer: y\r\n\r\n"
        let response = RawResponse(Bytes(head + body))
        #expect(SSETimeline.events(in: response, marks: nil).map(\.data) == ["a", "b"])
        let total = response.bytes.count
        let marks = (head.utf8.count + 1...total).map { StreamMark(offset: $0, ms: Double($0)) }
        let timed = SSETimeline.events(in: response, marks: marks)
        #expect(timed.map(\.data) == ["a", "b"])
        // Each event is stamped with the mark at which its blank line arrived.
        let firstBlank = head.utf8.count + "5 ;ext=1\r\ndata:\r\n4\r\n a\n\n".utf8.count
        #expect(timed.first?.receivedMs == Double(firstBlank))
    }

    @Test("A hostile chunk size (signed, prefixed, not hex) ends the payload where framing breaks; no trap")
    func test_HIS007_hostileChunkSize() {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
        for size in ["-5", "+9", "0x9", "zz"] {
            let wire = head + "9\r\ndata: a\n\n\r\n" + size + "\r\ndata: b\n\n\r\n0\r\n\r\n"
            let response = RawResponse(Bytes(wire))
            #expect(SSETimeline.events(in: response, marks: nil).map(\.data) == ["a"])
            let marks = [StreamMark(offset: wire.utf8.count, ms: 5)]
            #expect(SSETimeline.events(in: response, marks: marks).map(\.data) == ["a"])
        }
    }

    @Test("Event times come from the stream marks; without marks the events still parse")
    func test_HIS007_timeline() {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
        let first = "d\r\ndata: first\n\n\r\n"  // 13 payload bytes
        let second = "e\r\ndata: second\n\n\r\n0\r\n\r\n"  // 14
        let response = RawResponse(Bytes(head + first + second))
        #expect(SSETimeline.isEventStream(response))
        let headCount = head.utf8.count
        let marks = [
            StreamMark(offset: headCount + first.utf8.count, ms: 10),
            StreamMark(offset: headCount + first.utf8.count + second.utf8.count, ms: 250),
        ]
        let events = SSETimeline.events(in: response, marks: marks)
        #expect(events.map(\.data) == ["first", "second"])
        #expect(events.map(\.receivedMs) == [10, 250])
        let untimed = SSETimeline.events(in: response, marks: nil)
        #expect(untimed.map(\.data) == ["first", "second"] && untimed.allSatisfy { $0.receivedMs == nil })
    }
}
