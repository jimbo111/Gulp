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

    @Test("Chunked bodies decode the same whatever the pieces; extensions and trailers are skipped")
    func test_HIS007_chunkedDecoder() {
        let wire = Array("4;ext=1\r\nWiki\r\n6\r\npedia \r\n0\r\nX-Trailer: y\r\n\r\nignored".utf8)
        var whole = ChunkedBodyDecoder()
        #expect(whole.feed(wire) == Array("Wikipedia ".utf8))
        var split = ChunkedBodyDecoder()
        #expect(wire.flatMap { split.feed([$0]) } == Array("Wikipedia ".utf8))
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
