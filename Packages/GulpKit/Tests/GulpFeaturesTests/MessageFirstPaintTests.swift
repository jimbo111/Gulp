#if canImport(AppKit)
import AppKit
import GulpCore
import Testing

@testable import GulpFeatures
@testable import GulpUI

/// Doc 01 §9: "Message editor: open a 5 MB response < 300 ms to first paint". Everything here runs
/// on the main thread when a message opens: decode the bytes, fill the text view, lay out and draw
/// the visible part (offscreen, into a bitmap, so no window or screen is needed). The text view is
/// created inside the timed part, as it is the first time a message opens. TextKit itself is warmed
/// up first: in the app it already drew the window's other text, and its one-time start-up is not
/// part of opening a message. Serialized, so parallel tests do not share the CPU being measured.
@Suite("Opening a 5 MB message (doc 01 §9)", .serialized)
@MainActor
struct MessageFirstPaintTests {
    static let budget = Duration.milliseconds(300)

    /// A 5 MB JSON response (valid UTF-8).
    nonisolated static let json: [UInt8] = {
        var body = Array("[".utf8)
        let item = Array(#"{"id":12345,"name":"alpha beta gamma","ok":true,"tags":["x","y"]},"#.utf8) + [0x0A]
        while body.count < 5 * 1_048_576 - item.count { body += item }
        body += Array("{}]".utf8)
        let head =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\n\r\n"
        return Array(head.utf8) + body
    }()

    /// The same response with bytes that are not UTF-8 (a binary body): the Latin-1 path.
    nonisolated static let binary: [UInt8] = {
        var bytes = json
        for index in stride(from: 200, to: bytes.count, by: 97) { bytes[index] = 0xFF }
        return bytes
    }()

    /// Start TextKit and its fonts once, as the app has by the time a message opens.
    static let warmUp: Void = {
        let scroll = MessageTextView.makeScrollView(
            delegate: MessageTextView.Coordinator(bytes: .constant([])))
        (scroll.documentView as? NSTextView)?.string = "HTTP/1.1 200 OK\r\n\r\n{}"
        paint(scroll)
    }()

    /// Lay out and draw what a 700×600 pane shows, as the first paint does.
    static func paint(_ scroll: NSScrollView) {
        scroll.frame = NSRect(x: 0, y: 0, width: 700, height: 600)
        guard let view = scroll.documentView as? NSTextView, let container = view.textContainer,
            let rep = scroll.bitmapImageRepForCachingDisplay(in: scroll.bounds)
        else { return }
        view.layoutManager?.ensureLayout(forBoundingRect: scroll.contentView.bounds, in: container)
        scroll.cacheDisplay(in: scroll.bounds, to: rep)
    }

    @Test(
        "HIS-003: History and Repeater show a 5 MB response in under 300 ms; an update that changes nothing is cheap"
    )
    func test_HIS003_responseViewerFirstPaint() throws {
        let bytes = Bytes(Self.json)
        Self.warmUp
        let clock = ContinuousClock()
        let started = clock.now
        let shown = bytes.count > MessageViewer.displayLimit ? bytes[0..<MessageViewer.displayLimit] : bytes
        let scroll = RawTextView.makeScrollView()
        let coordinator = RawTextView.Coordinator()
        let view = try #require(scroll.textView)
        coordinator.show(shown.string(), in: view)
        Self.paint(scroll)
        let elapsed = clock.now - started
        #expect(elapsed < Self.budget, "first paint took \(elapsed)")
        #expect(view.string.utf8.count == MessageViewer.displayLimit)
        // A SwiftUI update with the same message must not redo the work (it bridged the whole
        // text back from the view before: ~30 ms per update for 1 MB).
        let again = clock.measure { coordinator.show(shown.string(), in: view) }
        #expect(again < .milliseconds(20), "a no-op update took \(again)")
    }

    @Test(
        "UI-010: the MessageEditor opens a 5 MB message in under 300 ms, UTF-8 or binary",
        arguments: ["utf8", "binary"])
    func test_UI010_editorFirstPaint(kind: String) throws {
        let bytes = kind == "utf8" ? Self.json : Self.binary  // (not an argument: a failure would print 5 MB)
        Self.warmUp
        let clock = ContinuousClock()
        let started = clock.now
        let coordinator = MessageTextView.Coordinator(bytes: .constant(bytes))
        let scroll = MessageTextView.makeScrollView(delegate: coordinator)
        let view = try #require(scroll.textView)
        coordinator.show(bytes, in: view)
        _ = MessageInspection(bytes)  // the Inspector beside it
        Self.paint(scroll)
        let elapsed = clock.now - started
        #expect(elapsed < Self.budget, "\(kind): first paint took \(elapsed)")
        #expect(coordinator.encoding == (kind == "utf8" ? .utf8 : .latin1))
        let lossless = MessageText.encode(view.string, coordinator.encoding) == bytes
        #expect(lossless, "\(kind): the text view's text does not encode back to the bytes")
    }
}

extension NSScrollView {
    fileprivate var textView: NSTextView? { documentView as? NSTextView }
}
#endif
