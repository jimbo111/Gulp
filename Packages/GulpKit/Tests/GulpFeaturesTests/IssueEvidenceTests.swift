#if canImport(AppKit)
import AppKit
import GulpCore
import SwiftUI
import Testing

@testable import GulpFeatures

/// The issue detail's evidence panes (SCN-002) render on the main thread when an issue opens.
@Suite("Issue evidence panes (SCN-002)")
@MainActor
struct IssueEvidenceTests {
    static func page(_ size: Int) -> [UInt8] {
        let line = Array("<div class=\"row\">alpha beta gamma delta</div>\n".utf8)
        var bytes: [UInt8] = []
        while bytes.count < size { bytes += line }
        return bytes
    }

    @Test("SCN-002: an issue with ten 256 KB evidence panes opens in under 300 ms (main thread)")
    func test_SCN002_largeEvidenceOpensFast() {
        let bytes = Self.page(HighlightedBytes.limit)
        let markers = [MarkerRange(100, 120), MarkerRange(bytes.count / 2, bytes.count / 2 + 30)]
        let panes = VStack {
            ForEach(0..<10, id: \.self) { index in
                HighlightedBytes(title: "Response \(index)", bytes: bytes, markers: markers).frame(
                    height: 220)
            }
        }
        let clock = ContinuousClock()
        let started = clock.now
        // Offscreen: lay out and draw into a bitmap, as the first paint does, without a window.
        let host = NSHostingView(rootView: panes.frame(width: 600, height: 2_400))
        host.frame = NSRect(x: 0, y: 0, width: 600, height: 2_400)
        host.layoutSubtreeIfNeeded()
        if let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) {
            host.cacheDisplay(in: host.bounds, to: rep)
        }
        let elapsed = clock.now - started
        // A SwiftUI Text took ~350 ms per pane here (3.5 s for the ten).
        #expect(elapsed < .milliseconds(300), "ten panes took \(elapsed)")
    }

    @Test("SCN-002: the proof's bytes are highlighted, at byte offsets, including non-UTF-8 bytes")
    func test_SCN002_markersHighlightTheirBytes() throws {
        let bytes = Array("HTTP/1.1 200 OK\r\n\r\n".utf8) + [0xFF, 0xC3] + Array("<b>gulp</b>".utf8)
        let proof = MarkerRange(24, 28)  // "gulp", after two bytes that are not UTF-8
        let text = HighlightedBytes.text(bytes)
        let ranges = HighlightedBytes.ranges([proof, MarkerRange(500, 600)], length: bytes.count)
        #expect(ranges == [NSRange(location: 24, length: 4)])  // the out-of-range marker is dropped
        let scroll = RawTextView.makeScrollView()
        let view = try #require(scroll.documentView as? NSTextView)
        RawTextView.Coordinator().show(text, highlights: ranges, in: view)
        let storage = try #require(view.textStorage)
        #expect((view.string as NSString).substring(with: ranges[0]) == "gulp")
        #expect(storage.attribute(.backgroundColor, at: 24, effectiveRange: nil) != nil)
        #expect(storage.attribute(.backgroundColor, at: 27, effectiveRange: nil) != nil)
        #expect(storage.attribute(.backgroundColor, at: 23, effectiveRange: nil) == nil)
        #expect(storage.attribute(.backgroundColor, at: 28, effectiveRange: nil) == nil)
    }
}
#endif
