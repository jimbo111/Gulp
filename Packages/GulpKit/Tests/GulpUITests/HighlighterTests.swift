#if canImport(AppKit)
import AppKit
import Testing

@testable import GulpUI

@Suite("Message highlighting (UI-011)")
@MainActor
struct HighlighterTests {
    @Test("every character has a dynamic color, so values stay readable in dark mode")
    func test_UI011_plainTextUsesTextColor() throws {
        let view = NSTextView()
        view.string = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody"
        Highlighter.highlight(view)
        let storage = try #require(view.textStorage)
        let text = view.string as NSString
        func color(of word: String) -> NSColor? {
            storage.attribute(.foregroundColor, at: text.range(of: word).location, effectiveRange: nil)
                as? NSColor
        }
        #expect(color(of: "GET") == .systemBlue)
        #expect(color(of: "Host") == .systemPurple)
        #expect(color(of: "example.com") == .textColor)
        #expect(color(of: "body") == .textColor)
        var uncolored = 0
        storage.enumerateAttribute(.foregroundColor, in: NSRange(location: 0, length: text.length)) {
            value, range, _ in
            if value == nil { uncolored += range.length }
        }
        #expect(uncolored == 0)
    }
}
#endif
