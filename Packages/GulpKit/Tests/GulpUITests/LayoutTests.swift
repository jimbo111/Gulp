#if canImport(AppKit)
import AppKit
import Foundation
import SwiftUI
import Testing

@testable import GulpUI

@Suite("Shared layouts")
@MainActor
struct LayoutTests {
    private func host<V: View>(_ view: V, width: CGFloat, height: CGFloat) -> NSHostingView<V> {
        let host = NSHostingView(rootView: view)
        host.frame = NSRect(x: 0, y: 0, width: width, height: height)
        host.layoutSubtreeIfNeeded()
        return host
    }

    private func splitView(in view: NSView) -> NSSplitView? {
        if let split = view as? NSSplitView { return split }
        return view.subviews.lazy.compactMap { splitView(in: $0) }.first
    }

    @Test("HSplit fills the offered height even when its panes are not greedy")
    func test_HSplit_fillsHeight() throws {
        let view = HSplit {
            List { Text("one") }
            ContentUnavailableView("Nothing selected", systemImage: "ladybug")
        }
        let hosted = host(view, width: 800, height: 600)
        let split = try #require(splitView(in: hosted))
        #expect(split.frame.height == 600)
        #expect(split.arrangedSubviews.allSatisfy { $0.frame.height == 600 })
    }

    @Test("VSplit fills the offered width")
    func test_VSplit_fillsWidth() throws {
        let view = VSplit {
            Text("top").frame(maxHeight: .infinity)
            Text("bottom").frame(maxHeight: .infinity)
        }
        let hosted = host(view, width: 700, height: 500)
        let split = try #require(splitView(in: hosted))
        #expect(split.frame.width == 700)
    }

    @Test("FlowLayout wraps items onto new lines instead of shrinking them (UI-002)")
    func test_UI002_flowWraps() {
        func chips(_ count: Int) -> some View {
            FlowLayout(spacing: 10, lineSpacing: 5) {
                ForEach(0..<count, id: \.self) { _ in Color.clear.frame(width: 40, height: 20) }
            }
        }
        // 40 + 10 + 40 = 90 fits in 100; the third chip starts a second line.
        let wrapped = NSHostingController(rootView: chips(3)).sizeThatFits(
            in: CGSize(width: 100, height: 1_000))
        #expect(wrapped == CGSize(width: 90, height: 45))
        let oneLine = NSHostingController(rootView: chips(3)).sizeThatFits(
            in: CGSize(width: 500, height: 1_000))
        #expect(oneLine == CGSize(width: 140, height: 20))
    }

    /// An SF Symbol name that does not exist renders as nothing: an empty toolbar button.
    @Test("every SF Symbol the app names exists")
    func test_sfSymbolsExist() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../../..").standardizedFileURL
        let folders = ["App", "Packages/GulpKit/Sources"].map { root.appendingPathComponent($0) }
        var names: Set<String> = []
        for folder in folders {
            let files = try #require(
                FileManager.default.enumerator(at: folder, includingPropertiesForKeys: nil))
            for case let file as URL in files where file.pathExtension == "swift" {
                names.formUnion(Self.symbolNames(in: try String(contentsOf: file, encoding: .utf8)))
            }
        }
        #expect(names.contains("ladybug"), "the scan found no symbols; did the folders move?")
        let missing = names.filter { NSImage(systemSymbolName: $0, accessibilityDescription: nil) == nil }
        #expect(missing.isEmpty, "unknown SF Symbols: \(missing.sorted())")
    }

    /// String literals after `systemImage:` / `systemName:` on a line, and the cases of a
    /// `var symbol` switch (the sidebar's tool icons).
    static func symbolNames(in source: String) -> Set<String> {
        let literal = /"([a-z0-9]+(?:\.[a-z0-9]+)*)"/
        var names: Set<String> = []
        var inSymbolSwitch = false
        for line in source.split(separator: "\n", omittingEmptySubsequences: false) {
            if line.contains("var symbol: String") {
                inSymbolSwitch = true
                continue
            }
            if inSymbolSwitch, line == "    }" { inSymbolSwitch = false }
            let tail: Substring?
            if let keyword = line.firstRange(of: /(systemImage|systemName|systemSymbolName):/) {
                tail = line[keyword.upperBound...]
            } else {
                tail = inSymbolSwitch && line.contains("case ") ? line : nil
            }
            guard let tail else { continue }
            for match in tail.matches(of: literal) { names.insert(String(match.output.1)) }
        }
        return names
    }
}
#endif
