// GulpUI — the shared MessageEditor (doc 05 UI-010…UI-014, UI-020): Pretty / Raw / Hex tabs and an
// Inspector sidebar, used editable by Intercept, Repeater and the Fuzzer.
//
// The Raw tab edits text through `MessageText`, so bytes the user doesn't touch never change: valid
// UTF-8 is edited as UTF-8, anything else in a byte-exact Latin-1 view.

#if canImport(AppKit)
import AppKit
import Foundation
import GulpCore
import SwiftUI

/// A request or response viewer/editor with an Inspector.
public struct MessageEditor: View {
    /// The editor's tabs (UI-010).
    public enum Tab: String, CaseIterable, Sendable {
        case pretty = "Pretty"
        case raw = "Raw"
        case hex = "Hex"
    }

    let title: String
    @Binding var bytes: [UInt8]
    let editable: Bool
    @State private var tab = Tab.raw
    @State private var showInvisibles = false
    @AppStorage("gulp.editor.inspector") private var showInspector = true

    /// An editor for `bytes`; read-only unless `editable`.
    public init(title: String, bytes: Binding<[UInt8]>, editable: Bool = false) {
        self.title = title
        _bytes = bytes
        self.editable = editable
    }

    /// The screen.
    public var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Text(title).font(.headline)
                Spacer()
                Picker("", selection: $tab) {
                    ForEach(Tab.allCases, id: \.self) { Text($0.rawValue) }
                }
                .pickerStyle(.segmented)
                .fixedSize()
                Toggle(isOn: $showInvisibles) { Image(systemName: "paragraphsign") }
                    .toggleStyle(.button)
                    .help("Show CR, LF and tab characters (UI-014)")
                Toggle(isOn: $showInspector) { Image(systemName: "sidebar.right") }
                    .toggleStyle(.button)
                    .help("Inspector (UI-020)")
            }
            .controlSize(.small)
            .padding(6)
            Divider()
            HSplitView {
                content
                    .frame(minWidth: 240, maxWidth: .infinity, maxHeight: .infinity)
                if showInspector {
                    InspectorView(bytes: bytes)
                        .frame(minWidth: 180, idealWidth: 240, maxWidth: 360)
                }
            }
        }
    }

    @ViewBuilder private var content: some View {
        switch tab {
        case .raw:
            MessageTextView(bytes: $bytes, editable: editable, showInvisibles: showInvisibles)
        case .pretty:
            let pretty = Array(Pretty.render(bytes).utf8)
            MessageTextView(bytes: .constant(pretty), editable: false, showInvisibles: false)
        case .hex:
            HexView(bytes: bytes)
        }
    }
}

/// Pretty rendering (UI-010): the header block as is, a JSON body re-indented.
enum Pretty {
    static func render(_ bytes: [UInt8]) -> String {
        let (end, terminator) = HTTP1.headerBlockEnd(bytes)
        guard terminator != 0, end < bytes.count else { return MessageText.decode(bytes).text }
        let head = MessageText.decode(Array(bytes[..<end])).text
        let body = Data(bytes[end...])
        if let object = try? JSONSerialization.jsonObject(with: body, options: [.fragmentsAllowed]),
            let pretty = try? JSONSerialization.data(
                withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed])
        {
            return head + String(decoding: pretty, as: UTF8.self)
        }
        return head + MessageText.decode(Array(bytes[end...])).text
    }
}

/// The Raw/Pretty text view: NSTextView with find (UI-013), invisibles (UI-014), header highlighting
/// (UI-011, header block only) and non-contiguous layout for large messages.
struct MessageTextView: NSViewRepresentable {
    @Binding var bytes: [UInt8]
    let editable: Bool
    let showInvisibles: Bool

    func makeCoordinator() -> Coordinator { Coordinator(bytes: $bytes) }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        guard let view = scroll.documentView as? NSTextView else { return scroll }
        view.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        view.isRichText = false
        view.allowsUndo = true
        view.usesFindBar = true
        view.isIncrementalSearchingEnabled = true
        view.isAutomaticQuoteSubstitutionEnabled = false
        view.isAutomaticDashSubstitutionEnabled = false
        view.isAutomaticTextReplacementEnabled = false
        view.isAutomaticSpellingCorrectionEnabled = false
        view.textContainerInset = NSSize(width: 4, height: 4)
        view.layoutManager?.allowsNonContiguousLayout = true
        view.delegate = context.coordinator
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let view = scroll.documentView as? NSTextView else { return }
        view.isEditable = editable
        view.layoutManager?.showsInvisibleCharacters = showInvisibles
        context.coordinator.binding = $bytes
        if bytes != context.coordinator.shownBytes {
            let (text, encoding) = MessageText.decode(bytes)
            context.coordinator.encoding = encoding
            context.coordinator.shownBytes = bytes
            view.string = text
            Highlighter.highlight(view)
        }
    }

    @MainActor
    final class Coordinator: NSObject, NSTextViewDelegate {
        var binding: Binding<[UInt8]>
        var shownBytes: [UInt8]?
        var encoding = MessageText.Encoding.utf8

        init(bytes: Binding<[UInt8]>) {
            binding = bytes
        }

        func textDidChange(_ notification: Notification) {
            guard let view = notification.object as? NSTextView else { return }
            let bytes = MessageText.encode(view.string, encoding)
            shownBytes = bytes
            binding.wrappedValue = bytes
        }
    }
}

/// Minimal syntax highlighting (UI-011): the start line and header names in the header block.
enum Highlighter {
    @MainActor
    static func highlight(_ view: NSTextView) {
        guard let storage = view.textStorage else { return }
        let text = storage.string as NSString
        let limit = min(text.length, 64 * 1_024)
        storage.beginEditing()
        storage.removeAttribute(.foregroundColor, range: NSRange(location: 0, length: text.length))
        var location = 0
        var first = true
        while location < limit {
            let line = text.lineRange(for: NSRange(location: location, length: 0))
            let content = text.substring(with: line).trimmingCharacters(in: .newlines)
            if content.isEmpty { break }  // end of the header block
            if first {
                storage.addAttribute(.foregroundColor, value: NSColor.systemBlue, range: line)
                first = false
            } else if let colon = content.firstIndex(of: ":") {
                let length = content.distance(from: content.startIndex, to: colon)
                let name = NSRange(location: line.location, length: length)
                storage.addAttribute(.foregroundColor, value: NSColor.systemPurple, range: name)
            }
            location = NSMaxRange(line)
        }
        storage.endEditing()
    }
}

/// The Hex tab (UI-012, read-only for now): offset, 16 bytes, ASCII.
struct HexView: View {
    let bytes: [UInt8]

    var body: some View {
        let lines = (bytes.count + 15) / 16
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(0..<lines, id: \.self) { line in
                    Text(Self.line(bytes, line)).font(.system(.body, design: .monospaced))
                }
            }
            .textSelection(.enabled)
            .padding(6)
        }
    }

    static func line(_ bytes: [UInt8], _ line: Int) -> String {
        let start = line * 16
        let end = min(start + 16, bytes.count)
        var hex = ""
        var ascii = ""
        for index in start..<end {
            hex += String(format: "%02x ", bytes[index])
            let byte = bytes[index]
            ascii.append(byte >= 0x20 && byte < 0x7F ? Character(UnicodeScalar(byte)) : ".")
        }
        let padding = String(repeating: "   ", count: 16 - (end - start))
        return String(format: "%08x  ", start) + hex + padding + " " + ascii
    }
}

/// The Inspector sidebar (UI-020): the message's parsed sections.
struct InspectorView: View {
    let bytes: [UInt8]

    var body: some View {
        let inspection = MessageInspection(bytes)
        List {
            ForEach(Array(inspection.sections.enumerated()), id: \.offset) { _, section in
                Section(section.title) {
                    ForEach(Array(section.rows.enumerated()), id: \.offset) { _, row in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(row.name).font(.caption).foregroundStyle(.secondary)
                            Text(row.value.removingPercentEncoding ?? row.value)
                                .font(.system(.body, design: .monospaced))
                                .textSelection(.enabled)
                                .lineLimit(3)
                        }
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }
}
#endif
