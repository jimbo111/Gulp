// GulpUI — no Writing Tools in Gulp's text views (docs/07, small decisions 2026-11-20).
//
// Gulp's text is traffic under test: raw requests, payloads, tokens. macOS's Writing Tools would
// offer to rewrite it (and send it to a language model), and its floating button stays behind
// over the sidebar edge after the focused editor goes away.

#if canImport(AppKit)
import AppKit
import SwiftUI

extension View {
    /// Turns Writing Tools off for every SwiftUI text view below this one (macOS 15+).
    @ViewBuilder public func writingToolsDisabled() -> some View {
        if #available(macOS 15.0, *) {
            writingToolsBehavior(.disabled)
        } else {
            self
        }
    }
}

extension NSTextView {
    /// Turns Writing Tools off for this AppKit text view (macOS 15+).
    public func disableWritingTools() {
        if #available(macOS 15.0, *) {
            writingToolsBehavior = .none
        }
    }
}
#endif
