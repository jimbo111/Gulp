// GulpFeatures — the DOM Probe screen (F16/M13a, DOM-001…). The CDP instrumentation and the finding
// parser live in GulpBrowser and are tested on Linux against a mock transport (and against real
// Chromium in the DoD); this file shows the shipped instrumentation script and decodes a captured
// `__gulpReport` payload into a source→sink DOM-XSS finding. The live run (navigate + collect,
// `GulpBrowser.DOMProbe.run`) needs a browser and is not wired into this screen yet.

#if canImport(AppKit)
import AppKit
import GulpBrowser
import Observation
import SwiftUI

/// State behind the DOM Probe inspector.
@MainActor
@Observable
public final class DOMProbeModel {
    /// A captured `__gulpReport` payload (JSON) to decode.
    public var reportJSON: String = ""
    /// The decoded finding, if valid.
    public private(set) var finding: DOMFinding?
    /// Whether the last parse failed.
    public private(set) var failed = false

    /// The instrumentation script that ships (the same bytes run in Chromium).
    public var instrumentation: String { DOMProbe.instrumentation }

    /// A model.
    public init() {}

    /// Decode the pasted report payload into a finding.
    public func parse() {
        guard !reportJSON.isEmpty else {
            finding = nil
            failed = false
            return
        }
        finding = DOMProbe.parse(reportJSON)
        failed = finding == nil
    }
}

/// The DOM Probe inspector: read the shipped instrumentation and decode a captured source→sink flow.
public struct DOMProbeView: View {
    @State private var model = DOMProbeModel()

    /// A DOM Probe view.
    public init() {}

    public var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 6) {
                Text("Captured __gulpReport payload (JSON)").font(.headline)
                TextEditor(text: $model.reportJSON).font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 120)
                Button("Decode finding") { model.parse() }.keyboardShortcut(.return, modifiers: .command)
                if model.failed {
                    Label("Not a valid finding payload.", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.red)
                }
                Divider()
                Text("Instrumentation (ships to the page)").font(.headline)
                ScrollView {
                    Text(model.instrumentation).font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(6)
            .frame(minWidth: 360)

            VStack(alignment: .leading, spacing: 8) {
                if let finding = model.finding {
                    Label("DOM-XSS flow", systemImage: "exclamationmark.octagon").font(.title3)
                        .foregroundStyle(.red)
                    LabeledContent("Source", value: finding.source)
                    LabeledContent("Sink", value: finding.sink)
                    Divider()
                    Text("Payload (source)").font(.headline)
                    Text(finding.sample).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    Text("Value at sink").font(.headline)
                    Text(finding.snippet).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                } else {
                    ContentUnavailableView(
                        "No finding decoded", systemImage: "ladybug",
                        description: Text("Paste a __gulpReport payload and press Decode finding (⌘↵)."))
                }
            }
            .padding(6)
            .frame(minWidth: 340)
        }
        .navigationTitle("DOM Probe")
    }
}
#endif
