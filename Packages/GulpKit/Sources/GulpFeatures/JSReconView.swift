// GulpFeatures — the JS Recon studio screen (F27, JSR-003/006/008/009). The source-map reconstruction,
// parameter mining, literal flagging and asset diff all live in GulpScanner.JSRecon and are fully
// tested on Linux; this file only drives them: paste an asset (and optionally its source map), read the
// recovered sources, mined parameters and interesting literals, and diff against an older version.

#if canImport(AppKit)
import AppKit
import GulpScanner
import Observation
import SwiftUI

/// An identifiable row for the literals table.
struct ReconLiteralRow: Identifiable {
    let id: Int
    let literal: ReconLiteral
}

/// State behind the JS Recon studio.
@MainActor
@Observable
public final class JSReconModel {
    /// The current asset's JavaScript.
    public var js: String = ""
    /// The current asset's source map JSON (optional).
    public var sourceMap: String = ""
    /// An older version of the asset to diff against (optional).
    public var baselineJS: String = ""
    /// The older version's source map (optional).
    public var baselineMap: String = ""
    /// The inventory of the current asset.
    public private(set) var inventory: ReconInventory?
    /// The diff against the baseline, when both are present.
    public private(set) var diff: ReconDiff?

    /// A model.
    public init() {}

    private func inventory(_ javascript: String, _ map: String) -> ReconInventory {
        JSRecon.inventory(js: javascript, sourceMap: map.isEmpty ? nil : Data(map.utf8))
    }

    /// Analyse the current asset and, if a baseline is present, the diff.
    public func analyze() {
        guard !js.isEmpty else {
            inventory = nil
            diff = nil
            return
        }
        let current = inventory(js, sourceMap)
        inventory = current
        if baselineJS.isEmpty {
            diff = nil
        } else {
            diff = JSRecon.diff(from: inventory(baselineJS, baselineMap), to: current)
        }
    }

    /// The current asset's literals as identifiable rows for the table (projection owned by the model).
    var literalRows: [ReconLiteralRow] {
        (inventory?.literals ?? []).enumerated().map { ReconLiteralRow(id: $0.offset, literal: $0.element) }
    }
}

/// The JS Recon studio: paste an asset, recover its sources, mine parameters and literals, diff deploys.
public struct JSReconView: View {
    @State private var model = JSReconModel()

    /// A JS Recon view.
    public init() {}

    public var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 6) {
                Text("Asset JavaScript").font(.headline)
                TextEditor(text: $model.js).font(.system(.caption, design: .monospaced)).frame(minHeight: 140)
                Text("Source map (optional)").font(.caption)
                TextEditor(text: $model.sourceMap).font(.system(.caption, design: .monospaced)).frame(
                    minHeight: 60)
                DisclosureGroup("Diff against an older version") {
                    Text("Older JavaScript").font(.caption)
                    TextEditor(text: $model.baselineJS).font(.system(.caption, design: .monospaced)).frame(
                        minHeight: 60)
                    Text("Older source map (optional)").font(.caption)
                    TextEditor(text: $model.baselineMap).font(.system(.caption, design: .monospaced)).frame(
                        minHeight: 40)
                }
                Button("Analyze") { model.analyze() }.keyboardShortcut(.return, modifiers: .command)
            }
            .padding(6)
            .frame(minWidth: 340)

            VStack(alignment: .leading, spacing: 8) {
                if let inventory = model.inventory {
                    if !inventory.sources.isEmpty {
                        Text("Recovered sources (\(inventory.sources.count))").font(.headline)
                        ForEach(inventory.sources, id: \.self) {
                            Text($0).font(.caption).textSelection(.enabled)
                        }
                    }
                    Text("Candidate parameters (\(inventory.parameters.count))").font(.headline)
                    Text(inventory.parameters.joined(separator: ", "))
                        .font(.caption).textSelection(.enabled)
                    Divider()
                    Text("Interesting literals (\(inventory.literals.count))").font(.headline)
                    Table(model.literalRows) {
                        TableColumn("Kind") { Text($0.literal.kind) }.width(120)
                        TableColumn("Value") { Text($0.literal.value).textSelection(.enabled) }
                    }
                    .frame(minHeight: 120)
                    if let diff = model.diff {
                        Divider()
                        Text("Diff vs. older version").font(.headline)
                        diffRows("param", added: diff.addedParameters, removed: diff.removedParameters)
                        diffRows("source", added: diff.addedSources, removed: diff.removedSources)
                        ForEach(Array(diff.addedLiterals.enumerated()), id: \.offset) { _, literal in
                            Label("literal [\(literal.kind)] \(literal.value)", systemImage: "plus.circle")
                                .font(.caption).foregroundStyle(.green)
                        }
                    }
                } else {
                    ContentUnavailableView(
                        "No analysis yet", systemImage: "doc.text.magnifyingglass",
                        description: Text("Paste a JS asset on the left and press Analyze (⌘↵)."))
                }
            }
            .padding(6)
            .frame(minWidth: 360)
        }
        .navigationTitle("JS Recon")
    }

    @ViewBuilder
    private func diffRows(_ noun: String, added: [String], removed: [String]) -> some View {
        ForEach(added, id: \.self) { value in
            Label("\(noun) \(value)", systemImage: "plus.circle").font(.caption).foregroundStyle(.green)
        }
        ForEach(removed, id: \.self) { value in
            Label("\(noun) \(value)", systemImage: "minus.circle").font(.caption).foregroundStyle(.red)
        }
    }
}
#endif
