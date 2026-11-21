// GulpFeatures — the Extensions screen (F15/M15, EXT-001…). The manifest model, its permission set and
// the JSON-RPC extension host live in GulpExtensions and are tested on Linux (the host against a real
// subprocess); this file drives the inspection side: load a `gulp-extension.json`, read its declared
// runtime, permissions and hooks before trusting it.

#if canImport(AppKit)
import AppKit
import GulpExtensions
import GulpUI
import Observation
import SwiftUI

/// A permission row.
struct PermissionRow: Identifiable {
    let id: String
    let granted: Bool
}

/// State behind the Extensions inspector.
@MainActor
@Observable
public final class ExtensionsModel {
    /// The manifest JSON.
    public var manifestJSON: String = ""
    /// The parsed manifest, if valid.
    public private(set) var manifest: ExtensionManifest?
    /// Why parsing failed, if it did.
    public private(set) var error: String?

    /// A model.
    public init() {}

    /// Parse the pasted manifest.
    public func parse() {
        guard !manifestJSON.isEmpty else {
            manifest = nil
            error = nil
            return
        }
        do {
            manifest = try ExtensionManifest.decode(Data(manifestJSON.utf8))
            error = nil
        } catch {
            manifest = nil
            self.error = "Invalid manifest: \(error)"
        }
    }

    /// Every permission, with whether this manifest requests it.
    var permissionRows: [PermissionRow] {
        guard let manifest else { return [] }
        return ExtensionPermission.allCases.map {
            PermissionRow(id: $0.rawValue, granted: manifest.allows($0))
        }
    }
}

/// The Extensions inspector: load a manifest and audit its runtime, permissions and hooks.
public struct ExtensionsView: View {
    @State private var model = ExtensionsModel()

    /// An Extensions view.
    public init() {}

    /// The screen.
    public var body: some View {
        HSplit {
            VStack(alignment: .leading, spacing: 6) {
                Text("gulp-extension.json").font(.headline)
                TextEditor(text: $model.manifestJSON).font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 260)
                Button("Load manifest") { model.parse() }.keyboardShortcut(.return, modifiers: .command)
                if let error = model.error {
                    Label(error, systemImage: "exclamationmark.triangle").font(.caption)
                        .foregroundStyle(.red)
                }
            }
            .padding(6)
            .frame(minWidth: 340)

            VStack(alignment: .leading, spacing: 8) {
                if let manifest = model.manifest {
                    Text(manifest.name).font(.title3)
                    LabeledContent("ID", value: manifest.id)
                    LabeledContent("Version", value: manifest.version)
                    LabeledContent("Author", value: manifest.author ?? "—")
                    LabeledContent("Runtime", value: manifest.runtime.rawValue)
                    LabeledContent("Min API", value: "\(manifest.minAPIVersion)")
                    Divider()
                    Text("Permissions").font(.headline)
                    ForEach(model.permissionRows) { row in
                        Label(
                            row.id,
                            systemImage: row.granted ? "checkmark.circle.fill" : "circle"
                        )
                        .foregroundStyle(row.granted ? Color.orange : Color.secondary)
                        .font(.caption)
                    }
                    Divider()
                    Text("Hooks (\(manifest.hooks.count))").font(.headline)
                    ForEach(manifest.hooks, id: \.self) { Text($0).font(.caption) }
                } else {
                    ContentUnavailableView(
                        "No manifest loaded", systemImage: "puzzlepiece.extension",
                        description: Text("Paste a gulp-extension.json and press Load manifest (⌘↵)."))
                }
            }
            .padding(6)
            .frame(minWidth: 360)
        }
        .navigationTitle("Extensions")
    }
}
#endif
