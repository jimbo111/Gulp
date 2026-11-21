// GulpFeatures — the Assistant screen (F22, AI-001…). The agent loop, the provider adapters and the
// pre-send redaction all live in GulpAI and are tested on Linux; this screen shows only the part that
// must be visible before anything leaves the machine: the redaction gate. The user sees exactly what
// would be masked (secrets, tokens, cookies). It sends nothing: the live agent run (a provider API
// key in the Keychain, network) is not wired into the app yet.

#if canImport(AppKit)
import AppKit
import GulpAI
import GulpUI
import Observation
import SwiftUI

/// A redaction count row.
struct RedactionCountRow: Identifiable {
    let id: String
    let count: Int
}

/// State behind the Assistant.
@MainActor
@Observable
public final class AssistantModel {
    /// The prompt to send.
    public var prompt: String = ""
    /// Whether the pre-send redaction is on (AI-safety: on by default).
    public var redactionEnabled: Bool = true
    /// The provider name (display only here).
    public var provider: String = "Anthropic"
    /// The model id to use (left to the user; never hard-coded).
    public var model: String = ""
    /// The last redaction preview.
    public private(set) var preview: Redactor.Result?

    /// A model.
    public init() {}

    /// Show what the redactor would mask before the prompt is sent.
    public func previewRedaction() {
        preview = Redactor(enabled: redactionEnabled).redact(prompt)
    }

    /// The per-rule counts as sorted rows.
    var countRows: [RedactionCountRow] {
        (preview?.counts ?? [:]).sorted { $0.key < $1.key }.map {
            RedactionCountRow(id: $0.key, count: $0.value)
        }
    }
}

/// The Assistant: compose a prompt and see what the pre-send redaction would mask.
public struct AssistantView: View {
    @State private var model = AssistantModel()

    /// An Assistant view.
    public init() {}

    /// The screen.
    public var body: some View {
        HSplit {
            VStack(alignment: .leading, spacing: 6) {
                Text("Prompt").font(.headline)
                TextEditor(text: $model.prompt).font(.system(.body, design: .monospaced)).frame(
                    minHeight: 200)
                Toggle("Redact secrets before sending", isOn: $model.redactionEnabled)
                HStack {
                    Text("Provider")
                    TextField("Provider", text: $model.provider).frame(width: 140)
                    Text("Model")
                    TextField("model id", text: $model.model).frame(width: 180)
                }
                .font(.callout)
                Button("Preview redaction") { model.previewRedaction() }
                    .keyboardShortcut(.return, modifiers: .command)
                Text("Preview only: this screen sends nothing to a provider yet.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(6)
            .frame(minWidth: 340)

            VStack(alignment: .leading, spacing: 8) {
                if let preview = model.preview {
                    HStack {
                        Label("\(preview.total) value(s) masked", systemImage: "eye.slash")
                            .foregroundStyle(preview.total > 0 ? Color.orange : Color.green)
                        Spacer()
                    }
                    if !model.countRows.isEmpty {
                        Text("Masked by rule").font(.headline)
                        ForEach(model.countRows) { row in
                            LabeledContent(row.id, value: "\(row.count)")
                        }
                        Divider()
                    }
                    Text("What would be sent").font(.headline)
                    ScrollView {
                        Text(preview.text).font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    }
                } else {
                    ContentUnavailableView(
                        "Nothing previewed yet", systemImage: "sparkles",
                        description: Text("Write a prompt and press Preview redaction (⌘↵)."))
                }
            }
            .padding(6)
            .frame(minWidth: 360)
        }
        .navigationTitle("Assistant")
    }
}
#endif
