// GulpFeatures — the Sequencer screen (F11, SEQ-001…). The randomness analysis (token decoding, the
// per-position Shannon estimate and the NIST-style battery) lives in GulpSequencer and is fully tested
// on Linux; this file only drives it: paste captured tokens, run the analysis, and read the verdict,
// the entropy estimate and each statistical test.

#if canImport(AppKit)
import AppKit
import GulpSequencer
import Observation
import SwiftUI

/// State behind the Sequencer.
@MainActor
@Observable
public final class SequencerModel {
    /// Captured tokens, one per line.
    public var tokenText: String = ""
    /// Significance level for the battery (a test fails when p < alpha).
    public var alpha: Double = 0.01
    /// The last analysis, if any.
    public private(set) var report: SequencerReport?
    /// Why the last run produced no report.
    public private(set) var note: String?

    /// A model.
    public init() {}

    /// The non-empty tokens currently entered.
    var tokens: [String] {
        tokenText.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Run the randomness analysis over the pasted tokens.
    public func analyze() {
        let tokens = self.tokens
        guard tokens.count >= 2 else {
            report = nil
            note = "Paste at least two tokens (one per line)."
            return
        }
        note = nil
        report = Sequencer.analyze(tokens: tokens, alpha: alpha)
    }
}

/// An identifiable wrapper so the battery can fill a `Table` (matches the other views' row pattern).
struct SequencerTestRow: Identifiable {
    let id: Int
    let test: RandomnessTest
}

/// The Sequencer tool: paste tokens, analyse their randomness, read the verdict and the test battery.
public struct SequencerView: View {
    @State private var model = SequencerModel()

    /// A Sequencer view.
    public init() {}

    public var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 6) {
                Text("Captured tokens (one per line)").font(.headline)
                TextEditor(text: $model.tokenText)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 240)
                HStack {
                    Text("\(model.tokens.count) token(s)").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Text("α")
                    TextField("alpha", value: $model.alpha, format: .number).frame(width: 60)
                    Button("Analyze") { model.analyze() }
                        .keyboardShortcut(.return, modifiers: .command)
                }
            }
            .padding(6)
            .frame(minWidth: 320)

            VStack(alignment: .leading, spacing: 8) {
                if let note = model.note {
                    Text(note).font(.callout).foregroundStyle(.secondary)
                }
                if let report = model.report {
                    HStack(spacing: 12) {
                        Label(report.verdict.rawValue, systemImage: verdictSymbol(report.verdict))
                            .font(.title3).foregroundStyle(verdictColor(report.verdict))
                        Spacer()
                    }
                    VStack(alignment: .leading, spacing: 2) {
                        LabeledContent("Samples", value: "\(report.sampleCount)")
                        LabeledContent("Unique", value: "\(report.uniqueCount)")
                        LabeledContent("Encoding", value: report.encoding.rawValue)
                        LabeledContent(
                            "Estimated entropy", value: String(format: "%.1f bits", report.estimatedBits))
                        LabeledContent(
                            "Shannon (per position)", value: String(format: "%.1f bits", report.shannonBits))
                    }
                    .font(.callout)
                    Divider()
                    Text("Randomness tests").font(.headline)
                    Table(report.tests.enumerated().map { SequencerTestRow(id: $0.offset, test: $0.element) })
                    {
                        TableColumn("Test") { Text($0.test.name) }
                        TableColumn("p-value") { row in
                            Text(row.test.pValue.map { String(format: "%.4f", $0) } ?? "—")
                        }
                        TableColumn("Result") { row in
                            Text(row.test.passed ? "pass" : "FAIL")
                                .foregroundStyle(row.test.passed ? Color.green : Color.red)
                        }
                        TableColumn("Note") { Text($0.test.note) }
                    }
                    .frame(minHeight: 180)
                    if !report.warnings.isEmpty {
                        Text("Warnings").font(.headline)
                        ForEach(report.warnings, id: \.self) { warning in
                            Label(warning, systemImage: "exclamationmark.triangle").font(.caption)
                        }
                    }
                } else {
                    ContentUnavailableView(
                        "No analysis yet", systemImage: "waveform.path.ecg",
                        description: Text("Paste tokens on the left and press Analyze (⌘↵)."))
                }
            }
            .padding(6)
            .frame(minWidth: 360)
        }
        .navigationTitle("Sequencer")
    }

    private func verdictSymbol(_ verdict: TokenVerdict) -> String {
        switch verdict {
        case .excellent, .good: "checkmark.seal"
        case .reasonable: "exclamationmark.triangle"
        case .poor, .extremelyPoor: "xmark.octagon"
        }
    }

    private func verdictColor(_ verdict: TokenVerdict) -> Color {
        switch verdict {
        case .excellent, .good: .green
        case .reasonable: .orange
        case .poor, .extremelyPoor: .red
        }
    }
}
#endif
