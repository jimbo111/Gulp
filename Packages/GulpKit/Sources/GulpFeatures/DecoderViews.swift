// GulpFeatures — Decoder, Comparer and JWT Workbench (F12, F13, ADV-010…013). The logic is in
// GulpCodec (transforms, Smart Decode, JWT), GulpDiff (the diff engine) and GulpWorkspace (the
// inbox that "Send to Comparer/Decoder" fills), all tested on Linux; this file only shows it.

#if canImport(AppKit)
import AppKit
import GulpCodec
import GulpCore
import GulpDiff
import GulpWorkspace
import Observation
import SwiftUI

// MARK: - Decoder (DEC-001…DEC-005)

/// One editable step of the stacked editor.
public struct DecoderStepRow: Identifiable, Hashable {
    public var id = UUID()
    /// Operation name.
    public var name: String
    /// `key=value, …` arguments.
    public var arguments: String = ""

    var step: TransformStep {
        var parsed: [String: String] = [:]
        for pair in arguments.split(separator: ",") {
            let parts = pair.split(separator: "=", maxSplits: 1).map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            if let key = parts.first, !key.isEmpty { parsed[key] = parts.count > 1 ? parts[1] : "true" }
        }
        return TransformStep(name, parsed)
    }
}

/// State behind the Decoder.
@MainActor
@Observable
public final class DecoderModel {
    /// The input bytes.
    public var input: [UInt8] = [] { didSet { evaluate() } }
    /// The steps.
    public var steps: [DecoderStepRow] = [] { didSet { evaluate() } }
    /// Each level's value (input first); a failing step stops the column.
    public private(set) var levels: [[UInt8]] = [[]]
    /// Why the chain stopped, if it did.
    public private(set) var error: String?
    /// The chain Smart Decode found (DEC-003), waiting to be accepted.
    public private(set) var suggestion: SmartDecodeResult?

    @ObservationIgnored let session: ProjectSession
    @ObservationIgnored private var watcher: Task<Void, Never>?

    /// The Decoder for `session`.
    public init(session: ProjectSession) {
        self.session = session
        watcher = Task { [weak self] in
            guard let inbox = self?.session.inbox else { return }
            for await tool in await inbox.opened() where tool == .decoder {
                let bytes = await inbox.decoderInput
                self?.input = bytes
            }
        }
        Task { [weak self] in
            guard let inbox = self?.session.inbox else { return }
            let bytes = await inbox.decoderInput
            if self?.input.isEmpty == true { self?.input = bytes }
        }
    }

    /// Every operation name, sorted.
    public static let operations = Transforms.all.keys.sorted()

    func evaluate() {
        var values = [input]
        error = nil
        for (index, row) in steps.enumerated() {
            do {
                values.append(try Transforms.run(values[values.count - 1], [row.step]).last ?? [])
            } catch let failure as CodecError {
                error = "Step \(index + 1): \(failure.message)"
                break
            } catch {
                self.error = "Step \(index + 1): \(error)"
                break
            }
        }
        levels = values
    }

    /// Run Smart Decode on the input.
    public func smartDecode() {
        let result = SmartDecode.run(input)
        suggestion = result.steps.isEmpty ? nil : result
        if result.steps.isEmpty { error = "Smart Decode found nothing to decode." }
    }

    /// Accept the suggested chain as explicit steps.
    public func acceptSuggestion() {
        guard let suggestion else { return }
        steps = suggestion.steps.map { DecoderStepRow(name: $0.name) }
        self.suggestion = nil
    }

    /// Add a step.
    public func addStep(_ name: String = "base64-decode") {
        steps.append(DecoderStepRow(name: name))
    }

    /// Replace the steps with their inverses in reverse order (re-encode an edited value).
    public func reverseChain() {
        guard let reversed = Transforms.reversed(steps.map(\.step)) else {
            error = "A step has no inverse (hashes, pretty-printing…)."
            return
        }
        if let last = levels.last { input = last }
        steps = reversed.map {
            DecoderStepRow(
                name: $0.name, arguments: $0.arguments.map { "\($0.key)=\($0.value)" }.joined(separator: ", ")
            )
        }
    }

    /// Load the input from a file.
    public func load() {
        let panel = NSOpenPanel()
        if panel.runModal() == .OK, let url = panel.url, let data = try? Data(contentsOf: url) {
            input = [UInt8](data)
        }
    }

    /// Copy a level as text (or hex for binary).
    public func copy(level: Int) {
        guard levels.indices.contains(level) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(Self.text(levels[level], hex: false), forType: .string)
    }

    /// Display text: UTF-8 (lossy) or a hex dump.
    public static func text(_ bytes: [UInt8], hex: Bool) -> String {
        if hex {
            return stride(from: 0, to: bytes.count, by: 16).map { offset in
                let row = bytes[offset..<min(offset + 16, bytes.count)]
                return String(format: "%08x  ", offset)
                    + row.map { String(format: "%02x", $0) }.joined(separator: " ")
            }.joined(separator: "\n")
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}

/// The Decoder: input, then one pane per step (DEC-001).
public struct DecoderView: View {
    @State private var model: DecoderModel
    @State private var hexLevels: Set<Int> = []

    /// The Decoder for `session`.
    public init(session: ProjectSession) {
        _model = State(initialValue: DecoderModel(session: session))
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button("Smart Decode") { model.smartDecode() }
                Button("Add Step") { model.addStep() }
                Button("Reverse Chain") { model.reverseChain() }.disabled(model.steps.isEmpty)
                Button("Load File…") { model.load() }
                Spacer()
                if let error = model.error { Text(error).foregroundStyle(.red).font(.caption) }
            }
            if let suggestion = model.suggestion {
                HStack {
                    Text("Detected: " + suggestion.chain.joined(separator: " → ")).font(.callout)
                    Button("Use These Steps") { model.acceptSuggestion() }
                }
                .padding(6)
                .background(.yellow.opacity(0.15), in: RoundedRectangle(cornerRadius: 6))
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    levelPane(0, title: "Input", editable: true)
                    ForEach(Array(model.steps.enumerated()), id: \.element.id) { index, _ in
                        stepControls(index)
                        if model.levels.indices.contains(index + 1) {
                            levelPane(index + 1, title: model.steps[index].name, editable: false)
                        }
                    }
                }
            }
        }
        .padding()
        .navigationTitle("Decoder")
    }

    private func stepControls(_ index: Int) -> some View {
        HStack {
            Picker("Step \(index + 1)", selection: $model.steps[index].name) {
                ForEach(DecoderModel.operations, id: \.self) { Text($0).tag($0) }
            }
            .frame(maxWidth: 280)
            TextField("arguments (key=value, …)", text: $model.steps[index].arguments)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 260)
            Button {
                if index > 0 { model.steps.swapAt(index, index - 1) }
            } label: {
                Image(systemName: "arrow.up")
            }
            .disabled(index == 0)
            Button(role: .destructive) {
                model.steps.remove(at: index)
            } label: {
                Image(systemName: "trash")
            }
        }
    }

    private func levelPane(_ level: Int, title: String, editable: Bool) -> some View {
        let bytes = model.levels.indices.contains(level) ? model.levels[level] : []
        let hex = hexLevels.contains(level)
        return VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title).font(.headline)
                Text("\(bytes.count) bytes").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Toggle(
                    "Hex",
                    isOn: Binding(
                        get: { hex },
                        set: { on in if on { hexLevels.insert(level) } else { hexLevels.remove(level) } })
                )
                .toggleStyle(.checkbox)
                Button("Copy") { model.copy(level: level) }
            }
            if editable && !hex {
                TextEditor(
                    text: Binding(
                        get: { DecoderModel.text(model.input, hex: false) },
                        set: { model.input = Array($0.utf8) })
                )
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 80, maxHeight: 160)
            } else {
                ScrollView {
                    Text(DecoderModel.text(bytes, hex: hex))
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(minHeight: 60, maxHeight: 160)
            }
        }
        .padding(6)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
    }
}

// MARK: - Comparer (CMP-001…CMP-005)

/// State behind the Comparer.
@MainActor
@Observable
public final class ComparerModel {
    /// The items (from Send to Comparer, paste or files).
    public private(set) var items: [ComparerItem] = []
    /// Slot A.
    public var left: UUID? { didSet { recompute() } }
    /// Slot B.
    public var right: UUID? { didSet { recompute() } }
    /// Word or byte.
    public var granularity = DiffGranularity.word { didSet { recompute() } }
    /// Pre-diff transforms.
    public var options = DiffOptions() { didSet { recompute() } }
    /// The diff, once computed.
    public private(set) var result: DiffResult?
    /// A diff is being computed.
    public private(set) var computing = false
    /// The change shown by next/previous.
    public var currentChange = 0

    @ObservationIgnored let session: ProjectSession
    @ObservationIgnored private var watcher: Task<Void, Never>?
    @ObservationIgnored private var job: Task<Void, Never>?

    /// The Comparer for `session`.
    public init(session: ProjectSession) {
        self.session = session
        watcher = Task { [weak self] in
            guard let inbox = self?.session.inbox else { return }
            await self?.reload()
            for await tool in await inbox.opened() where tool == .comparer { await self?.reload() }
        }
    }

    func reload() async {
        items = await session.inbox.comparerItems
        // Newly added items fill the empty slots (the last two sent are compared).
        if left == nil || !items.contains(where: { $0.id == left }) {
            left = items.dropLast().last?.id ?? items.first?.id
        }
        if right == nil || !items.contains(where: { $0.id == right }) { right = items.last?.id }
    }

    /// Add pasted text.
    public func addPaste() {
        guard let text = NSPasteboard.general.string(forType: .string) else { return }
        let inbox = session.inbox
        Task {
            await inbox.addToComparer(ComparerItem(label: "Pasted", source: "paste", bytes: Array(text.utf8)))
            await reload()
        }
    }

    /// Add a file.
    public func addFile() {
        let panel = NSOpenPanel()
        guard panel.runModal() == .OK, let url = panel.url, let data = try? Data(contentsOf: url) else {
            return
        }
        let inbox = session.inbox
        Task {
            await inbox.addToComparer(
                ComparerItem(label: url.lastPathComponent, source: "file", bytes: [UInt8](data)))
            await reload()
        }
    }

    /// Remove items.
    public func remove(_ ids: Set<UUID>) {
        let inbox = session.inbox
        Task {
            await inbox.removeFromComparer(ids)
            await reload()
        }
    }

    func recompute() {
        job?.cancel()
        guard let a = items.first(where: { $0.id == left })?.bytes,
            let b = items.first(where: { $0.id == right })?.bytes
        else {
            result = nil
            return
        }
        computing = true
        let granularity = self.granularity
        let options = self.options
        // Off the main thread (CMP-004): large diffs must not freeze the UI.
        job = Task.detached(priority: .userInitiated) { [weak self] in
            let diff = Differ.diff(a, b, granularity: granularity, options: options)
            guard !Task.isCancelled else { return }
            await MainActor.run {
                self?.result = diff
                self?.computing = false
                self?.currentChange = 0
            }
        }
    }
}

/// The Comparer: items, A/B slots, the diff with toggles and navigation.
public struct ComparerView: View {
    @State private var model: ComparerModel
    @State private var selection: Set<UUID> = []

    /// The Comparer for `session`.
    public init(session: ProjectSession) {
        _model = State(initialValue: ComparerModel(session: session))
    }

    public var body: some View {
        HSplitView {
            VStack(alignment: .leading) {
                List(model.items, selection: $selection) { item in
                    VStack(alignment: .leading) {
                        Text(item.label)
                        Text("\(item.bytes.count) bytes · \(item.source)").font(.caption).foregroundStyle(
                            .secondary)
                    }
                }
                HStack {
                    Button("Paste") { model.addPaste() }
                    Button("Load…") { model.addFile() }
                    Button("Remove") { model.remove(selection) }.disabled(selection.isEmpty)
                }
                .padding(6)
            }
            .frame(minWidth: 200, idealWidth: 240)
            VStack(alignment: .leading, spacing: 6) {
                controls
                Divider()
                diffView
            }
            .padding(6)
            .frame(minWidth: 500)
        }
        .navigationTitle("Comparer")
    }

    private var controls: some View {
        HStack {
            Picker("A", selection: $model.left) {
                ForEach(model.items) { Text($0.label).tag(Optional($0.id)) }
            }
            .frame(maxWidth: 200)
            Picker("B", selection: $model.right) {
                ForEach(model.items) { Text($0.label).tag(Optional($0.id)) }
            }
            .frame(maxWidth: 200)
            Picker("", selection: $model.granularity) {
                Text("Words").tag(DiffGranularity.word)
                Text("Bytes").tag(DiffGranularity.byte)
            }
            .pickerStyle(.segmented)
            .frame(width: 140)
            Toggle("Ignore whitespace", isOn: $model.options.ignoreWhitespace)
            Toggle("Ignore case", isOn: $model.options.ignoreCase)
            Toggle("Pretty JSON", isOn: $model.options.prettyJSON)
        }
        .toggleStyle(.checkbox)
    }

    @ViewBuilder private var diffView: some View {
        if model.computing {
            ProgressView("Comparing…")
        } else if let result = model.result {
            let summary = result.summary
            HStack {
                Text(
                    result.identical
                        ? "Identical"
                        : "\(summary.modifications) modified · \(summary.added) added · \(summary.deleted) deleted"
                )
                Spacer()
                Button("Previous") { model.currentChange = max(0, model.currentChange - 1) }
                    .disabled(result.changes.isEmpty)
                Button("Next") {
                    model.currentChange = min(result.changes.count - 1, model.currentChange + 1)
                }
                .disabled(result.changes.isEmpty)
            }
            HSplitView {
                ScrollView {
                    Text(Self.render(result, side: .a)).textSelection(.enabled).frame(
                        maxWidth: .infinity, alignment: .leading)
                }
                ScrollView {
                    Text(Self.render(result, side: .b)).textSelection(.enabled).frame(
                        maxWidth: .infinity, alignment: .leading)
                }
            }
            .font(.system(.body, design: .monospaced))
        } else {
            ContentUnavailableView(
                "Nothing to compare", systemImage: "rectangle.split.2x1",
                description: Text(
                    "Send two requests or responses here from History (Send to Comparer), or paste."))
        }
    }

    enum Side { case a, b }

    /// One side with deletions (A) or insertions (B) highlighted; long equal runs are shortened.
    static func render(_ result: DiffResult, side: Side) -> AttributedString {
        var output = AttributedString()
        for segment in result.segments {
            let range = side == .a ? segment.a : segment.b
            guard !range.isEmpty else { continue }
            var bytes = Array((side == .a ? result.a : result.b)[range])
            if segment.operation == .equal, bytes.count > 4_000 {
                bytes =
                    Array(bytes.prefix(1_500)) + Array("\n  … \(bytes.count - 3_000) equal bytes …\n".utf8)
                    + Array(bytes.suffix(1_500))
            }
            var piece = AttributedString(String(decoding: bytes, as: UTF8.self))
            if segment.operation == .delete { piece.backgroundColor = .red.opacity(0.3) }
            if segment.operation == .insert { piece.backgroundColor = .green.opacity(0.3) }
            output += piece
        }
        return output
    }
}

// MARK: - JWT Workbench (ADV-010…ADV-013)

/// State behind the JWT Workbench.
@MainActor
@Observable
public final class JWTModel {
    /// The token text.
    public var token = "" { didSet { parse() } }
    /// Pretty header JSON (editable).
    public var header = ""
    /// Pretty claims JSON (editable).
    public var claims = ""
    /// Signing algorithm.
    public var algorithm = "HS256"
    /// HMAC secret, or PEM/JWK key text.
    public var keyText = ""
    /// The server's public key PEM (for RS→HS confusion).
    public var publicKeyPEM = ""
    /// Wordlist text for cracking (one per line).
    public var wordlist = ""
    /// Status line.
    public private(set) var status: String?
    /// Forged tokens from the attack helpers.
    public private(set) var forgeries: [JWTForgery] = []

    /// A workbench.
    public init() {}

    func parse() {
        guard let jwt = try? JWT(token) else {
            status = token.isEmpty ? nil : "Not a JWT."
            return
        }
        header = Self.pretty(jwt.headerJSON)
        claims = Self.pretty(jwt.payloadJSON)
        algorithm = jwt.algorithm.isEmpty ? algorithm : jwt.algorithm
        status = nil
    }

    static func pretty(_ bytes: [UInt8]) -> String {
        (try? Transforms.named("json-pretty")?.apply(bytes)).map { String(decoding: $0, as: UTF8.self) }
            ?? String(decoding: bytes, as: UTF8.self)
    }

    var key: JWTKey? {
        let text = keyText.trimmingCharacters(in: .whitespacesAndNewlines)
        if let pem = JWTKey.pem(text) { return pem }
        if let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
            let jwk = try? JWTKey.jwk(object)
        {
            return jwk
        }
        return text.isEmpty ? nil : .secret(Array(keyText.utf8))
    }

    /// The token rebuilt from the edited header and claims (unsigned).
    func edited() throws -> JWT {
        func segment(_ text: String) throws -> String {
            guard (try? JSONSerialization.jsonObject(with: Data(text.utf8))) != nil else {
                throw CodecError("not valid JSON")
            }
            let minified = try Transforms.require("json-minify").apply(Array(text.utf8))
            return String(decoding: try Transforms.require("base64url").apply(minified), as: UTF8.self)
        }
        return JWT(
            headerSegment: try segment(header), payloadSegment: try segment(claims), signatureSegment: "")
    }

    /// Re-sign with the key (ADV-010).
    public func sign() {
        do {
            guard let key else { throw CodecError("enter a secret or a PEM/JWK key") }
            token = try edited().signed(algorithm, key: key).compact
            status = "Signed with \(algorithm)."
        } catch {
            status = "Sign failed: \(error)"
        }
    }

    /// Verify with the key (ADV-012).
    public func verify() {
        guard let jwt = try? JWT(token), let key else {
            status = "Enter a token and a key."
            return
        }
        status =
            jwt.verifies(with: key)
            ? "Signature valid (\(jwt.algorithm))." : "Signature INVALID (\(jwt.algorithm))."
    }

    /// Run an attack helper (ADV-011).
    public func forge(_ attack: String) {
        do {
            let jwt = try edited()
            switch attack {
            case "none": forgeries = try JWTAttacks.algNone(jwt)
            case "confusion": forgeries = try JWTAttacks.keyConfusion(jwt, publicKeyPEM: publicKeyPEM)
            case "kid": forgeries = [try JWTAttacks.kidInjection(jwt)]
            default: forgeries = try JWTAttacks.timeClaims(jwt)
            }
            status = "\(forgeries.count) token(s). Sending them is scope-gated like any request."
        } catch {
            status = "Failed: \(error)"
        }
    }

    /// Brute-force the HMAC secret (ADV-011).
    public func crack() {
        guard let jwt = try? JWT(token) else { return }
        let words = wordlist.split(whereSeparator: \.isNewline).map(String.init).filter { !$0.hasPrefix("#") }
        if let secret = JWTAttacks.crack(jwt, wordlist: words) {
            keyText = secret
            status = "Secret found: \(secret)"
        } else {
            status = "Not found in \(words.count) candidates."
        }
    }

    /// Generate a key for the algorithm.
    public func generateKey() {
        guard let key = try? JWTKey.generate(for: algorithm) else { return }
        switch key {
        case .secret(let bytes): keyText = bytes.map { String(format: "%02x", $0) }.joined()
        default: keyText = key.privatePEM ?? ""
        }
    }
}

/// The JWT Workbench.
public struct JWTWorkbenchView: View {
    @State private var model = JWTModel()

    /// A workbench.
    public init() {}

    public var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 6) {
                Text("Token").font(.headline)
                TextEditor(text: $model.token).font(.system(.body, design: .monospaced)).frame(minHeight: 80)
                Text("Header").font(.headline)
                TextEditor(text: $model.header).font(.system(.body, design: .monospaced)).frame(minHeight: 80)
                Text("Claims").font(.headline)
                TextEditor(text: $model.claims).font(.system(.body, design: .monospaced)).frame(
                    minHeight: 120)
            }
            .padding(6)
            .frame(minWidth: 360)
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Picker("Algorithm", selection: $model.algorithm) {
                        ForEach(
                            [
                                "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS512",
                                "ES256", "ES384", "ES512",
                            ], id: \.self
                        ) {
                            Text($0)
                        }
                    }
                    .frame(maxWidth: 200)
                    Button("Generate Key") { model.generateKey() }
                }
                Text("Secret, or PEM / JWK key").font(.caption)
                TextEditor(text: $model.keyText).font(.system(.caption, design: .monospaced)).frame(
                    minHeight: 70)
                HStack {
                    Button("Sign") { model.sign() }
                    Button("Verify") { model.verify() }
                }
                Divider()
                Text("Attacks (clearly labelled; sends are scope-gated)").font(.headline)
                HStack {
                    Button("alg:none") { model.forge("none") }
                    Button("kid → /dev/null") { model.forge("kid") }
                    Button("exp / nbf") { model.forge("times") }
                }
                Text("Server public key PEM (RS→HS confusion)").font(.caption)
                TextEditor(text: $model.publicKeyPEM).font(.system(.caption, design: .monospaced)).frame(
                    minHeight: 50)
                Button("RS→HS Confusion") { model.forge("confusion") }
                Text("Wordlist (weak HMAC secret)").font(.caption)
                TextEditor(text: $model.wordlist).font(.system(.caption, design: .monospaced)).frame(
                    minHeight: 50)
                Button("Crack Secret") { model.crack() }
                if let status = model.status { Text(status).font(.callout) }
                List(model.forgeries, id: \.token) { forgery in
                    VStack(alignment: .leading) {
                        Text(forgery.label).bold()
                        Text(forgery.token).font(.system(.caption, design: .monospaced)).textSelection(
                            .enabled
                        ).lineLimit(2)
                    }
                    .contextMenu {
                        Button("Copy Token") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(forgery.token, forType: .string)
                        }
                    }
                }
                .frame(minHeight: 120)
            }
            .padding(6)
            .frame(minWidth: 360)
        }
        .navigationTitle("JWT Workbench")
    }
}
#endif
