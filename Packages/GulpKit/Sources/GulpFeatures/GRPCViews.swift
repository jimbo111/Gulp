// GulpFeatures — gRPC views (F33 §3): the Protobuf panel for RPC exchanges (message list, decoded
// field tree or JSON, trailers and status) and Project → gRPC Schemas… (import `.proto` or a
// descriptor set, fetch via reflection, remove). Decoding never changes the stored bytes.

#if canImport(AppKit)
import AppKit
import GulpCodec
import GulpCore
import GulpWorkspace
import SwiftUI
import UniformTypeIdentifiers

/// The project's merged protobuf schemas, for naming fields in RPC views (empty: schema-less).
private struct GRPCSchemaKey: EnvironmentKey {
    static let defaultValue = ProtoSchemaSet()
}

extension EnvironmentValues {
    /// Schemas used to name protobuf fields (F33 GRP-003).
    public var grpcSchema: ProtoSchemaSet {
        get { self[GRPCSchemaKey.self] }
        set { self[GRPCSchemaKey.self] = newValue }
    }
}

/// Hands a project's schemas to the RPC views below it, reloaded whenever `revision` changes.
struct GRPCSchemaProvider: ViewModifier {
    let session: ProjectSession
    let revision: Int
    @State private var schema = ProtoSchemaSet()

    func body(content: Content) -> some View {
        content
            .environment(\.grpcSchema, schema)
            .task(id: revision) { schema = session.grpcSchemaSet() }
    }
}

extension View {
    /// Name protobuf fields in RPC views with `session`'s schemas; bump `revision` after a change.
    public func grpcSchemas(from session: ProjectSession, revision: Int) -> some View {
        modifier(GRPCSchemaProvider(session: session, revision: revision))
    }
}

/// An exchange decoded as an RPC call (F33 GRP-001…003): pick a message, read it as a field tree or
/// JSON; trailers, status and warnings below.
public struct RPCCallView: View {
    let exchange: Exchange
    @Environment(\.grpcSchema) private var schema
    @State private var selection = 0
    @State private var asJSON = false

    /// A view of `exchange` (show it only when `RPCCallView.isRPC(exchange)`).
    public init(exchange: Exchange) { self.exchange = exchange }

    /// Whether `exchange` is a gRPC, gRPC-Web or Connect call.
    public static func isRPC(_ exchange: Exchange) -> Bool { RPC.detect(exchange.request) != nil }

    struct Entry: Identifiable {
        let id: Int
        let title: String
        let text: String
        let json: String?
    }

    /// The screen.
    public var body: some View {
        if let call = RPC.parse(request: exchange.request, response: exchange.response) {
            let detail = RPCCallDetail(call: call, schema: schema)
            let entries = Self.entries(detail)
            VStack(alignment: .leading, spacing: 6) {
                header(detail)
                HStack {
                    Picker("Message", selection: $selection) {
                        ForEach(entries) { Text($0.title).tag($0.id) }
                    }
                    .frame(maxWidth: 360)
                    Toggle("JSON", isOn: $asJSON)
                        .disabled(detail.inputType == nil)
                        .help(
                            detail.inputType == nil
                                ? "Import a schema to view messages as JSON" : "View as JSON")
                }
                let entry = entries.first { $0.id == selection } ?? entries.first
                ScrollView {
                    Text(entry.map { asJSON ? ($0.json ?? $0.text) : $0.text } ?? "(no messages)")
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                        .padding(6)
                }
                .background(Color(nsColor: .textBackgroundColor))
                if !call.trailers.isEmpty {
                    Text(call.trailers.map { "\($0.name): \($0.value)" }.joined(separator: "\n"))
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
                ForEach(call.warnings, id: \.self) { warning in
                    Label(warning, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                }
            }
            .padding(8)
        } else {
            Text("Not an RPC call").foregroundStyle(.secondary)
        }
    }

    @ViewBuilder func header(_ detail: RPCCallDetail) -> some View {
        let call = detail.call
        HStack {
            Text(call.rpcProtocol.label).bold()
            Text(call.path).font(.system(.body, design: .monospaced))
            Spacer()
            if let status = call.status {
                Text("\(status) \(call.statusName ?? "")")
                    .foregroundStyle(status == 0 ? Color.green : Color.red)
                    .help(call.statusMessage ?? "")
            } else {
                Text("no gRPC status").foregroundStyle(.orange)
            }
        }
    }

    static func entries(_ detail: RPCCallDetail) -> [Entry] {
        let call = detail.call
        var entries: [Entry] = []
        for (index, message) in call.requests.enumerated() {
            entries.append(
                Entry(
                    id: entries.count,
                    title:
                        "Request \(index + 1) · \(message.framed.count) bytes\(message.compressed ? " (compressed)" : "")",
                    text: detail.requestTexts[index],
                    json: index < detail.requestJSON.count ? detail.requestJSON[index] : nil))
        }
        for (index, message) in call.responses.enumerated() {
            entries.append(
                Entry(
                    id: entries.count,
                    title:
                        "Response \(index + 1) · \(message.framed.count) bytes\(message.compressed ? " (compressed)" : "")",
                    text: detail.responseTexts[index],
                    json: index < detail.responseJSON.count ? detail.responseJSON[index] : nil))
        }
        return entries
    }
}

/// Project → gRPC Schemas… (F33 §3): imported schemas with their services; import a `.proto` or a
/// descriptor set; fetch from the server's reflection service (scope-gated).
public struct GRPCSchemasView: View {
    let session: ProjectSession
    /// Called after a change so the window can refresh the schemas it hands to RPC views.
    var onChange: @MainActor () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var schemas: [GRPCSchemaSettings.Schema] = []
    @State private var target = "https://"
    @State private var busy = false
    @State private var message: String?
    @State private var confirmOutOfScope = false

    /// The sheet for `session`.
    public init(session: ProjectSession, onChange: @escaping @MainActor () -> Void = {}) {
        self.session = session
        self.onChange = onChange
    }

    /// The screen.
    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("gRPC Schemas").font(.title2)
            List(schemas) { schema in
                HStack(alignment: .top) {
                    VStack(alignment: .leading) {
                        Text(schema.source).bold()
                        Text(schema.services.joined(separator: ", ")).font(.caption).foregroundStyle(
                            .secondary)
                    }
                    Spacer()
                    Button(role: .destructive) {
                        let session = self.session
                        let id = schema.id
                        run { try await session.removeGRPCSchema(id) }
                    } label: {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                    .help("Remove this schema")
                }
            }
            .frame(minHeight: 160)
            HStack {
                Button("Import .proto…") { importFile(proto: true) }
                Button("Import Descriptor Set…") { importFile(proto: false) }
            }
            HStack {
                TextField("Server, e.g. https://localhost:8443", text: $target)
                Button("Fetch via Reflection") { fetch(allowOutOfScope: false) }
                    .disabled(HTTPTarget(url: target) == nil)
            }
            if busy { ProgressView().controlSize(.small) }
            if let message { Text(message).font(.caption).foregroundStyle(.secondary) }
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(minWidth: 520, minHeight: 360)
        .task { schemas = session.grpcSchemas() }
        .alert("Target is out of scope. Send anyway?", isPresented: $confirmOutOfScope) {
            Button("Send Anyway") { fetch(allowOutOfScope: true) }
            Button("Cancel", role: .cancel) {}
        }
    }

    func run(_ action: @escaping @Sendable () async throws -> Void) {
        busy = true
        message = nil
        Task {
            do {
                try await action()
                schemas = session.grpcSchemas()
                onChange()
            } catch let error as RPCServiceError {
                if error.outOfScope { confirmOutOfScope = true } else { message = error.message }
            } catch {
                message = "\(error)"
            }
            busy = false
        }
    }

    func fetch(allowOutOfScope: Bool) {
        guard let destination = HTTPTarget(url: target) else { return }
        let session = self.session
        run { _ = try await session.fetchGRPCSchema(from: destination, allowOutOfScope: allowOutOfScope) }
    }

    func importFile(proto: Bool) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.message =
            proto ? "Choose a .proto file (imports resolve next to it)" : "Choose a FileDescriptorSet"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let session = self.session
        run {
            if proto {
                _ = try await session.importProto(at: url)
            } else {
                _ = try await session.importDescriptorSet(at: url)
            }
        }
    }
}
#endif
