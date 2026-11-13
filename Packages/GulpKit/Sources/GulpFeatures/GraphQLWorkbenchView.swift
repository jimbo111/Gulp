// GulpFeatures — the GraphQL workbench screen (F23 §5, M13b). The introspection parsing, SDL render and
// request building live in GulpCodec.GraphQL and are tested on Linux; this file drives them: paste an
// introspection result, read the rendered schema, and browse the queries and mutations (the attack
// surface) with their field types.

#if canImport(AppKit)
import AppKit
import GulpCodec
import Observation
import SwiftUI

/// A GraphQL field row for a list.
struct GraphQLFieldRow: Identifiable {
    let id: Int
    let field: GraphQLField
}

/// State behind the GraphQL workbench.
@MainActor
@Observable
public final class GraphQLWorkbenchModel {
    /// The introspection JSON (the `{ "data": { "__schema": … } }` result).
    public var introspection: String = ""
    /// The parsed schema, if valid.
    public private(set) var schema: GraphQLSchema?
    /// Why parsing failed, if it did.
    public private(set) var error: String?

    /// A model.
    public init() {}

    /// Parse the pasted introspection result.
    public func parse() {
        guard !introspection.isEmpty else {
            schema = nil
            error = nil
            return
        }
        if let parsed = GraphQLSchema.parse(introspection: Data(introspection.utf8)) {
            schema = parsed
            error = nil
        } else {
            schema = nil
            error = "Not a valid introspection result (expected data.__schema)."
        }
    }

    func rows(_ fields: [GraphQLField]) -> [GraphQLFieldRow] {
        fields.enumerated().map { GraphQLFieldRow(id: $0.offset, field: $0.element) }
    }
}

/// The GraphQL workbench: introspect, render the schema, and browse queries and mutations.
public struct GraphQLWorkbenchView: View {
    @State private var model = GraphQLWorkbenchModel()

    /// A workbench.
    public init() {}

    public var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 6) {
                Text("Introspection result (JSON)").font(.headline)
                TextEditor(text: $model.introspection).font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 260)
                Button("Parse schema") { model.parse() }.keyboardShortcut(.return, modifiers: .command)
                if let error = model.error {
                    Label(error, systemImage: "exclamationmark.triangle").font(.caption)
                        .foregroundStyle(.red)
                }
            }
            .padding(6)
            .frame(minWidth: 340)

            VStack(alignment: .leading, spacing: 8) {
                if let schema = model.schema {
                    Text("Queries (\(schema.queries.count))").font(.headline)
                    Table(model.rows(schema.queries)) {
                        TableColumn("Field") { Text($0.field.name) }
                        TableColumn("Type") { Text($0.field.type) }
                        TableColumn("Args") { Text("\($0.field.args.count)") }.width(50)
                    }
                    .frame(minHeight: 140)
                    Text("Mutations (\(schema.mutations.count))").font(.headline)
                    Table(model.rows(schema.mutations)) {
                        TableColumn("Field") { Text($0.field.name) }
                        TableColumn("Type") { Text($0.field.type) }
                        TableColumn("Args") { Text("\($0.field.args.count)") }.width(50)
                    }
                    .frame(minHeight: 140)
                    DisclosureGroup("Rendered schema (SDL)") {
                        ScrollView {
                            Text(schema.render()).font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(minHeight: 160)
                    }
                } else {
                    ContentUnavailableView(
                        "No schema yet", systemImage: "point.3.connected.trianglepath.dotted",
                        description: Text("Paste an introspection result and press Parse schema (⌘↵)."))
                }
            }
            .padding(6)
            .frame(minWidth: 360)
        }
        .navigationTitle("GraphQL")
    }
}
#endif
