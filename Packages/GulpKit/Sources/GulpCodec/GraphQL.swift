// GulpCodec — GraphQL support (F23 §5, M13b): detect GraphQL requests, the standard introspection
// query, a parser from an introspection JSON response into a schema model, a text renderer of that
// schema, and helpers to read a GraphQL request's operation name and variables (for the Scanner's
// insertion points, ADV-043). Pure Swift (no schema library), so it builds and tests on Linux; the
// macOS Workbench renders the same model.

import Foundation
import GulpCore

/// A GraphQL request body: the query/mutation text, an optional operation name, and variables.
public struct GraphQLRequest: Sendable, Hashable {
    /// The query/mutation/subscription document.
    public var query: String
    /// The chosen operation name, if the document has several.
    public var operationName: String?
    /// The variables object, as raw JSON text (so values stay exact for insertion points).
    public var variablesJSON: String?

    /// A request.
    public init(query: String, operationName: String? = nil, variablesJSON: String? = nil) {
        self.query = query
        self.operationName = operationName
        self.variablesJSON = variablesJSON
    }
}

/// GraphQL request/response helpers.
public enum GraphQL {
    /// The introspection query (a compact form of the standard one; enough to render the schema).
    public static let introspectionQuery = """
        query IntrospectionQuery { __schema { queryType { name } mutationType { name } \
        types { kind name description fields(includeDeprecated: true) { name description \
        args { name type { ...TypeRef } } type { ...TypeRef } } inputFields { name type { ...TypeRef } } \
        enumValues(includeDeprecated: true) { name } } } } \
        fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
        """

    /// Whether a request looks like GraphQL: a POST to a graphql-ish path, or a JSON body with a
    /// `query` string (ADV-040).
    public static func isGraphQL(request: RawRequest) -> Bool {
        let target = request.bytes[request.parsed.target].string().lowercased()
        let path = target.split(separator: "?").first.map(String.init) ?? target
        if path.hasSuffix("/graphql") || path.hasSuffix("/graphql/") || path.contains("/graphql") {
            return true
        }
        guard request.headerValue("content-type")?.string().lowercased().contains("json") == true else {
            return false
        }
        return parse(request: request) != nil
    }

    /// Parse a GraphQL request body (`{"query":"…","variables":{…},"operationName":"…"}`).
    public static func parse(request: RawRequest) -> GraphQLRequest? {
        let body = Data(request.bytes.rawBytes[request.parsed.body])
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
            let query = root["query"] as? String
        else { return nil }
        var variablesJSON: String?
        if let variables = root["variables"], JSONSerialization.isValidJSONObject(variables),
            let data = try? JSONSerialization.data(withJSONObject: variables)
        {
            variablesJSON = String(decoding: data, as: UTF8.self)
        }
        return GraphQLRequest(
            query: query, operationName: root["operationName"] as? String, variablesJSON: variablesJSON)
    }

    /// Build a request body for a GraphQL query (ADV-041).
    public static func body(_ request: GraphQLRequest) -> [UInt8] {
        var object: [String: Any] = ["query": request.query]
        if let operationName = request.operationName { object["operationName"] = operationName }
        if let variablesJSON = request.variablesJSON,
            let variables = try? JSONSerialization.jsonObject(with: Data(variablesJSON.utf8))
        {
            object["variables"] = variables
        }
        return (try? Array(JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))) ?? []
    }

    /// Whether a GraphQL response is an "introspection disabled" error (ADV-040).
    public static func introspectionDisabled(_ response: RawResponse) -> Bool {
        let body = String(decoding: response.bytes.rawBytes[response.parsed.body], as: UTF8.self).lowercased()
        return body.contains("introspection") && (body.contains("disabled") || body.contains("not allowed"))
            || body.contains("__schema") && body.contains("error")
    }
}

/// A parsed GraphQL schema (from introspection).
public struct GraphQLSchema: Sendable, Hashable {
    /// The root query type name.
    public var queryType: String?
    /// The root mutation type name.
    public var mutationType: String?
    /// Types by name (user types; built-in scalars and `__*` introspection types are kept too).
    public var types: [GraphQLType]

    /// A type by name.
    public func type(_ name: String) -> GraphQLType? { types.first { $0.name == name } }

    /// The query root's fields (the available top-level queries).
    public var queries: [GraphQLField] { queryType.flatMap { type($0)?.fields } ?? [] }
    /// The mutation root's fields.
    public var mutations: [GraphQLField] { mutationType.flatMap { type($0)?.fields } ?? [] }

    /// Parse an introspection response's JSON (`{"data":{"__schema":{…}}}`), or nil.
    public static func parse(introspection data: Data) -> GraphQLSchema? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let dataObject = root["data"] as? [String: Any],
            let schema = dataObject["__schema"] as? [String: Any]
        else { return nil }
        let queryType = (schema["queryType"] as? [String: Any])?["name"] as? String
        let mutationType = (schema["mutationType"] as? [String: Any])?["name"] as? String
        let types = (schema["types"] as? [[String: Any]] ?? []).map(GraphQLType.init)
        return GraphQLSchema(queryType: queryType, mutationType: mutationType, types: types)
    }

    /// A readable rendering (the text the macOS Workbench shows; ADV-040).
    public func render() -> String {
        var lines: [String] = []
        func describe(_ field: GraphQLField) -> String {
            let args =
                field.args.isEmpty
                ? "" : "(" + field.args.map { "\($0.name): \($0.type)" }.joined(separator: ", ") + ")"
            return "  \(field.name)\(args): \(field.type)"
        }
        if let queryType {
            lines.append("type \(queryType) {  # queries"); lines += queries.map(describe); lines.append("}")
        }
        if let mutationType {
            lines.append("type \(mutationType) {  # mutations"); lines += mutations.map(describe);
            lines.append("}")
        }
        for type in types.sorted(by: { $0.name < $1.name })
        where !type.name.hasPrefix("__") && type.name != queryType && type.name != mutationType
            && !type.fields.isEmpty
        {
            lines.append("type \(type.name) {")
            lines += type.fields.map { "  \($0.name): \($0.type)" }
            lines.append("}")
        }
        return lines.joined(separator: "\n")
    }
}

/// A GraphQL type (OBJECT, SCALAR, ENUM, INPUT_OBJECT…).
public struct GraphQLType: Sendable, Hashable {
    /// Kind (OBJECT, SCALAR, …).
    public var kind: String
    /// Name.
    public var name: String
    /// Object/interface fields.
    public var fields: [GraphQLField]

    init(_ object: [String: Any]) {
        kind = object["kind"] as? String ?? ""
        name = object["name"] as? String ?? ""
        fields = (object["fields"] as? [[String: Any]] ?? []).map(GraphQLField.init)
    }
}

/// A GraphQL field with its args and result type.
public struct GraphQLField: Sendable, Hashable {
    /// Name.
    public var name: String
    /// The result type, as a readable string (`User!`, `[Order!]`).
    public var type: String
    /// Arguments.
    public var args: [GraphQLArg]

    init(_ object: [String: Any]) {
        name = object["name"] as? String ?? ""
        type = GraphQLField.typeRef(object["type"] as? [String: Any])
        args = (object["args"] as? [[String: Any]] ?? []).map(GraphQLArg.init)
    }

    /// Flatten a `TypeRef` (NON_NULL/LIST wrappers) into a readable string.
    static func typeRef(_ ref: [String: Any]?) -> String {
        guard let ref else { return "Unknown" }
        let kind = ref["kind"] as? String ?? ""
        let ofType = ref["ofType"] as? [String: Any]
        switch kind {
        case "NON_NULL": return typeRef(ofType) + "!"
        case "LIST": return "[" + typeRef(ofType) + "]"
        default: return ref["name"] as? String ?? "Unknown"
        }
    }
}

/// A GraphQL field/argument name and type.
public struct GraphQLArg: Sendable, Hashable {
    /// Name.
    public var name: String
    /// Type string.
    public var type: String

    init(_ object: [String: Any]) {
        name = object["name"] as? String ?? ""
        type = GraphQLField.typeRef(object["type"] as? [String: Any])
    }
}
