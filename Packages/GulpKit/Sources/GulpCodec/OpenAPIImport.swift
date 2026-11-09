// GulpCodec — OpenAPI 3.x / Swagger 2.0 import (F23 ADV-050) with schema-aware values (ADV-052):
// one request per operation, with path, query, header and cookie parameters filled in and a body
// built from the request schema, plus the auth the operation declares (as an obvious placeholder).
// JSON documents only (no YAML parser in the dependency set; see doc 07).
//
// Values, in order of preference: the parameter's or schema's `example` / first of `examples`, its
// `default`, the first `enum` value, then one generated from `type`/`format` (date-time, date,
// email, uuid, uri, ipv4/ipv6, byte, password; integers honour `minimum`, strings `minLength`).
// `$ref`s are followed (local JSON pointers), `allOf` merged, `oneOf`/`anyOf` use their first
// choice; recursion stops at depth 8.

import Foundation
import GulpCore

/// Builds requests from an OpenAPI/Swagger document.
public enum OpenAPIImport {
    /// The placeholder put where a credential goes.
    public static let credentialPlaceholder = "REPLACE_ME"

    static let methods = ["get", "put", "post", "delete", "options", "head", "patch", "trace"]

    /// Requests for every operation in `data`. `baseURL` (where the document came from) is used
    /// when the document names no server, or a relative one.
    public static func read(_ data: Data, baseURL: String? = nil) throws -> ImportBatch {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw TrafficImportError(
                "Not an OpenAPI/Swagger JSON document (YAML is not supported; convert it to JSON).")
        }
        guard root["openapi"] != nil || root["swagger"] != nil else {
            throw TrafficImportError("Not an OpenAPI/Swagger document: no \"openapi\" or \"swagger\" field.")
        }
        let document = Document(root: root)
        guard let server = document.serverURL(baseURL: baseURL) else {
            throw TrafficImportError(
                "The document names no absolute server URL; give the URL it came from (--base-url).")
        }
        var batch = ImportBatch(format: .openAPI)
        let paths = root["paths"] as? [String: Any] ?? [:]
        for path in paths.keys.sorted() {
            guard let item = document.resolve(paths[path]) as? [String: Any] else { continue }
            let shared = item["parameters"] as? [Any] ?? []
            for method in methods {
                guard let operation = document.resolve(item[method]) as? [String: Any] else { continue }
                let label = "\(method.uppercased()) \(path)"
                do {
                    batch.exchanges.append(
                        try document.request(
                            method: method, path: path, operation: operation, shared: shared, server: server))
                } catch let error as TrafficImportError {
                    batch.skipped.append(ImportSkip(item: label, reason: error.message))
                } catch {
                    batch.skipped.append(ImportSkip(item: label, reason: "\(error)"))
                }
            }
        }
        return batch
    }

    /// A parsed document.
    struct Document {
        let root: [String: Any]
        var isSwagger2: Bool { root["swagger"] != nil }

        /// Follow a local `$ref` (`#/a/b`) until there is none (bounded).
        func resolve(_ value: Any?, depth: Int = 0) -> Any? {
            guard depth < 16, let object = value as? [String: Any], let ref = object["$ref"] as? String else {
                return value
            }
            guard ref.hasPrefix("#/") else { return nil }
            var node: Any? = root
            for part in ref.dropFirst(2).split(separator: "/") {
                let key = part.replacingOccurrences(of: "~1", with: "/").replacingOccurrences(
                    of: "~0", with: "~")
                node = (node as? [String: Any])?[key]
            }
            return resolve(node, depth: depth + 1)
        }

        /// The absolute server URL (without a trailing `/`).
        func serverURL(baseURL: String?) -> String? {
            let origin = baseURL.flatMap(Self.origin)
            var server: String?
            if isSwagger2 {
                if let host = root["host"] as? String {
                    let scheme =
                        (root["schemes"] as? [String])?.first
                        ?? (baseURL?.hasPrefix("http://") == true ? "http" : "https")
                    server = "\(scheme)://\(host)\(root["basePath"] as? String ?? "")"
                } else if let origin {
                    server = origin + (root["basePath"] as? String ?? "")
                }
            } else if let first = (root["servers"] as? [[String: Any]])?.first,
                var url = first["url"] as? String
            {
                for (name, spec) in first["variables"] as? [String: [String: Any]] ?? [:] {
                    url = url.replacingOccurrences(
                        of: "{\(name)}", with: spec["default"].map { "\($0)" } ?? "")
                }
                if url.hasPrefix("http://") || url.hasPrefix("https://") {
                    server = url
                } else if let origin {
                    server = origin + (url.hasPrefix("/") ? url : "/" + url)
                }
            } else {
                server = origin
            }
            guard var result = server, HTTPTarget(url: result) != nil else { return nil }
            while result.hasSuffix("/") { result.removeLast() }
            return result
        }

        /// `scheme://host[:port]` of a URL.
        static func origin(_ url: String) -> String? {
            guard let schemeEnd = url.range(of: "://") else { return nil }
            let rest = url[schemeEnd.upperBound...]
            let end = rest.firstIndex { $0 == "/" || $0 == "?" || $0 == "#" } ?? rest.endIndex
            return String(url[..<end])
        }

        func request(method: String, path: String, operation: [String: Any], shared: [Any], server: String)
            throws
            -> ImportedExchange
        {
            // Operation parameters override path-level ones with the same name and location.
            var parameters: [[String: Any]] = []
            for raw in shared + (operation["parameters"] as? [Any] ?? []) {
                guard let parameter = resolve(raw) as? [String: Any], let name = parameter["name"] as? String
                else {
                    continue
                }
                let location = parameter["in"] as? String ?? ""
                parameters.removeAll { $0["name"] as? String == name && $0["in"] as? String == location }
                parameters.append(parameter)
            }
            var resolvedPath = path
            var query: [String] = []
            var headers: [(String, String)] = []
            var cookies: [String] = []
            var form: [String] = []
            var body: [UInt8] = []
            var contentType: String?
            for parameter in parameters {
                let name = parameter["name"] as? String ?? ""
                let value = parameterValue(parameter)
                switch parameter["in"] as? String {
                case "path":
                    resolvedPath = resolvedPath.replacingOccurrences(
                        of: "{\(name)}", with: Self.encode(value))
                case "query": query.append("\(Self.encode(name))=\(Self.encode(value))")
                case "header": headers.append((name, value))
                case "cookie": cookies.append("\(name)=\(value)")
                case "formData": form.append("\(Self.encode(name))=\(Self.encode(value))")
                case "body":
                    let schema = resolve(parameter["schema"]) as? [String: Any] ?? [:]
                    body = Self.json(SchemaValues(document: self).value(for: schema))
                    contentType = "application/json"
                default: break
                }
            }
            if !form.isEmpty {
                body = Array(form.joined(separator: "&").utf8)
                contentType = "application/x-www-form-urlencoded"
            }
            if let requestBody = resolve(operation["requestBody"]) as? [String: Any],
                let content = requestBody["content"] as? [String: Any]
            {
                let preferred = ["application/json", "application/x-www-form-urlencoded", "text/plain"]
                let type =
                    preferred.first { content[$0] != nil } ?? content.keys.sorted().first {
                        $0.contains("json")
                    }
                    ?? content.keys.sorted().first
                if let type, let media = content[type] as? [String: Any] {
                    contentType = type
                    let example =
                        media["example"]
                        ?? (media["examples"] as? [String: Any]).flatMap { examples in
                            examples.keys.sorted().first.flatMap {
                                (resolve(examples[$0]) as? [String: Any])?["value"]
                            }
                        }
                    let schema = resolve(media["schema"]) as? [String: Any] ?? [:]
                    let value = example ?? SchemaValues(document: self).value(for: schema)
                    if type.contains("x-www-form-urlencoded"), let object = value as? [String: Any] {
                        body = Array(
                            object.keys.sorted().map {
                                "\(Self.encode($0))=\(Self.encode(Self.text(object[$0])))"
                            }
                            .joined(separator: "&").utf8)
                    } else if type.contains("json") {
                        body = Self.json(value)
                    } else {
                        body = Array(Self.text(value).utf8)
                    }
                }
            }
            if let contentType, !body.isEmpty { headers.append(("Content-Type", contentType)) }
            for (name, value, location) in security(operation) {
                switch location {
                case "query": query.append("\(Self.encode(name))=\(Self.encode(value))")
                case "cookie": cookies.append("\(name)=\(value)")
                default: headers.append((name, value))
                }
            }
            if !cookies.isEmpty { headers.append(("Cookie", cookies.joined(separator: "; "))) }
            let url = server + resolvedPath + (query.isEmpty ? "" : "?" + query.joined(separator: "&"))
            guard let target = HTTPTarget(url: url) else { throw TrafficImportError("bad URL \(url)") }
            let summary = [operation["operationId"] as? String, operation["summary"] as? String].compactMap {
                $0
            }
            return ImportedExchange(
                target: target,
                request: Wire.build(
                    method: method.uppercased(), url: url, target: target, headers: headers, body: body),
                comment: summary.isEmpty ? nil : summary.joined(separator: " — "))
        }

        func parameterValue(_ parameter: [String: Any]) -> String {
            if let example = parameter["example"] { return Self.text(example) }
            if let examples = parameter["examples"] as? [String: Any],
                let first = examples.keys.sorted().first,
                let value = (resolve(examples[first]) as? [String: Any])?["value"]
            {
                return Self.text(value)
            }
            // Swagger 2.0 puts type/format/enum on the parameter itself.
            let schema = resolve(parameter["schema"]) as? [String: Any] ?? parameter
            return Self.text(SchemaValues(document: self).value(for: schema))
        }

        /// The credentials the operation (or the document) requires: (name, value, location).
        func security(_ operation: [String: Any]) -> [(String, String, String)] {
            let requirements = (operation["security"] ?? root["security"]) as? [[String: Any]] ?? []
            guard let first = requirements.first else { return [] }
            let schemes =
                isSwagger2
                ? root["securityDefinitions"] as? [String: Any]
                : (root["components"] as? [String: Any])?["securitySchemes"] as? [String: Any]
            var result: [(String, String, String)] = []
            for name in first.keys.sorted() {
                guard let scheme = resolve(schemes?[name]) as? [String: Any] else { continue }
                let placeholder = OpenAPIImport.credentialPlaceholder
                switch (scheme["type"] as? String ?? "").lowercased() {
                case "apikey":
                    result.append(
                        (scheme["name"] as? String ?? name, placeholder, scheme["in"] as? String ?? "header"))
                case "http" where (scheme["scheme"] as? String)?.lowercased() == "basic", "basic":
                    result.append(
                        (
                            "Authorization",
                            "Basic " + Data("user:\(placeholder)".utf8).base64EncodedString(), "header"
                        ))
                default:  // http bearer, oauth2, openIdConnect
                    result.append(("Authorization", "Bearer \(placeholder)", "header"))
                }
            }
            return result
        }

        static func encode(_ text: String) -> String {
            // RFC 3986 unreserved characters only (form and path values).
            let allowed = CharacterSet(
                charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
            return text.addingPercentEncoding(withAllowedCharacters: allowed) ?? text
        }

        static func text(_ value: Any?) -> String {
            switch value {
            case let string as String: return string
            case let bool as Bool where isBoolean(value):
                return bool ? "true" : "false"
            case let number as NSNumber:
                return number.stringValue
            case nil: return ""
            case let other?:
                if JSONSerialization.isValidJSONObject(other) {
                    return String(decoding: json(other), as: UTF8.self)
                }
                return "\(other)"
            }
        }

        /// Whether a JSON value is a boolean (JSONSerialization hands numbers and booleans back as
        /// NSNumber, and `as? Bool` also accepts 0 and 1).
        static func isBoolean(_ value: Any?) -> Bool {
            guard let number = value as? NSNumber else { return value is Bool }
            #if canImport(Darwin)
            return CFGetTypeID(number) == CFBooleanGetTypeID()
            #else
            return String(cString: number.objCType) == "c" || type(of: value!) == Bool.self
            #endif
        }

        static func json(_ value: Any?) -> [UInt8] {
            guard let value else { return Array("null".utf8) }
            if JSONSerialization.isValidJSONObject(value),
                let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
            {
                return [UInt8](data)
            }
            let wrapped = try? JSONSerialization.data(withJSONObject: [value], options: [.fragmentsAllowed])
            return wrapped.map { Array($0.dropFirst().dropLast()) } ?? Array("null".utf8)
        }
    }
}

/// Plausible, well-typed values for a JSON schema (ADV-052).
public struct SchemaValues {
    let document: OpenAPIImport.Document?

    init(document: OpenAPIImport.Document?) {
        self.document = document
    }

    /// Values for schemas without a document (no `$ref`s).
    public init() {
        document = nil
    }

    /// A value for `schema`.
    public func value(for schema: [String: Any]) -> Any {
        value(for: schema, depth: 0)
    }

    func resolved(_ value: Any?) -> [String: Any] {
        (document?.resolve(value) ?? value) as? [String: Any] ?? [:]
    }

    func value(for raw: [String: Any], depth: Int) -> Any {
        let schema = resolved(raw)
        if let example = schema["example"] { return example }
        if let examples = schema["examples"] as? [Any], let first = examples.first { return first }
        if let fallback = schema["default"] { return fallback }
        if let choices = schema["enum"] as? [Any], let first = choices.first { return first }
        if let constant = schema["const"] { return constant }
        guard depth < 8 else { return NSNull() }
        if let parts = schema["allOf"] as? [Any] {
            var merged: [String: Any] = [:]
            for part in parts {
                if let object = value(for: resolved(part), depth: depth + 1) as? [String: Any] {
                    merged.merge(object) { _, new in new }
                }
            }
            return merged
        }
        for key in ["oneOf", "anyOf"] {
            if let choices = schema[key] as? [Any], let first = choices.first {
                return value(for: resolved(first), depth: depth + 1)
            }
        }
        var type = schema["type"] as? String
        if type == nil, let types = schema["type"] as? [String] { type = types.first { $0 != "null" } }
        if type == nil {
            type = schema["properties"] != nil ? "object" : (schema["items"] != nil ? "array" : "string")
        }
        switch type {
        case "object":
            var object: [String: Any] = [:]
            for (name, property) in schema["properties"] as? [String: Any] ?? [:] {
                object[name] = value(for: resolved(property), depth: depth + 1)
            }
            return object
        case "array":
            let count = max(1, schema["minItems"] as? Int ?? 1)
            let item = value(for: resolved(schema["items"]), depth: depth + 1)
            return Array(repeating: item, count: min(count, 3))
        case "integer":
            let minimum = (schema["minimum"] as? NSNumber)?.intValue ?? 1
            return max(minimum, (schema["exclusiveMinimum"] as? NSNumber).map { $0.intValue + 1 } ?? minimum)
        case "number":
            return (schema["minimum"] as? NSNumber)?.doubleValue ?? 1.5
        case "boolean":
            return true
        default:
            return string(format: schema["format"] as? String, minLength: schema["minLength"] as? Int ?? 0)
        }
    }

    func string(format: String?, minLength: Int) -> String {
        let base: String
        switch format?.lowercased() {
        case "date-time": base = "2026-01-01T00:00:00Z"
        case "date": base = "2026-01-01"
        case "time": base = "12:00:00"
        case "email": base = "user@example.com"
        case "uuid": base = "00000000-0000-4000-8000-000000000001"
        case "uri", "url": base = "https://example.com/"
        case "hostname": base = "example.com"
        case "ipv4": base = "127.0.0.1"
        case "ipv6": base = "::1"
        case "byte": base = "Z3VscA=="
        case "password": base = "Passw0rd!"
        default: base = "string"
        }
        return base.count >= minLength ? base : base + String(repeating: "x", count: minLength - base.count)
    }
}
