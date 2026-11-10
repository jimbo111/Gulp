// GulpCodec — a `.proto` parser for the subset that matters (F33 §4): syntax, package, imports,
// messages (nested types, enums, oneof, map, repeated/optional, reserved, options skipped), enums and
// services. Type names are resolved with protobuf's scoping rules (innermost scope outward, then the
// package) into the same models a compiled descriptor set decodes to. Anything it can't parse is an
// error with the line; `google/protobuf/*` imports that aren't supplied are tolerated (their types
// stay unresolved and decode schema-less).

import Foundation

/// A `.proto` parse error.
public struct ProtoParseError: Error, Sendable, Hashable, CustomStringConvertible {
    /// The file.
    public var file: String
    /// The line (1-based).
    public var line: Int
    /// What's wrong.
    public var message: String

    /// `file:line: message`.
    public var description: String { "\(file):\(line): \(message)" }
}

/// Parses `.proto` source.
public enum ProtoParser {
    /// Parse `files` (name → source) and resolve types across them; imports must be among `files`
    /// (except `google/protobuf/*`).
    public static func parse(_ files: [String: String]) throws(ProtoParseError) -> [ProtoFile] {
        var parsed: [ProtoFile] = []
        for name in files.keys.sorted() {
            var parser = FileParser(name: name, tokens: try tokenize(files[name] ?? "", file: name))
            parsed.append(try parser.file())
        }
        for file in parsed {
            for dependency in file.dependencies
            where files[dependency] == nil && !dependency.hasPrefix("google/protobuf/") {
                throw ProtoParseError(file: file.name, line: 1, message: "import not found: \(dependency)")
            }
        }
        return try Resolver(parsed).resolved()
    }

    struct Token {
        var text: String
        var line: Int
        var isString: Bool
    }

    static func tokenize(_ source: String, file: String) throws(ProtoParseError) -> [Token] {
        var tokens: [Token] = []
        let chars = Array(source)
        var index = 0
        var line = 1
        while index < chars.count {
            let c = chars[index]
            if c == "\n" { line += 1 }
            if c.isWhitespace {
                index += 1
                continue
            }
            if c == "/", index + 1 < chars.count, chars[index + 1] == "/" {
                while index < chars.count, chars[index] != "\n" { index += 1 }
                continue
            }
            if c == "/", index + 1 < chars.count, chars[index + 1] == "*" {
                index += 2
                while index + 1 < chars.count, !(chars[index] == "*" && chars[index + 1] == "/") {
                    if chars[index] == "\n" { line += 1 }
                    index += 1
                }
                index += 2
                continue
            }
            if c == "\"" || c == "'" {
                var text = ""
                index += 1
                while index < chars.count, chars[index] != c {
                    if chars[index] == "\\", index + 1 < chars.count { index += 1 }
                    text.append(chars[index])
                    index += 1
                }
                guard index < chars.count else {
                    throw ProtoParseError(file: file, line: line, message: "unterminated string")
                }
                index += 1
                tokens.append(Token(text: text, line: line, isString: true))
                continue
            }
            if c.isLetter || c.isNumber || c == "_" || c == "." || c == "-" || c == "+" {
                var text = ""
                while index < chars.count,
                    chars[index].isLetter || chars[index].isNumber || chars[index] == "_"
                        || chars[index] == "."
                        || (text.isEmpty && (chars[index] == "-" || chars[index] == "+"))
                {
                    text.append(chars[index])
                    index += 1
                }
                tokens.append(Token(text: text, line: line, isString: false))
                continue
            }
            tokens.append(Token(text: String(c), line: line, isString: false))
            index += 1
        }
        return tokens
    }

    struct FileParser {
        let name: String
        let tokens: [Token]
        var position = 0

        init(name: String, tokens: [Token]) {
            self.name = name
            self.tokens = tokens
        }

        var peek: Token? { position < tokens.count ? tokens[position] : nil }
        var line: Int { peek?.line ?? tokens.last?.line ?? 1 }

        func error(_ message: String) -> ProtoParseError {
            ProtoParseError(file: name, line: line, message: message)
        }

        mutating func next() throws(ProtoParseError) -> Token {
            guard let token = peek else { throw error("unexpected end of file") }
            position += 1
            return token
        }

        mutating func expect(_ text: String) throws(ProtoParseError) {
            let token = try next()
            guard token.text == text, !token.isString else {
                throw ProtoParseError(
                    file: name, line: token.line, message: "expected \(text), found \(token.text)")
            }
        }

        mutating func skip(_ text: String) -> Bool {
            if let token = peek, token.text == text, !token.isString {
                position += 1
                return true
            }
            return false
        }

        /// Skip to the end of a statement (`;`) or past a balanced `{ … }` block.
        mutating func skipStatement() throws(ProtoParseError) {
            var depth = 0
            while let token = peek {
                position += 1
                if token.text == "{" { depth += 1 }
                if token.text == "}" {
                    depth -= 1
                    if depth <= 0 { return }
                }
                if token.text == ";", depth == 0 { return }
            }
        }

        mutating func file() throws(ProtoParseError) -> ProtoFile {
            var file = ProtoFile(name: name, syntax: "proto2")
            while let token = peek {
                switch token.text {
                case "syntax", "edition":
                    position += 1
                    try expect("=")
                    file.syntax = try next().text
                    try expect(";")
                case "package":
                    position += 1
                    file.package = try next().text
                    try expect(";")
                case "import":
                    position += 1
                    _ = skip("public") || skip("weak")
                    file.dependencies.append(try next().text)
                    try expect(";")
                case "option": try skipStatement()
                case "message": file.messages.append(try message())
                case "enum": file.enums.append(try enumeration())
                case "service": file.services.append(try service())
                case "extend": try skipStatement()
                case ";": position += 1
                default: throw error("unexpected \(token.text)")
                }
            }
            return file
        }

        mutating func message() throws(ProtoParseError) -> ProtoMessageType {
            try expect("message")
            var type = ProtoMessageType(name: try next().text)
            try expect("{")
            while !skip("}") {
                guard let token = peek else { throw error("unterminated message \(type.name)") }
                switch token.text {
                case "message": type.nested.append(try message())
                case "enum": type.enums.append(try enumeration())
                case "option", "reserved", "extensions", "extend": try skipStatement()
                case ";": position += 1
                case "oneof":
                    position += 1
                    let oneofName = try next().text
                    type.oneofs.append(oneofName)
                    try expect("{")
                    while !skip("}") {
                        if peek?.text == "option" {
                            try skipStatement()
                            continue
                        }
                        var def = try field(label: .optional)
                        def.oneofIndex = type.oneofs.count - 1
                        type.fields.append(def)
                    }
                case "map":
                    position += 1
                    try expect("<")
                    let keyType = try next().text
                    try expect(",")
                    let valueType = try next().text
                    try expect(">")
                    let fieldName = try next().text
                    try expect("=")
                    guard let number = Int(try next().text) else { throw error("bad field number") }
                    if peek?.text == "[" { try skipOptions() }
                    try expect(";")
                    let entryName =
                        fieldName.split(separator: "_").map { $0.prefix(1).uppercased() + $0.dropFirst() }
                        .joined() + "Entry"
                    var entry = ProtoMessageType(name: entryName, isMapEntry: true)
                    entry.fields = [
                        ProtoFieldDef(
                            name: "key", number: 1, type: try typeOf(keyType).0,
                            typeName: try typeOf(keyType).1),
                        ProtoFieldDef(
                            name: "value", number: 2, type: try typeOf(valueType).0,
                            typeName: try typeOf(valueType).1),
                    ]
                    type.nested.append(entry)
                    type.fields.append(
                        ProtoFieldDef(
                            name: fieldName, number: number, label: .repeated, type: .message,
                            typeName: entryName))
                case "repeated":
                    position += 1
                    type.fields.append(try field(label: .repeated))
                case "optional":
                    position += 1
                    type.fields.append(try field(label: .optional))
                case "required":
                    position += 1
                    type.fields.append(try field(label: .required))
                case "group": throw error("groups aren't supported; import a compiled descriptor set instead")
                default: type.fields.append(try field(label: .optional))
                }
            }
            return type
        }

        /// A type keyword or a (still unresolved) message/enum name.
        func typeOf(_ name: String) throws(ProtoParseError) -> (ProtoFieldType, String?) {
            if let scalar = ProtoFieldType.keyword(name) { return (scalar, nil) }
            return (.message, name)  // message or enum: decided by the resolver
        }

        mutating func field(label: ProtoLabel) throws(ProtoParseError) -> ProtoFieldDef {
            let typeToken = try next()
            let name = try next().text
            try expect("=")
            let numberToken = try next()
            guard let number = Int(numberToken.text) else {
                throw ProtoParseError(
                    file: name, line: numberToken.line, message: "bad field number \(numberToken.text)")
            }
            var jsonName: String?
            if peek?.text == "[" { jsonName = try skipOptions() }
            try expect(";")
            let (type, typeName) = try typeOf(typeToken.text)
            return ProtoFieldDef(
                name: name, number: number, label: label, type: type, typeName: typeName, jsonName: jsonName)
        }

        /// Skip `[ … ]` field options; returns a `json_name` if one was given.
        @discardableResult
        mutating func skipOptions() throws(ProtoParseError) -> String? {
            try expect("[")
            var jsonName: String?
            var previous = ""
            while !skip("]") {
                let token = try next()
                if previous == "=" && tokens[position - 3].text == "json_name" { jsonName = token.text }
                previous = token.text
            }
            return jsonName
        }

        mutating func enumeration() throws(ProtoParseError) -> ProtoEnumType {
            try expect("enum")
            var type = ProtoEnumType(name: try next().text, values: [])
            try expect("{")
            while !skip("}") {
                guard let token = peek else { throw error("unterminated enum \(type.name)") }
                if token.text == "option" || token.text == "reserved" {
                    try skipStatement()
                    continue
                }
                if skip(";") { continue }
                let name = try next().text
                try expect("=")
                guard let number = Int(try next().text) else { throw error("bad enum value") }
                if peek?.text == "[" { try skipOptions() }
                try expect(";")
                type.values.append(ProtoEnumValue(name: name, number: number))
            }
            return type
        }

        mutating func service() throws(ProtoParseError) -> ProtoService {
            try expect("service")
            var service = ProtoService(name: try next().text, methods: [])
            try expect("{")
            while !skip("}") {
                guard let token = peek else { throw error("unterminated service \(service.name)") }
                if token.text == "option" {
                    try skipStatement()
                    continue
                }
                if skip(";") { continue }
                try expect("rpc")
                let name = try next().text
                try expect("(")
                let clientStreaming = skip("stream")
                let input = try next().text
                try expect(")")
                try expect("returns")
                try expect("(")
                let serverStreaming = skip("stream")
                let output = try next().text
                try expect(")")
                if peek?.text == "{" { try skipStatement() } else { try expect(";") }
                service.methods.append(
                    ProtoMethod(
                        name: name, inputType: input, outputType: output, clientStreaming: clientStreaming,
                        serverStreaming: serverStreaming))
            }
            return service
        }
    }

    /// Resolves type names to fully qualified ones and decides message vs enum.
    struct Resolver {
        var files: [ProtoFile]
        var messageNames: Set<String> = []
        var enumNames: Set<String> = []

        init(_ files: [ProtoFile]) {
            self.files = files
            for file in files {
                let prefix = file.package.isEmpty ? "" : "." + file.package
                func collect(_ type: ProtoMessageType, _ scope: String) {
                    let full = scope + "." + type.name
                    messageNames.insert(full)
                    for e in type.enums { enumNames.insert(full + "." + e.name) }
                    for nested in type.nested { collect(nested, full) }
                }
                for type in file.messages { collect(type, prefix) }
                for e in file.enums { enumNames.insert(prefix + "." + e.name) }
            }
        }

        /// Protobuf scoping: try the innermost scope first, then each enclosing one.
        func resolve(_ name: String, scope: String) -> String? {
            if name.hasPrefix(".") {
                return messageNames.contains(name) || enumNames.contains(name) ? name : nil
            }
            var parts = scope.split(separator: ".").map(String.init)
            while true {
                let candidate = "." + (parts + [name]).joined(separator: ".")
                if messageNames.contains(candidate) || enumNames.contains(candidate) { return candidate }
                if parts.isEmpty { return nil }
                parts.removeLast()
            }
        }

        func resolveMessage(_ type: ProtoMessageType, scope: String) -> ProtoMessageType {
            var copy = type
            let inner = scope + "." + type.name
            copy.fields = type.fields.map { def in
                guard def.type == .message, let written = def.typeName else { return def }
                var resolved = def
                if let full = resolve(written, scope: inner) {
                    resolved.typeName = full
                    resolved.type = enumNames.contains(full) ? .enum : .message
                } else {
                    resolved.typeName = "." + written  // unresolved (e.g. a google.protobuf type)
                }
                return resolved
            }
            copy.nested = type.nested.map { resolveMessage($0, scope: inner) }
            return copy
        }

        func resolved() throws(ProtoParseError) -> [ProtoFile] {
            files.map { file in
                var copy = file
                let scope = file.package.isEmpty ? "" : "." + file.package
                copy.messages = file.messages.map { resolveMessage($0, scope: scope) }
                copy.services = file.services.map { service in
                    var s = service
                    s.methods = service.methods.map { method in
                        var m = method
                        m.inputType = resolve(method.inputType, scope: scope) ?? "." + method.inputType
                        m.outputType = resolve(method.outputType, scope: scope) ?? "." + method.outputType
                        return m
                    }
                    return s
                }
                return copy
            }
        }
    }
}
