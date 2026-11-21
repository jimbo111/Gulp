// GulpCodec — Transform Tags (F12 DEC-020…DEC-023): inline operations in request bytes, evaluated
// just before sending (the F03 hook pipeline) so the request you edit stays readable:
//
//     Authorization: Basic «base64{ «var(user)»:«var(pass)» }»
//     X-Sig: «hmac-sha256(key=s3cret){«var(body)»}»     X-Id: «uuid()»     X-N: «counter(n)»
//
// Syntax: `«op»`, `«op(args)»`, `«op{ inner }»` or `«op(args){ inner }»`. Tags nest; the inner content
// is evaluated first, then the op runs on it. Spaces and tabs just inside `{ … }` are trimmed, so
// tags can be spaced for reading. Arguments are positional (`hmac-sha256(s3cret)`) or `key=value`.
// Every Decoder operation is a tag, plus the dynamic ops `var(name)`, `now(format)`,
// `random(charset,len)`, `uuid()`, `counter(name)` and `len{inner}`; `beacon()` mints an OAST
// payload host once OAST is configured (F10, M11a). Everything outside tags is kept byte for byte.
// `««` and `»»` are literal delimiters. Errors name the byte offset of the tag (DEC-023); unbalanced
// delimiters are errors, never silently passed through.

import Foundation

/// A Transform Tag error, with the byte offset of the tag it concerns.
public struct TransformTagError: Error, Sendable, Equatable, CustomStringConvertible {
    /// Byte offset in the evaluated text.
    public var offset: Int
    /// What is wrong.
    public var message: String

    /// A readable form of the error, with the tag's byte offset.
    public var description: String { "Transform tag at byte \(offset): \(message)" }
}

// Mutable state behind a lock: the counters advance from concurrent sends (Repeater tabs, Fuzzer
// lanes), and every access goes through `lock`, so sharing it across tasks is safe.
/// Values tags read and counters they advance. Shared by every send of a project.
public final class TagState: @unchecked Sendable {
    private let lock = NSLock()
    private var variables: [String: String]
    private var counters: [String: Int] = [:]
    private var oastMinter: (@Sendable () -> String)?

    /// Set (or clear) how `beacon()` mints an OAST payload host (F10 BCN-001; nil: OAST is off).
    public func setOASTMinter(_ minter: (@Sendable () -> String)?) {
        lock.withLock { oastMinter = minter }
    }

    /// A fresh OAST payload host, or nil when OAST isn't configured.
    public func mintOASTHost() -> String? {
        let minter = lock.withLock { oastMinter }
        return minter?()
    }

    /// State with `variables`.
    public init(variables: [String: String] = [:]) {
        self.variables = variables
    }

    /// Replace the variables (`var(name)`).
    public func setVariables(_ values: [String: String]) {
        lock.withLock { variables = values }
    }

    /// Set one variable.
    public func setVariable(_ name: String, _ value: String?) {
        lock.withLock { variables[name] = value }
    }

    /// A variable's value.
    public func variable(_ name: String) -> String? {
        lock.withLock { variables[name] }
    }

    /// The counter's next value (1, 2, …); with `advance: false` (previews) it isn't consumed.
    public func counter(_ name: String, advance: Bool) -> Int {
        lock.withLock {
            let next = (counters[name] ?? 0) + 1
            if advance { counters[name] = next }
            return next
        }
    }
}

/// Parses and evaluates Transform Tags.
public struct TransformTags: Sendable {
    /// The opening delimiter (default `«`, configurable — doc 07).
    public var open: [UInt8]
    /// The closing delimiter (default `»`).
    public var close: [UInt8]

    /// Tags with the given delimiters.
    public init(open: String = "«", close: String = "»") {
        self.open = Array(open.utf8)
        self.close = Array(close.utf8)
    }

    /// Whether `bytes` contain an opening delimiter (cheap pre-check: most requests have none).
    public func containsTags(_ bytes: [UInt8]) -> Bool {
        find(open, in: bytes, from: 0) != nil
    }

    /// `bytes` with every tag replaced by its value. `advance: false` previews without consuming
    /// counters.
    public func evaluate(_ bytes: [UInt8], state: TagState, advance: Bool = true) throws -> [UInt8] {
        var parser = Parser(bytes: bytes, open: open, close: close)
        let nodes = try parser.parseSequence(until: nil)
        return try render(nodes, state: state, advance: advance)
    }

    // MARK: parsing

    indirect enum Node {
        case literal([UInt8])
        case tag(name: String, arguments: [String], inner: [Node]?, offset: Int)
    }

    struct Parser {
        let bytes: [UInt8]
        let open: [UInt8]
        let close: [UInt8]
        var index = 0

        func starts(_ token: [UInt8], at position: Int) -> Bool {
            position + token.count <= bytes.count && Array(bytes[position..<position + token.count]) == token
        }

        /// Literals and tags until the end, or until `}` + close (the end of a tag's inner content).
        mutating func parseSequence(until terminator: [UInt8]?) throws -> [Node] {
            var nodes: [Node] = []
            var literal: [UInt8] = []
            func flush() {
                if !literal.isEmpty { nodes.append(.literal(literal)) }
                literal = []
            }
            while index < bytes.count {
                if let terminator, starts(terminator, at: index) { break }
                if starts(open + open, at: index) {
                    literal += open
                    index += open.count * 2
                } else if starts(close + close, at: index) {
                    literal += close
                    index += close.count * 2
                } else if starts(open, at: index) {
                    flush()
                    nodes.append(try parseTag())
                } else if starts(close, at: index) {
                    throw TransformTagError(
                        offset: index, message: "closing delimiter without an opening one")
                } else {
                    literal.append(bytes[index])
                    index += 1
                }
            }
            if let terminator, !starts(terminator, at: index) {
                throw TransformTagError(
                    offset: index,
                    message: "unterminated tag body (expected }\(String(decoding: close, as: UTF8.self)))")
            }
            flush()
            return nodes
        }

        mutating func parseTag() throws -> Node {
            let start = index
            index += open.count
            var name: [UInt8] = []
            while index < bytes.count, isNameByte(bytes[index]) {
                name.append(bytes[index])
                index += 1
            }
            guard !name.isEmpty else {
                throw TransformTagError(offset: start, message: "missing operation name")
            }
            var arguments: [String] = []
            if index < bytes.count, bytes[index] == 0x28 {  // (
                index += 1
                guard let end = bytes[index...].firstIndex(of: 0x29) else {
                    throw TransformTagError(offset: start, message: "unterminated argument list")
                }
                let text = String(decoding: bytes[index..<end], as: UTF8.self)
                arguments =
                    text.isEmpty
                    ? []
                    : text.split(separator: ",", omittingEmptySubsequences: false).map {
                        $0.trimmingCharacters(in: .whitespaces)
                    }
                index = end + 1
            }
            var inner: [Node]?
            if index < bytes.count, bytes[index] == 0x7B {  // {
                index += 1
                inner = try parseSequence(until: [0x7D] + close)  // }»
                index += 1 + close.count
            } else if starts(close, at: index) {
                index += close.count
            } else {
                throw TransformTagError(
                    offset: start,
                    message:
                        "expected ( { or \(String(decoding: close, as: UTF8.self)) after \(String(decoding: name, as: UTF8.self))"
                )
            }
            return .tag(
                name: String(decoding: name, as: UTF8.self), arguments: arguments, inner: inner, offset: start
            )
        }

        func isNameByte(_ byte: UInt8) -> Bool {
            (byte >= 0x61 && byte <= 0x7A) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x30 && byte <= 0x39)
                || byte == 0x2D || byte == 0x5F
        }
    }

    // MARK: evaluation

    func render(_ nodes: [Node], state: TagState, advance: Bool) throws -> [UInt8] {
        var output: [UInt8] = []
        for node in nodes {
            switch node {
            case .literal(let bytes): output += bytes
            case .tag(let name, let arguments, let inner, let offset):
                var content: [UInt8] = []
                if let inner {
                    content = trimSpaces(try render(inner, state: state, advance: advance))
                }
                output += try apply(
                    name, arguments, content, hasInner: inner != nil, offset: offset, state: state,
                    advance: advance)
            }
        }
        return output
    }

    func trimSpaces(_ bytes: [UInt8]) -> [UInt8] {
        guard let first = bytes.firstIndex(where: { $0 != 0x20 && $0 != 0x09 }),
            let last = bytes.lastIndex(where: { $0 != 0x20 && $0 != 0x09 })
        else { return [] }
        return Array(bytes[first...last])
    }

    func apply(
        _ name: String, _ arguments: [String], _ content: [UInt8], hasInner: Bool, offset: Int,
        state: TagState,
        advance: Bool
    ) throws -> [UInt8] {
        func fail(_ message: String) -> TransformTagError {
            TransformTagError(offset: offset, message: message)
        }
        switch name.lowercased() {
        case "var":
            guard let variable = arguments.first, !variable.isEmpty else {
                throw fail("var needs a name: «var(name)»")
            }
            guard let value = state.variable(variable) else {
                throw fail("variable \"\(variable)\" is not set")
            }
            return Array(value.utf8)
        case "now":
            return Array(Self.now(arguments.first ?? "unix").utf8)
        case "random":
            let charset = arguments.first.map(Self.charset) ?? Self.charset("alnum")
            let length = arguments.count > 1 ? Int(arguments[1]) ?? -1 : 16
            guard (0...65_536).contains(length) else { throw fail("random length must be 0…65536") }
            guard !charset.isEmpty else { throw fail("random needs a non-empty charset") }
            return (0..<length).map { _ in charset.randomElement()! }
        case "uuid":
            return Array(UUID().uuidString.lowercased().utf8)
        case "counter":
            return Array(String(state.counter(arguments.first ?? "default", advance: advance)).utf8)
        case "len":
            return Array(String(content.count).utf8)
        case "lit":
            return Array(arguments.joined(separator: ",").utf8)
        case "beacon":
            // F10 BCN-001: a unique payload per evaluation; `beacon()`/`beacon(host)` the hostname,
            // `beacon(url)` http://host/, `beacon(https)`, `beacon(email)`.
            guard let host = state.mintOASTHost() else {
                throw fail(
                    "beacon() needs OAST: configure a Beacon or interactsh server first (it is off by default)"
                )
            }
            switch (arguments.first ?? "host").lowercased() {
            case "", "host", "dns": return Array(host.utf8)
            case "url", "http": return Array("http://\(host)/".utf8)
            case "https": return Array("https://\(host)/".utf8)
            case "email": return Array("gulp@\(host)".utf8)
            default: throw fail("beacon(…) takes host, url, https or email")
            }
        default:
            guard let transform = Transforms.named(name) else { throw fail("unknown operation \"\(name)\"") }
            var named: [String: String] = [:]
            for (position, argument) in arguments.enumerated() {
                if let equals = argument.firstIndex(of: "=") {
                    named[String(argument[..<equals])] = String(argument[argument.index(after: equals)...])
                } else if position < transform.arguments.count {
                    named[transform.arguments[position]] = argument
                } else {
                    throw fail(
                        "\(name) takes \(transform.arguments.isEmpty ? "no" : transform.arguments.joined(separator: ", ")) arguments"
                    )
                }
            }
            do {
                return try transform.apply(content, named)
            } catch let error as CodecError {
                throw fail("\(name): \(error.message)")
            }
        }
    }

    static func charset(_ name: String) -> [UInt8] {
        switch name.lowercased() {
        case "alnum": Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".utf8)
        case "alpha": Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".utf8)
        case "digits", "numeric": Array("0123456789".utf8)
        case "hex": Array("0123456789abcdef".utf8)
        default: Array(name.utf8)  // the characters given
        }
    }

    /// `unix` (seconds), `unixms`, `iso`, or a date format pattern (`yyyy-MM-dd`).
    static func now(_ format: String) -> String {
        let date = Date()
        switch format.lowercased() {
        case "unix": return String(Int(date.timeIntervalSince1970))
        case "unixms": return String(Int(date.timeIntervalSince1970 * 1_000))
        case "iso": return ISO8601DateFormatter().string(from: date)
        default:
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(identifier: "UTC")
            formatter.dateFormat = format
            return formatter.string(from: date)
        }
    }

    func find(_ token: [UInt8], in bytes: [UInt8], from: Int) -> Int? {
        guard !token.isEmpty, bytes.count >= token.count else { return nil }
        var index = from
        while index + token.count <= bytes.count {
            if bytes[index] == token[0], Array(bytes[index..<index + token.count]) == token { return index }
            index += 1
        }
        return nil
    }
}
