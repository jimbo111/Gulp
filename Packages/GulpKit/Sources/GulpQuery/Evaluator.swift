// GulpQuery — in-memory evaluation over an Exchange (F05 HIS-023). Pure and Sendable: regexes are
// compiled once into a `GulpQLPredicate`; per-exchange values (params, cookies, bodies) are derived
// lazily and only for the fields an expression uses. Missing values (a `resp.*` field on a row with
// no response) never satisfy a comparison, so `not` and `has_response` behave consistently (§5).

import Foundation
import GulpCore

/// What evaluation may need beyond the exchange itself.
public struct GulpQLContext: Sendable {
    /// The current scope (`matches_scope`, and `in_scope` when `inScope` isn't given).
    public var scope: ScopeService?
    /// The stored in-scope flag, when the caller has it (the `exchanges.in_scope` column).
    public var inScope: (@Sendable (Exchange) -> Bool)?
    /// Undo a `Content-Encoding` (gzip, deflate, br…); nil leaves bodies as they are.
    public var decodeBody: (@Sendable (_ body: [UInt8], _ encoding: String) -> [UInt8]?)?
    /// Notebook notes for an exchange (`notes`).
    public var notes: (@Sendable (ExchangeID) -> [String])?
    /// Bodies are searched up to this many bytes (§5: 2 MB).
    public var bodyLimit = 2 * 1024 * 1024

    /// An empty context.
    public init(
        scope: ScopeService? = nil, inScope: (@Sendable (Exchange) -> Bool)? = nil,
        decodeBody: (@Sendable ([UInt8], String) -> [UInt8]?)? = nil,
        notes: (@Sendable (ExchangeID) -> [String])? = nil
    ) {
        self.scope = scope
        self.inScope = inScope
        self.decodeBody = decodeBody
        self.notes = notes
    }
}

/// A compiled expression, ready to test exchanges.
public struct GulpQLPredicate: Sendable {
    /// The expression.
    public let expression: GulpQLExpression
    /// Compiled regexes keyed by `i:` / `s:` + pattern.
    let regexes: [String: NSRegularExpression]

    /// Compile `expression` (throws for an invalid regex).
    public init(_ expression: GulpQLExpression) throws {
        self.expression = expression
        var regexes: [String: NSRegularExpression] = [:]
        func walk(_ node: GulpQLExpression) throws {
            switch node {
            case .and(let a, let b), .or(let a, let b):
                try walk(a)
                try walk(b)
            case .not(let a): try walk(a)
            case .compare(_, let op, let value):
                if let (key, pattern, caseless) = Self.regexKey(op, value), regexes[key] == nil {
                    regexes[key] = try NSRegularExpression(
                        pattern: pattern, options: caseless ? [.caseInsensitive] : [])
                }
            case .test, .constant: break
            }
        }
        try walk(expression)
        self.regexes = regexes
    }

    /// Parse and compile.
    public init(_ text: String) throws {
        try self.init(try GulpQL.parse(text))
    }

    static func regexKey(_ op: GulpQLOperator, _ value: GulpQLValue) -> (String, String, Bool)? {
        let pattern: String
        switch value {
        case .regex(let text): pattern = text
        case .string(let text) where op.isRegex: pattern = text
        default: return nil
        }
        let caseless = op != .matchesCaseSensitive
        return ((caseless ? "i:" : "s:") + pattern, pattern, caseless)
    }

    /// Whether `exchange` matches.
    public func evaluate(_ exchange: Exchange, context: GulpQLContext = GulpQLContext()) -> Bool {
        let view = ExchangeView(exchange, context)
        return evaluate(expression, view)
    }

    func evaluate(_ node: GulpQLExpression, _ view: ExchangeView) -> Bool {
        switch node {
        case .and(let a, let b): return evaluate(a, view) && evaluate(b, view)
        case .or(let a, let b): return evaluate(a, view) || evaluate(b, view)
        case .not(let a): return !evaluate(a, view)
        case .constant(let flag): return flag
        case .test(let field): return view.value(field).truthy
        case .compare(let field, let op, let value): return compare(view.value(field), op, value)
        }
    }

    func compare(_ resolved: Resolved, _ op: GulpQLOperator, _ value: GulpQLValue) -> Bool {
        switch resolved {
        case .missing: return false
        case .list(let items):
            // Negative operators hold when no element matches the positive one.
            switch op {
            case .notEqual: return !items.contains { compareScalar(.text($0), .equal, value) }
            case .notMatches: return !items.contains { compareScalar(.text($0), .matches, value) }
            default: return items.contains { compareScalar(.text($0), op, value) }
            }
        default: return compareScalar(resolved, op, value)
        }
    }

    func compareScalar(_ resolved: Resolved, _ op: GulpQLOperator, _ value: GulpQLValue) -> Bool {
        if case .bool(let flag) = resolved {
            guard let wanted = value.asBool else { return false }
            return op == .notEqual ? flag != wanted : flag == wanted
        }
        // Regex operators (or a /regex/ literal with ==).
        let regexValue: Bool = if case .regex = value { true } else { false }
        if op.isRegex || (op == .equal && regexValue),
            let (key, _, _) = Self.regexKey(op.isRegex ? op : .matches, value), let regex = regexes[key]
        {
            let text = resolved.text
            let range = NSRange(text.startIndex..., in: text)
            let hit = regex.firstMatch(in: text, range: range) != nil
            return op == .notMatches ? !hit : hit
        }
        if op == .in {
            switch value {
            case .list(let values): return values.contains { compareScalar(resolved, .equal, $0) }
            case .range(let low, let high):
                guard let number = resolved.number else { return false }
                return number >= low && number <= high
            default: return false
            }
        }
        // Numeric when both sides are numbers.
        if let left = resolved.number, let right = value.asNumber {
            switch op {
            case .equal: return left == right
            case .notEqual: return left != right
            case .less: return left < right
            case .lessOrEqual: return left <= right
            case .greater: return left > right
            case .greaterOrEqual: return left >= right
            default: break
            }
        }
        guard let right = value.asText?.lowercased() else { return false }
        let left = resolved.text.lowercased()
        switch op {
        case .equal: return left == right
        case .notEqual: return left != right
        case .less: return left < right
        case .lessOrEqual: return left <= right
        case .greater: return left > right
        case .greaterOrEqual: return left >= right
        case .contains: return left.contains(right)
        case .startsWith: return left.hasPrefix(right)
        case .endsWith: return left.hasSuffix(right)
        case .matches, .notMatches, .matchesCaseSensitive, .in: return false
        }
    }
}

/// A field's value for one exchange.
enum Resolved {
    case missing
    case text(String)
    case number(Double)
    case bool(Bool)
    case list([String])

    var truthy: Bool {
        switch self {
        case .missing: false
        case .text(let text): !text.isEmpty
        case .number(let number): number != 0
        case .bool(let flag): flag
        case .list(let items): !items.isEmpty
        }
    }

    var text: String {
        switch self {
        case .missing: ""
        case .text(let text): text
        case .number(let number): GulpQLValue.format(number)
        case .bool(let flag): flag ? "true" : "false"
        case .list(let items): items.joined(separator: "\n")
        }
    }

    var number: Double? {
        switch self {
        case .number(let number): number
        case .text(let text): Double(text.trimmingCharacters(in: .whitespaces))
        default: nil
        }
    }
}

extension GulpQLValue {
    var asBool: Bool? {
        switch self {
        case .bool(let flag): flag
        case .number(let number): number != 0
        case .string(let text):
            switch text.lowercased() {
            case "true", "yes", "1": true
            case "false", "no", "0": false
            default: nil
            }
        default: nil
        }
    }

    var asNumber: Double? {
        switch self {
        case .number(let number): number
        case .string(let text): Double(text)
        default: nil
        }
    }

    var asText: String? {
        switch self {
        case .string(let text), .regex(let text): text
        case .number(let number): GulpQLValue.format(number)
        case .bool(let flag): flag ? "true" : "false"
        case .list, .range: nil
        }
    }
}

/// Lazily derived views of one exchange (only what the expression touches is computed).
final class ExchangeView {
    let exchange: Exchange
    let context: GulpQLContext
    private var cachedParams: [(String, String)]?
    private var cachedRequestBody: String?
    private var cachedResponseBody: String?

    init(_ exchange: Exchange, _ context: GulpQLContext) {
        self.exchange = exchange
        self.context = context
    }

    var request: RawRequest { exchange.request }
    var derived: DerivedFields { exchange.derived }

    func value(_ field: GulpQLField) -> Resolved {
        let argument = field.arguments.first ?? ""
        switch field.name {
        case "req.method": return derived.method.map { .text($0) } ?? .missing
        case "req.host": return .text(derived.host.lowercased())
        case "req.port": return .number(Double(derived.port))
        case "req.scheme": return .text(derived.scheme.rawValue)
        case "req.path": return derived.path.map { .text($0) } ?? .missing
        case "req.query": return derived.query.map { .text($0) } ?? .missing
        case "req.url": return .text(url)
        case "req.ext": return derived.ext.map { .text($0) } ?? .missing
        case "req.length": return .number(Double(request.bytes.count))
        case "req.body": return .text(requestBody)
        case "req.line":
            let p = request.parsed
            return .text(request.bytes[p.method.lowerBound..<p.version.upperBound].string())
        case "req.header": return request.headerValue(argument).map { .text($0.string()) } ?? .missing
        case "req.headers":
            return .list(request.headerValues(argument).map { $0.string() })
        case "req.cookie": return cookies.first { $0.0 == argument }.map { .text($0.1) } ?? .missing
        case "req.param": return params.first { $0.0 == argument }.map { .text($0.1) } ?? .missing
        case "req.params": return .list(params.map(\.0))
        case "req.has_param":
            return .bool(argument.isEmpty ? !params.isEmpty : params.contains { $0.0 == argument })
        case "resp.status": return exchange.response.map { .number(Double($0.parsed.statusCode)) } ?? .missing
        case "resp.length": return derived.responseLength.map { .number(Double($0)) } ?? .missing
        case "resp.mime": return derived.mime.map { .text($0) } ?? .missing
        case "resp.title": return derived.title.map { .text($0) } ?? .missing
        case "resp.body": return exchange.response == nil ? .missing : .text(responseBody)
        case "resp.time": return exchange.timing.totalMs.map { .number($0) } ?? .missing
        case "resp.header":
            return exchange.response?.headerValue(argument).map { .text($0.string()) } ?? .missing
        case "resp.cookie":
            guard let response = exchange.response else { return .missing }
            for line in response.headerValues("set-cookie") {
                let pair = line.string().split(separator: ";").first ?? ""
                let parts = pair.split(separator: "=", maxSplits: 1).map {
                    $0.trimmingCharacters(in: .whitespaces)
                }
                if parts.first == argument { return .text(parts.count > 1 ? parts[1] : "") }
            }
            return .missing
        case "resp.sets_cookie": return .bool(derived.setsCookies)
        case "source": return .text(exchange.source.rawValue)
        case "in_scope":
            if let inScope = context.inScope { return .bool(inScope(exchange)) }
            return .bool(matchesScope)
        case "matches_scope": return .bool(matchesScope)
        case "highlight": return exchange.annotation.highlight.map { .text($0.rawValue) } ?? .missing
        case "comment": return exchange.annotation.comment.map { .text($0) } ?? .missing
        case "tag": return .list(exchange.annotation.tags)
        case "has_response": return .bool(exchange.response != nil)
        case "edited": return .bool(exchange.edited != nil)
        case "notes": return .list(context.notes?(exchange.id) ?? [])
        case "id": return .number(Double(exchange.id))
        case "reflected": return .bool(reflected(argument))
        case "time_between":
            guard field.arguments.count == 2, let from = GulpQLTime.parse(field.arguments[0]),
                let to = GulpQLTime.parse(field.arguments[1])
            else { return .missing }
            let start = exchange.timing.start
            return .bool(start >= from && start <= to)
        default: return .missing
        }
    }

    var url: String {
        let standard = derived.port == (derived.scheme == .https ? 443 : 80)
        let authority = standard ? derived.host : "\(derived.host):\(derived.port)"
        let query = derived.query.map { "?" + $0 } ?? ""
        return "\(derived.scheme.rawValue)://\(authority)\(derived.path ?? "/")\(query)"
    }

    var matchesScope: Bool {
        guard let scope = context.scope else { return false }
        let query = derived.query.map { "?" + $0 } ?? ""
        return scope.isInScope(exchange.target, path: (derived.path ?? "/") + query)
    }

    var cookies: [(String, String)] {
        var pairs: [(String, String)] = []
        for header in request.headerValues("cookie") {
            for piece in header.string().split(separator: ";") {
                let parts = piece.split(separator: "=", maxSplits: 1).map {
                    $0.trimmingCharacters(in: .whitespaces)
                }
                if let name = parts.first, !name.isEmpty {
                    pairs.append((name, parts.count > 1 ? parts[1] : ""))
                }
            }
        }
        return pairs
    }

    /// Query, form and top-level JSON parameters (name, decoded value).
    var params: [(String, String)] {
        if let cachedParams { return cachedParams }
        var pairs = Self.formPairs(derived.query ?? "")
        let type = request.headerValue("content-type")?.string().lowercased() ?? ""
        if type.contains("x-www-form-urlencoded") {
            pairs += Self.formPairs(requestBody)
        } else if type.contains("json"), let data = requestBody.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        {
            for (key, value) in object.sorted(by: { $0.key < $1.key }) {
                switch value {
                case let text as String: pairs.append((key, text))
                case let number as NSNumber: pairs.append((key, number.stringValue))
                default: pairs.append((key, ""))
                }
            }
        }
        cachedParams = pairs
        return pairs
    }

    static func formPairs(_ text: String) -> [(String, String)] {
        text.split(separator: "&").compactMap { piece in
            let parts = piece.split(separator: "=", maxSplits: 1).map(String.init)
            guard let name = parts.first.map(decode), !name.isEmpty else { return nil }
            return (name, parts.count > 1 ? decode(parts[1]) : "")
        }
    }

    static func decode(_ text: String) -> String {
        text.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? text
    }

    var requestBody: String {
        if let cachedRequestBody { return cachedRequestBody }
        let body = Array(request.bytes.rawBytes[request.parsed.body])
        let text = decoded(body, encoding: request.headerValue("content-encoding")?.string())
        cachedRequestBody = text
        return text
    }

    var responseBody: String {
        if let cachedResponseBody { return cachedResponseBody }
        guard let response = exchange.response else { return "" }
        let raw =
            response.parsed.dechunkedBody?.rawBytes ?? Array(response.bytes.rawBytes[response.parsed.body])
        let text = decoded(raw, encoding: response.headerValue("content-encoding")?.string())
        cachedResponseBody = text
        return text
    }

    func decoded(_ body: [UInt8], encoding: String?) -> String {
        var bytes = body
        if let encoding = encoding?.trimmingCharacters(in: .whitespaces).lowercased(), !encoding.isEmpty,
            encoding != "identity", let decode = context.decodeBody, let plain = decode(bytes, encoding)
        {
            bytes = plain
        }
        if bytes.count > context.bodyLimit { bytes = Array(bytes[..<context.bodyLimit]) }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// HIS-022: a value of parameter `name` (≥ 3 characters, raw or decoded) appears in the response.
    func reflected(_ name: String) -> Bool {
        guard let response = exchange.response else { return false }
        let values = params.filter { $0.0 == name }.map(\.1) + cookies.filter { $0.0 == name }.map(\.1)
        let rawValues = (derived.query ?? "").split(separator: "&").compactMap { piece -> String? in
            let parts = piece.split(separator: "=", maxSplits: 1)
            return parts.count == 2 && String(parts[0]) == name ? String(parts[1]) : nil
        }
        let headers = response.bytes[0..<response.parsed.headerBlockEnd].string()
        let haystack = headers + responseBody
        return (values + rawValues).contains { $0.count >= 3 && haystack.contains($0) }
    }
}
