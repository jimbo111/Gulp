// GulpQuery — GulpQL lexer and recursive-descent parser (F05 §4). Errors carry the character range
// to underline (HIS-025); the token stream is public so the FilterBar can color the text.

import Foundation

/// A parse error with the character range to underline.
public struct GulpQLError: Error, Sendable, Hashable, CustomStringConvertible {
    /// What went wrong.
    public var message: String
    /// The offending characters (offsets into the text).
    public var range: Range<Int>

    /// An error.
    public init(_ message: String, at range: Range<Int>) {
        self.message = message
        self.range = range
    }

    /// `message (at N)`.
    public var description: String { "\(message) (at \(range.lowerBound + 1))" }
}

/// A token's role, for syntax coloring.
public enum GulpQLTokenKind: Sendable, Hashable {
    /// `and`, `or`, `not`, `contains`, `in`…
    case keyword
    /// A field or predicate name.
    case field
    /// `==`, `~`, `<=`…
    case `operator`
    /// A quoted string.
    case string
    /// A number.
    case number
    /// A `/regex/`.
    case regex
    /// `( ) [ ] , ..`
    case punctuation
    /// A bare word that isn't a field (a value like `proxy`).
    case word
}

/// A lexed token.
public struct GulpQLToken: Sendable, Hashable {
    /// Its role.
    public var kind: GulpQLTokenKind
    /// Its text (unescaped for strings and regexes).
    public var text: String
    /// Character offsets.
    public var range: Range<Int>
}

/// Parse, tokenize and complete GulpQL.
public enum GulpQL {
    /// The SQL function GulpStore registers for regex push-down: `gulpql_regexp(pattern, text, ci)`.
    public static let regexFunctionName = "gulpql_regexp"

    static let keywords: Set<String> = [
        "and", "or", "not", "contains", "startswith", "endswith", "in", "true", "false",
    ]

    /// Parse `text`; empty text matches everything.
    public static func parse(_ text: String) throws(GulpQLError) -> GulpQLExpression {
        let tokens = try tokenize(text)
        if tokens.isEmpty { return .constant(true) }
        var parser = Parser(tokens: tokens, length: text.count)
        let expression = try parser.expression()
        if let extra = parser.peek {
            throw GulpQLError("expected and/or before “\(extra.text)”", at: extra.range)
        }
        return expression
    }

    /// The tokens of `text`, for coloring (stops at the first lexical error).
    public static func highlights(_ text: String) -> [GulpQLToken] {
        var tokens: [GulpQLToken] = []
        var lexer = Lexer(Array(text))
        while let token = try? lexer.next() { tokens.append(token) }
        return tokens
    }

    /// Field and keyword completions for the word ending at `cursor` (HIS-025).
    public static func completions(_ text: String, cursor: Int) -> [String] {
        let characters = Array(text)
        let end = min(max(0, cursor), characters.count)
        var start = end
        while start > 0,
            characters[start - 1].isLetter || characters[start - 1] == "_"
                || characters[start - 1] == "." || characters[start - 1].isNumber
        {
            start -= 1
        }
        let prefix = String(characters[start..<end]).lowercased()
        let names = GulpQLFields.all.map(\.name) + keywords.sorted()
        return names.filter { $0.hasPrefix(prefix) && $0 != prefix }
    }

    static func tokenize(_ text: String) throws(GulpQLError) -> [GulpQLToken] {
        var lexer = Lexer(Array(text))
        var tokens: [GulpQLToken] = []
        while let token = try lexer.next() { tokens.append(token) }
        return tokens
    }
}

struct Lexer {
    let characters: [Character]
    var index = 0

    init(_ characters: [Character]) { self.characters = characters }

    mutating func next() throws(GulpQLError) -> GulpQLToken? {
        while index < characters.count, characters[index].isWhitespace { index += 1 }
        guard index < characters.count else { return nil }
        let start = index
        let c = characters[index]
        func token(_ kind: GulpQLTokenKind, _ length: Int) -> GulpQLToken {
            index = start + length
            return GulpQLToken(kind: kind, text: String(characters[start..<index]), range: start..<index)
        }
        func at(_ offset: Int) -> Character? {
            start + offset < characters.count ? characters[start + offset] : nil
        }
        switch c {
        case "(", ")", "[", "]", ",": return token(.punctuation, 1)
        case "." where at(1) == ".": return token(.punctuation, 2)
        case "=" where at(1) == "=": return token(.operator, 2)
        case "=" where at(1) == "~": return token(.operator, 2)
        case "!" where at(1) == "=": return token(.operator, 2)
        case "!" where at(1) == "~": return token(.operator, 2)
        case "<" where at(1) == "=", ">" where at(1) == "=": return token(.operator, 2)
        case "<", ">", "~": return token(.operator, 1)
        case "&" where at(1) == "&":
            return GulpQLToken(kind: .keyword, text: "and", range: start..<(index + 2)).advancing(&index)
        case "|" where at(1) == "|":
            return GulpQLToken(kind: .keyword, text: "or", range: start..<(index + 2)).advancing(&index)
        case "!":
            return GulpQLToken(kind: .keyword, text: "not", range: start..<(index + 1)).advancing(&index)
        case "=":
            // A lone `=` is a common slip for `==`.
            return GulpQLToken(kind: .operator, text: "==", range: start..<(index + 1)).advancing(&index)
        case "\"", "'": return try quoted(c)
        case "/": return try regex()
        default: break
        }
        if c.isNumber || (c == "-" && (at(1)?.isNumber ?? false)) {
            index += 1
            while index < characters.count, characters[index].isNumber { index += 1 }
            // A fraction, but not the `..` of a range.
            if index + 1 < characters.count, characters[index] == ".", characters[index + 1].isNumber {
                index += 1
                while index < characters.count, characters[index].isNumber { index += 1 }
            }
            return GulpQLToken(kind: .number, text: String(characters[start..<index]), range: start..<index)
        }
        if c.isLetter || c == "_" {
            index += 1
            while index < characters.count {
                let d = characters[index]
                if d.isLetter || d.isNumber || d == "_" || d == "-" {
                    index += 1
                } else if d == ".", index + 1 < characters.count, characters[index + 1].isLetter {
                    index += 1
                } else {
                    break
                }
            }
            let word = String(characters[start..<index])
            let lower = word.lowercased()
            let kind: GulpQLTokenKind =
                GulpQL.keywords.contains(lower) ? .keyword : GulpQLFields.named(lower) != nil ? .field : .word
            return GulpQLToken(kind: kind, text: kind == .keyword ? lower : word, range: start..<index)
        }
        throw GulpQLError("unexpected “\(c)”", at: start..<(start + 1))
    }

    mutating func quoted(_ quote: Character) throws(GulpQLError) -> GulpQLToken {
        let start = index
        index += 1
        var text = ""
        while index < characters.count {
            let c = characters[index]
            if c == quote {
                index += 1
                return GulpQLToken(kind: .string, text: text, range: start..<index)
            }
            if c == "\\", index + 1 < characters.count {
                let escaped = characters[index + 1]
                switch escaped {
                case "n": text.append("\n")
                case "t": text.append("\t")
                case "r": text.append("\r")
                default: text.append(escaped)
                }
                index += 2
                continue
            }
            text.append(c)
            index += 1
        }
        throw GulpQLError("unterminated string", at: start..<characters.count)
    }

    mutating func regex() throws(GulpQLError) -> GulpQLToken {
        let start = index
        index += 1
        var text = ""
        while index < characters.count {
            let c = characters[index]
            if c == "/" {
                index += 1
                return GulpQLToken(kind: .regex, text: text, range: start..<index)
            }
            if c == "\\", index + 1 < characters.count, characters[index + 1] == "/" {
                text.append("/")
                index += 2
                continue
            }
            text.append(c)
            index += 1
        }
        throw GulpQLError("unterminated /regex/", at: start..<characters.count)
    }
}

extension GulpQLToken {
    fileprivate func advancing(_ index: inout Int) -> GulpQLToken {
        index = range.upperBound
        return self
    }
}

struct Parser {
    let tokens: [GulpQLToken]
    let length: Int
    var position = 0

    init(tokens: [GulpQLToken], length: Int) {
        self.tokens = tokens
        self.length = length
    }

    var peek: GulpQLToken? { position < tokens.count ? tokens[position] : nil }

    var endRange: Range<Int> { length..<(length + 1) }

    mutating func advance() -> GulpQLToken? {
        defer { position += 1 }
        return peek
    }

    func isKeyword(_ word: String) -> Bool { peek?.kind == .keyword && peek?.text == word }

    mutating func expect(_ text: String) throws(GulpQLError) {
        guard let token = peek, token.text == text, token.kind == .punctuation else {
            throw GulpQLError("expected “\(text)”", at: peek?.range ?? endRange)
        }
        position += 1
    }

    mutating func expression() throws(GulpQLError) -> GulpQLExpression {
        var left = try andExpression()
        while isKeyword("or") {
            position += 1
            left = .or(left, try andExpression())
        }
        return left
    }

    mutating func andExpression() throws(GulpQLError) -> GulpQLExpression {
        var left = try notExpression()
        while isKeyword("and") {
            position += 1
            left = .and(left, try notExpression())
        }
        return left
    }

    mutating func notExpression() throws(GulpQLError) -> GulpQLExpression {
        if isKeyword("not") {
            position += 1
            return .not(try notExpression())
        }
        return try primary()
    }

    mutating func primary() throws(GulpQLError) -> GulpQLExpression {
        guard let token = peek else { throw GulpQLError("expected a field", at: endRange) }
        if token.kind == .punctuation, token.text == "(" {
            position += 1
            let inner = try expression()
            try expect(")")
            return inner
        }
        if token.kind == .keyword, token.text == "true" || token.text == "false" {
            position += 1
            return .constant(token.text == "true")
        }
        guard token.kind == .field || token.kind == .word else {
            throw GulpQLError("expected a field, found “\(token.text)”", at: token.range)
        }
        position += 1
        let name = token.text.lowercased()
        guard let info = GulpQLFields.named(name) else {
            let hint = GulpQLFields.suggestion(for: name).map { "; did you mean \($0)?" } ?? ""
            throw GulpQLError("unknown field “\(token.text)”\(hint)", at: token.range)
        }
        var arguments: [String] = []
        var argumentsRange = token.range
        if let open = peek, open.kind == .punctuation, open.text == "(" {
            position += 1
            while true {
                guard let argument = advance() else { throw GulpQLError("expected “)”", at: endRange) }
                switch argument.kind {
                case .string, .number, .word, .field: arguments.append(argument.text)
                default: throw GulpQLError("expected a string argument", at: argument.range)
                }
                if let comma = peek, comma.kind == .punctuation, comma.text == "," {
                    position += 1
                    continue
                }
                break
            }
            argumentsRange = token.range.lowerBound..<(peek?.range.upperBound ?? length)
            try expect(")")
        }
        guard info.arity.contains(arguments.count) else {
            let want =
                info.arity.lowerBound == info.arity.upperBound
                ? "\(info.arity.lowerBound)" : "\(info.arity.lowerBound)–\(info.arity.upperBound)"
            throw GulpQLError("\(info.name) takes \(want) argument(s): \(info.signature)", at: argumentsRange)
        }
        if info.name == "time_between" {
            for argument in arguments where GulpQLTime.parse(argument) == nil {
                throw GulpQLError(
                    "“\(argument)” isn't a date (use ISO 8601, e.g. 2026-11-10 or 2026-11-10T09:00:00Z)",
                    at: argumentsRange)
            }
        }
        let field = GulpQLField(info.name, arguments)
        guard let opToken = peek, let op = Self.comparison(opToken) else { return .test(field) }
        position += 1
        let value = try self.value()
        try validate(info, op, value, at: opToken.range.lowerBound..<(tokens[position - 1].range.upperBound))
        return .compare(field, op, value)
    }

    static func comparison(_ token: GulpQLToken) -> GulpQLOperator? {
        switch token.kind {
        case .operator: GulpQLOperator(rawValue: token.text)
        case .keyword:
            ["contains", "startswith", "endswith", "in"].contains(token.text)
                ? GulpQLOperator(rawValue: token.text) : nil
        default: nil
        }
    }

    mutating func value() throws(GulpQLError) -> GulpQLValue {
        guard let token = advance() else { throw GulpQLError("expected a value", at: endRange) }
        switch token.kind {
        case .string: return .string(token.text)
        case .regex: return .regex(token.text)
        case .word, .field: return .string(token.text)
        case .keyword where token.text == "true" || token.text == "false": return .bool(token.text == "true")
        case .number:
            guard let low = Double(token.text) else { throw GulpQLError("bad number", at: token.range) }
            if let dots = peek, dots.kind == .punctuation, dots.text == ".." {
                position += 1
                guard let end = advance(), end.kind == .number, let high = Double(end.text) else {
                    throw GulpQLError("expected a number after ..", at: peek?.range ?? endRange)
                }
                return .range(low, high)
            }
            return .number(low)
        case .punctuation where token.text == "[":
            var values: [GulpQLValue] = []
            if let close = peek, close.kind == .punctuation, close.text == "]" {
                position += 1
                return .list(values)
            }
            while true {
                values.append(try value())
                if let comma = peek, comma.kind == .punctuation, comma.text == "," {
                    position += 1
                    continue
                }
                try expect("]")
                return .list(values)
            }
        default:
            throw GulpQLError("expected a value, found “\(token.text)”", at: token.range)
        }
    }

    func validate(_ info: GulpQLFieldInfo, _ op: GulpQLOperator, _ value: GulpQLValue, at range: Range<Int>)
        throws(GulpQLError)
    {
        if info.kind == .bool, op != .equal, op != .notEqual {
            throw GulpQLError("\(info.name) is true/false: use it bare, with not, or with == / !=", at: range)
        }
        if op == .in {
            switch value {
            case .list, .range: break
            default: throw GulpQLError("in needs a [list] or a range like 500..599", at: range)
            }
        }
        if op.isRegex || { if case .regex = value { return true } else { return false } }() {
            let pattern: String
            switch value {
            case .string(let text), .regex(let text): pattern = text
            default: throw GulpQLError("\(op.rawValue) needs a regex (a string or /…/)", at: range)
            }
            if (try? NSRegularExpression(pattern: pattern)) == nil {
                throw GulpQLError("invalid regex /\(pattern)/", at: range)
            }
        }
    }
}

/// Dates for `time_between`.
enum GulpQLTime {
    /// ISO 8601 date-time, a date (midnight UTC), or epoch seconds.
    static func parse(_ text: String) -> Date? {
        if let seconds = Double(text) { return Date(timeIntervalSince1970: seconds) }
        let full = ISO8601DateFormatter()
        if let date = full.date(from: text) { return date }
        full.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = full.date(from: text) { return date }
        let day = ISO8601DateFormatter()
        day.formatOptions = [.withFullDate]
        return day.date(from: text)
    }
}
