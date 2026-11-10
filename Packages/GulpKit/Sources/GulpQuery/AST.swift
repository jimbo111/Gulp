// GulpQuery — the GulpQL syntax tree (F05 HIS-020). Sendable and Codable so filters can be saved,
// shared and sent between actors; `description` prints the canonical text back.

import Foundation

/// A literal on the right of a comparison.
public indirect enum GulpQLValue: Sendable, Hashable, Codable {
    /// A quoted string or a bare word (`source == proxy`).
    case string(String)
    /// A number.
    case number(Double)
    /// A `/regex/` literal.
    case regex(String)
    /// `true` or `false`.
    case bool(Bool)
    /// `[a, b, c]`.
    case list([GulpQLValue])
    /// `500..599` (inclusive).
    case range(Double, Double)
}

/// A comparison operator (HIS-020).
public enum GulpQLOperator: String, Sendable, Hashable, Codable, CaseIterable {
    /// Equal (case-insensitive for text).
    case equal = "=="
    /// Not equal.
    case notEqual = "!="
    /// Less than.
    case less = "<"
    /// Less than or equal.
    case lessOrEqual = "<="
    /// Greater than.
    case greater = ">"
    /// Greater than or equal.
    case greaterOrEqual = ">="
    /// Regex match, case-insensitive.
    case matches = "~"
    /// Regex doesn't match (case-insensitive).
    case notMatches = "!~"
    /// Regex match, case-sensitive.
    case matchesCaseSensitive = "=~"
    /// Substring (case-insensitive).
    case contains
    /// Prefix (case-insensitive).
    case startsWith = "startswith"
    /// Suffix (case-insensitive).
    case endsWith = "endswith"
    /// Member of a list or inside a range.
    case `in`

    var isRegex: Bool { self == .matches || self == .notMatches || self == .matchesCaseSensitive }
}

/// A field reference, e.g. `resp.status` or `req.header("x-api-key")`.
public struct GulpQLField: Sendable, Hashable, Codable {
    /// The canonical (lowercase) name.
    public var name: String
    /// Call arguments (`req.header("name")`, `time_between(a, b)`).
    public var arguments: [String]

    /// A field.
    public init(_ name: String, _ arguments: [String] = []) {
        self.name = name
        self.arguments = arguments
    }
}

/// A parsed GulpQL expression.
public indirect enum GulpQLExpression: Sendable, Hashable, Codable {
    /// Both.
    case and(GulpQLExpression, GulpQLExpression)
    /// Either.
    case or(GulpQLExpression, GulpQLExpression)
    /// Negation.
    case not(GulpQLExpression)
    /// `field op value`.
    case compare(GulpQLField, GulpQLOperator, GulpQLValue)
    /// A bare field or predicate: `in_scope`, `reflected("q")`, `comment` (non-empty).
    case test(GulpQLField)
    /// Matches everything (`true`, the empty filter) or nothing.
    case constant(Bool)

    /// Every node's fields, for analysis (which fields an expression needs).
    public var fields: [GulpQLField] {
        switch self {
        case .and(let a, let b), .or(let a, let b): a.fields + b.fields
        case .not(let a): a.fields
        case .compare(let field, _, _), .test(let field): [field]
        case .constant: []
        }
    }
}

extension GulpQLValue: CustomStringConvertible {
    /// The canonical GulpQL text.
    public var description: String {
        switch self {
        case .string(let text): GulpQLValue.quote(text)
        case .number(let number): GulpQLValue.format(number)
        case .regex(let pattern): "/" + pattern.replacingOccurrences(of: "/", with: "\\/") + "/"
        case .bool(let flag): flag ? "true" : "false"
        case .list(let values): "[" + values.map(\.description).joined(separator: ", ") + "]"
        case .range(let low, let high): GulpQLValue.format(low) + ".." + GulpQLValue.format(high)
        }
    }

    static func quote(_ text: String) -> String {
        var out = "\""
        for character in text {
            switch character {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\t": out += "\\t"
            case "\r": out += "\\r"
            default: out.append(character)
            }
        }
        return out + "\""
    }

    /// Integral numbers without a fraction (`500`, not `500.0`).
    static func format(_ number: Double) -> String {
        if number.rounded() == number, abs(number) < 1e15 { return String(Int64(number)) }
        return String(number)
    }
}

extension GulpQLField: CustomStringConvertible {
    /// `name` or `name("a", "b")`.
    public var description: String {
        arguments.isEmpty
            ? name : name + "(" + arguments.map(GulpQLValue.quote).joined(separator: ", ") + ")"
    }
}

extension GulpQLExpression: CustomStringConvertible {
    /// The canonical GulpQL text (fully parenthesised where precedence needs it).
    public var description: String { text(parent: 0) }

    /// Precedence: or 1, and 2, not 3, leaves 4.
    private func text(parent: Int) -> String {
        let own: Int
        let body: String
        switch self {
        case .or(let a, let b):
            own = 1
            body = a.text(parent: 1) + " or " + b.text(parent: 1)
        case .and(let a, let b):
            own = 2
            body = a.text(parent: 2) + " and " + b.text(parent: 2)
        case .not(let a):
            own = 3
            body = "not " + a.text(parent: 3)
        case .compare(let field, let op, let value):
            own = 4
            body = "\(field) \(op.rawValue) \(value)"
        case .test(let field):
            own = 4
            body = field.description
        case .constant(let flag):
            own = 4
            body = flag ? "true" : "false"
        }
        return own < parent ? "(" + body + ")" : body
    }
}
