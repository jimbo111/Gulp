// GulpSession — identities and the per-identity variable store (F15 SES-002, SES-021). An identity
// is a named actor (admin, user-A, unauthenticated) with its own cookie-jar partition, static
// credential variables, extra headers, and a login method. Variables captured by macros and session
// rules live here too, so later requests and Transform Tags (F12) can read them.

import Foundation
import GulpCore

/// A named set of credentials and session state (SES-002).
public struct Identity: Sendable, Hashable, Codable, Identifiable {
    /// Stable id.
    public var id: UUID
    /// Display name (`admin`, `user-A`).
    public var name: String
    /// Static variables (credentials, API keys) usable as `${name}` in macros, rules and tags.
    public var variables: [String: String]
    /// Extra headers added to this identity's requests (name → value).
    public var headers: [String: String]
    /// The macro id that logs this identity in (SES-023), if any.
    public var loginMacro: UUID?
    /// This identity's cookies.
    public var cookies: CookieJar
    /// Captured (dynamic) variables, kept apart from the static ones so a reset clears only these.
    public var captured: [String: String]

    /// An identity.
    public init(
        id: UUID = UUID(), name: String, variables: [String: String] = [:], headers: [String: String] = [:],
        loginMacro: UUID? = nil, cookies: CookieJar = CookieJar(), captured: [String: String] = [:]
    ) {
        self.id = id
        self.name = name
        self.variables = variables
        self.headers = headers
        self.loginMacro = loginMacro
        self.cookies = cookies
        self.captured = captured
    }

    /// Every variable visible to this identity (captured override static).
    public var allVariables: [String: String] { variables.merging(captured) { _, new in new } }

    /// The built-in "no credentials" identity (Authz Matrix's unauthenticated row, F23).
    public static let unauthenticated = Identity(name: "unauthenticated")
}

/// Substitutes `${name}` references from a variable map (shared by macros and rules).
public enum VariableExpansion {
    /// `text` with every `${name}` replaced by `variables[name]` (unknown names are left as-is).
    public static func expand(_ text: String, _ variables: [String: String]) -> String {
        guard text.contains("${") else { return text }
        var result = ""
        var rest = Substring(text)
        while let open = rest.range(of: "${") {
            result += rest[..<open.lowerBound]
            guard let close = rest[open.upperBound...].firstIndex(of: "}") else {
                result += rest[open.lowerBound...]
                return result
            }
            let name = String(rest[open.upperBound..<close])
            result += variables[name] ?? "${\(name)}"
            rest = rest[rest.index(after: close)...]
        }
        result += rest
        return result
    }

    /// The variable names referenced in `text`.
    public static func references(in text: String) -> [String] {
        var names: [String] = []
        var rest = Substring(text)
        while let open = rest.range(of: "${") {
            guard let close = rest[open.upperBound...].firstIndex(of: "}") else { break }
            names.append(String(rest[open.upperBound..<close]))
            rest = rest[rest.index(after: close)...]
        }
        return names
    }
}
