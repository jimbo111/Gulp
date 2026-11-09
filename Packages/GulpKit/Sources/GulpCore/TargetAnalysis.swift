// GulpCore — "Analyze target" for one host (F04 TGT-008): how many URLs are dynamic (take
// parameters) versus static, which parameters were seen and where (query, body, JSON, cookie), and
// observations worth a closer look — parameters that look like file names, redirect targets or
// tokens. A pure function over exchanges; the workspace feeds it a host's history.

import Foundation

/// Where a parameter appeared.
public enum ParameterLocation: String, Sendable, Hashable, Codable, CaseIterable, Comparable {
    /// The URL query string.
    case query
    /// A form-encoded body.
    case body
    /// A top-level key of a JSON body.
    case json
    /// A request cookie.
    case cookie

    /// Declaration order.
    public static func < (lhs: Self, rhs: Self) -> Bool {
        allCases.firstIndex(of: lhs)! < allCases.firstIndex(of: rhs)!
    }
}

/// One parameter name and where it was used.
public struct ParameterUse: Sendable, Hashable {
    /// The parameter name.
    public var name: String
    /// Where it appeared.
    public var locations: Set<ParameterLocation>
    /// How many requests carried it.
    public var count: Int
    /// Up to five endpoints (`METHOD /path`) that took it, first seen first.
    public var endpoints: [String]
    /// A value seen for it (the first non-empty one), up to 100 characters.
    public var sampleValue: String
}

/// Something in a host's traffic worth a closer look.
public struct TargetObservation: Sendable, Hashable {
    /// What kind of thing.
    public enum Kind: String, Sendable, Hashable, CaseIterable {
        /// A parameter that may name a file or a path (traversal, inclusion).
        case fileParameter
        /// A parameter that may hold a redirect target (open redirect, SSRF).
        case redirectParameter
        /// A parameter that holds a token, key or session value.
        case tokenParameter
        /// A token or key sent in the URL (leaks through logs and Referer).
        case tokenInURL
    }

    /// The kind.
    public var kind: Kind
    /// The parameter.
    public var parameter: String
    /// The endpoint it was seen on (`METHOD /path`).
    public var endpoint: String
    /// A one-line explanation.
    public var detail: String
}

/// The result of analyzing one host (TGT-008).
public struct TargetAnalysis: Sendable, Hashable {
    /// Requests looked at.
    public var requestCount = 0
    /// Distinct endpoints (method + path).
    public var endpointCount = 0
    /// Endpoints that took parameters (query, body or JSON).
    public var dynamicEndpointCount = 0
    /// Endpoints that never took parameters.
    public var staticEndpointCount: Int { endpointCount - dynamicEndpointCount }
    /// Responses that redirected (3xx with a `Location`).
    public var redirectCount = 0
    /// Every parameter seen, by name.
    public var parameters: [ParameterUse] = []
    /// Observations, grouped by kind then parameter.
    public var observations: [TargetObservation] = []

    /// An empty analysis.
    public init() {}

    /// Analyze `exchanges` (normally one host's traffic).
    public static func analyze(_ exchanges: [Exchange]) -> TargetAnalysis {
        var result = TargetAnalysis()
        var endpoints: Set<String> = []
        var dynamic: Set<String> = []
        var uses: [String: ParameterUse] = [:]
        var order: [String] = []
        var seenObservations: Set<String> = []
        for exchange in exchanges {
            result.requestCount += 1
            let endpoint = "\(exchange.derived.method ?? "?") \(exchange.derived.path ?? "/")"
            endpoints.insert(endpoint)
            if let response = exchange.response, (300..<400).contains(response.parsed.statusCode),
                response.headerValue("location") != nil
            {
                result.redirectCount += 1
            }
            let params = parameters(of: exchange)
            if params.contains(where: { $0.location != .cookie }) { dynamic.insert(endpoint) }
            for param in params {
                if uses[param.name] == nil {
                    order.append(param.name)
                    uses[param.name] = ParameterUse(
                        name: param.name, locations: [], count: 0, endpoints: [], sampleValue: "")
                }
                uses[param.name]?.locations.insert(param.location)
                uses[param.name]?.count += 1
                if let list = uses[param.name]?.endpoints, list.count < 5, !list.contains(endpoint) {
                    uses[param.name]?.endpoints.append(endpoint)
                }
                if uses[param.name]?.sampleValue.isEmpty == true {
                    uses[param.name]?.sampleValue = String(param.value.prefix(100))
                }
                for observation in observe(param, endpoint: endpoint)
                where seenObservations.insert("\(observation.kind)|\(observation.parameter)").inserted {
                    result.observations.append(observation)
                }
            }
        }
        result.endpointCount = endpoints.count
        result.dynamicEndpointCount = dynamic.count
        result.parameters = order.compactMap { uses[$0] }
        let kinds = TargetObservation.Kind.allCases
        result.observations.sort {
            ($0.kind == $1.kind)
                ? $0.parameter < $1.parameter
                : kinds.firstIndex(of: $0.kind)! < kinds.firstIndex(of: $1.kind)!
        }
        return result
    }

    /// One parameter occurrence.
    struct Occurrence: Equatable {
        var name: String
        var value: String
        var location: ParameterLocation
    }

    /// The parameters a request carries: query, form body, top-level JSON keys, cookies.
    static func parameters(of exchange: Exchange) -> [Occurrence] {
        var found: [Occurrence] = []
        if let query = exchange.derived.query {
            found += pairs(query, separator: "&").map { Occurrence(name: $0, value: $1, location: .query) }
        }
        let request = exchange.request
        let type = request.headerValue("content-type")?.string().lowercased() ?? ""
        let body = request.bytes[request.parsed.body]
        if !body.isEmpty {
            if type.contains("x-www-form-urlencoded") {
                found += pairs(body.string(), separator: "&").map {
                    Occurrence(name: $0, value: $1, location: .body)
                }
            } else if type.contains("json"),
                let object = try? JSONSerialization.jsonObject(with: Data(body.rawBytes.prefix(1_000_000)))
                    as? [String: Any]
            {
                for key in object.keys.sorted() {
                    let value = object[key].map { ($0 as? String) ?? "\($0)" } ?? ""
                    found.append(Occurrence(name: key, value: value, location: .json))
                }
            }
        }
        if let cookie = request.headerValue("cookie")?.string() {
            found += pairs(cookie, separator: ";").map { Occurrence(name: $0, value: $1, location: .cookie) }
        }
        return found
    }

    /// `a=1&b=2` (or `a=1; b=2`) as decoded name/value pairs; empty names dropped.
    static func pairs(_ text: String, separator: Character) -> [(String, String)] {
        text.split(separator: separator).compactMap { part in
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            let pieces = trimmed.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            func decode(_ s: Substring) -> String {
                let plus = s.replacingOccurrences(of: "+", with: " ")
                return plus.removingPercentEncoding ?? plus
            }
            let name = decode(pieces[0])
            guard !name.isEmpty else { return nil }
            return (name, pieces.count > 1 ? decode(pieces[1]) : "")
        }
    }

    private static let fileNames: Set<String> = [
        "file", "filename", "path", "filepath", "page", "template", "include", "doc", "document", "folder",
        "dir", "load", "download", "view", "img", "image",
    ]
    private static let redirectNames: Set<String> = [
        "url", "uri", "redirect", "redirect_uri", "redirecturl", "redirect_url", "next", "return",
        "returnurl",
        "return_url", "returnto", "goto", "dest", "destination", "continue", "callback", "target", "to",
        "out",
    ]
    private static let tokenFragments = [
        "token", "csrf", "xsrf", "session", "sessid", "jwt", "auth", "apikey", "api_key", "secret", "sig",
        "password", "passwd",
    ]

    /// What `param` looks like.
    static func observe(_ param: Occurrence, endpoint: String) -> [TargetObservation] {
        let name = param.name.lowercased()
        let value = param.value
        var result: [TargetObservation] = []
        let looksLikeFile =
            value.range(of: #"(^|/)[\w.-]+\.[A-Za-z0-9]{1,5}$"#, options: .regularExpression) != nil
            && !value.lowercased().hasPrefix("http")
        if param.location != .cookie, fileNames.contains(name) || looksLikeFile || value.contains("../") {
            result.append(
                TargetObservation(
                    kind: .fileParameter, parameter: param.name, endpoint: endpoint,
                    detail:
                        "Looks like a file name or path (\(value.prefix(60))): try traversal or inclusion."))
        }
        let lowerValue = value.lowercased()
        let looksLikeURL =
            lowerValue.hasPrefix("http://") || lowerValue.hasPrefix("https://") || lowerValue.hasPrefix("//")
        if param.location != .cookie, redirectNames.contains(name) || looksLikeURL {
            result.append(
                TargetObservation(
                    kind: .redirectParameter, parameter: param.name, endpoint: endpoint,
                    detail: "May hold a URL to go to or fetch: try an open redirect or SSRF."))
        }
        let tokenName = tokenFragments.contains { name.contains($0) }
        if tokenName || looksLikeToken(value) {
            let inURL = param.location == .query
            result.append(
                TargetObservation(
                    kind: inURL ? .tokenInURL : .tokenParameter, parameter: param.name, endpoint: endpoint,
                    detail: inURL
                        ? "A token or key in the URL leaks through logs, history and Referer."
                        : "Holds a token, key or session value."))
        }
        return result
    }

    /// A JWT, or a long run of hex or base64 characters.
    static func looksLikeToken(_ value: String) -> Bool {
        if value.range(of: #"^eyJ[\w-]+\.[\w-]+\.[\w-]*$"#, options: .regularExpression) != nil {
            return true
        }
        return value.count >= 24
            && value.range(of: #"^[A-Za-z0-9+/_=-]+$"#, options: .regularExpression) != nil
            && value.contains(where: \.isNumber) && value.contains(where: \.isLetter)
    }
}
