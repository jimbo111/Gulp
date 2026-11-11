// GulpCrawler — URL normalization for the crawl frontier (F09 CRL-003): default ports, fragments,
// dot segments, trailing slashes, sorted query parameters and (configurable) volatile parameters.
// The normalized form is only a dedup key; requests use the URL as discovered.

import Foundation
import GulpCore

/// How URLs are compared for dedup (CRL-003).
public struct NormalizationOptions: Sendable, Codable, Hashable {
    /// Treat `/a/` and `/a` as the same page (the root `/` is kept).
    public var ignoreTrailingSlash: Bool
    /// Query parameters left out of the key (tracking and cache-busting values), case-insensitive;
    /// a trailing `*` matches a prefix.
    public var ignoredParameters: [String]

    /// Options; the defaults drop common tracking parameters.
    public init(
        ignoreTrailingSlash: Bool = true,
        ignoredParameters: [String] = ["utm_*", "gclid", "fbclid", "_", "cb", "cachebuster"]
    ) {
        self.ignoreTrailingSlash = ignoreTrailingSlash
        self.ignoredParameters = ignoredParameters
    }

    func ignores(_ name: String) -> Bool {
        let name = name.lowercased()
        return ignoredParameters.contains { pattern in
            let pattern = pattern.lowercased()
            return pattern.hasSuffix("*") ? name.hasPrefix(pattern.dropLast()) : name == pattern
        }
    }
}

/// A parsed absolute http(s) URL.
public struct CrawlURL: Sendable, Hashable {
    /// `http` or `https`.
    public var scheme: Scheme
    /// Host (lowercased).
    public var host: String
    /// Port (the scheme's default when absent).
    public var port: Int
    /// Path, starting with `/`.
    public var path: String
    /// Query without `?` (nil when absent).
    public var query: String?

    /// Parse `url` (absolute http/https; the fragment is dropped). Nil for anything else.
    public init?(_ url: String) {
        let lower = url.lowercased()
        let scheme: Scheme
        if lower.hasPrefix("http://") {
            scheme = .http
        } else if lower.hasPrefix("https://") {
            scheme = .https
        } else {
            return nil
        }
        var rest = Substring(url.dropFirst(scheme == .http ? 7 : 8))
        if let hash = rest.firstIndex(of: "#") { rest = rest[..<hash] }
        let authorityEnd = rest.firstIndex { $0 == "/" || $0 == "?" } ?? rest.endIndex
        var authority = rest[..<authorityEnd]
        if let at = authority.lastIndex(of: "@") { authority = authority[authority.index(after: at)...] }
        guard !authority.isEmpty else { return nil }
        var host = String(authority)
        var port = scheme == .https ? 443 : 80
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else { return nil }
            host = String(authority[authority.index(after: authority.startIndex)..<close])
            let after = authority[authority.index(after: close)...]
            if after.hasPrefix(":") {
                guard let value = Int(after.dropFirst()) else { return nil }
                port = value
            }
        } else if let colon = authority.lastIndex(of: ":") {
            host = String(authority[..<colon])
            let digits = authority[authority.index(after: colon)...]
            if !digits.isEmpty {
                guard let value = Int(digits), (1...65_535).contains(value) else { return nil }
                port = value
            }
        }
        guard !host.isEmpty else { return nil }
        self.scheme = scheme
        self.host = host.lowercased()
        self.port = port
        let tail = rest[authorityEnd...]
        if let question = tail.firstIndex(of: "?") {
            path = String(tail[..<question])
            query = String(tail[tail.index(after: question)...])
        } else {
            path = String(tail)
            query = nil
        }
        if path.isEmpty { path = "/" }
        path = Self.removingDotSegments(path)
    }

    /// The target to connect to.
    public var target: HTTPTarget { HTTPTarget(scheme: scheme, host: host, port: port) }

    /// `host[:port]` for the Host header (the port only when it isn't the default).
    public var authority: String {
        let shown = host.contains(":") ? "[\(host)]" : host
        return port == (scheme == .https ? 443 : 80) ? shown : "\(shown):\(port)"
    }

    /// Path and query, as a request target.
    public var requestTarget: String { path + (query.map { "?" + $0 } ?? "") }

    /// The URL as text.
    public var string: String { "\(scheme.rawValue)://\(authority)\(requestTarget)" }

    /// The directory of the path (`/a/b/c` → `/a/b/`), for per-directory caps (CRL-008).
    public var directory: String {
        guard let slash = path.lastIndex(of: "/") else { return "/" }
        return String(path[...slash])
    }

    /// The dedup key (CRL-003): scheme, host and non-default port, the path (dot segments resolved,
    /// optionally without a trailing slash) and the query with ignored parameters dropped and the
    /// rest sorted.
    public func key(_ options: NormalizationOptions) -> String {
        var keyPath = path
        if options.ignoreTrailingSlash, keyPath.count > 1, keyPath.hasSuffix("/") { keyPath.removeLast() }
        let pairs = (query ?? "").split(separator: "&", omittingEmptySubsequences: true).map(String.init)
            .filter { pair in
                let name = pair.split(separator: "=", maxSplits: 1).first.map(String.init) ?? pair
                return !options.ignores(Self.decode(name))
            }
            .sorted()
        return "\(scheme.rawValue)://\(authority)\(keyPath)"
            + (pairs.isEmpty ? "" : "?" + pairs.joined(separator: "&"))
    }

    /// The query's parameters as (name, value), decoded.
    public var parameters: [(name: String, value: String)] {
        (query ?? "").split(separator: "&", omittingEmptySubsequences: true).map { pair in
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            return (Self.decode(String(parts[0])), parts.count > 1 ? Self.decode(String(parts[1])) : "")
        }
    }

    static func decode(_ text: String) -> String {
        text.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? text
    }

    /// RFC 3986 §5.2.4.
    static func removingDotSegments(_ path: String) -> String {
        guard path.contains("/.") else { return path }
        var output: [Substring] = []
        let segments = path.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
        for (index, segment) in segments.enumerated() {
            let last = index == segments.count - 1
            switch segment {
            case ".":
                if last { output.append("") }
            case "..":
                _ = output.popLast()
                if last { output.append("") }
            default: output.append(segment)
            }
        }
        return "/" + output.joined(separator: "/")
    }
}
