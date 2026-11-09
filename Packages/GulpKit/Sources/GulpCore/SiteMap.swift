// GulpCore — the site map (F04 TGT-001…TGT-003, TGT-005/006): a trie of host → path segments →
// endpoint, built from exchanges as they are recorded (and rebuildable from the store). Nodes are
// *visited* (a real request was seen) or *inferred* (only referenced by a response — a link, a
// `Location`, a URL in JSON); a later real request turns an inferred node visited.
//
// The structure is kept in memory and never stored (F04 §4): it rebuilds from `exchanges` on open.

import Foundation

/// One node of the site map.
public struct SiteMapNode: Sendable, Hashable, Identifiable {
    /// What the node stands for.
    public enum Kind: Sendable, Hashable {
        /// `scheme://host[:port]`.
        case host
        /// A path segment (a directory or a file).
        case segment
    }

    /// Stable id: the node's URL key (`https://example.com:443/a/b`).
    public var id: String
    /// Host or segment.
    public var kind: Kind
    /// The label shown (host with scheme/port, or the segment).
    public var name: String
    /// A real request was seen for this node or below it.
    public var visited: Bool
    /// Some exchange at this node or below it was in scope.
    public var inScope: Bool
    /// Some exchange at this node or below it got a response other than 404 (TGT-005).
    public var found: Bool = false
    /// Response MIME types seen at this node or below it (TGT-005).
    public var mimes: Set<String> = []
    /// Exchanges whose path ends exactly at this node, oldest first.
    public var exchanges: [ExchangeID]
    /// Child node ids, in name order.
    public var children: [String]
}

/// One request seen for the site map.
public struct SiteMapEntry: Sendable, Hashable {
    /// The exchange.
    public var id: ExchangeID
    /// Where it went.
    public var target: HTTPTarget
    /// The path (no query).
    public var path: String
    /// Whether it is in scope.
    public var inScope: Bool
    /// The response status, if any.
    public var status: Int?
    /// The response MIME type, if any.
    public var mime: String?
    /// The request was actually sent (false for imported request-only entries such as OpenAPI
    /// operations or URL lists, which show as inferred).
    public var visited: Bool

    /// An entry.
    public init(
        id: ExchangeID, target: HTTPTarget, path: String, inScope: Bool, status: Int? = nil,
        mime: String? = nil, visited: Bool = true
    ) {
        self.visited = visited
        self.id = id
        self.target = target
        self.path = path
        self.inScope = inScope
        self.status = status
        self.mime = mime
    }
}

/// The site map trie (TGT-001).
public struct SiteMap: Sendable {
    /// Fold numeric and UUID path segments into `{id}` (TGT-006).
    public var groupsParameterizedSegments: Bool
    private(set) var nodes: [String: SiteMapNode] = [:]
    /// Host node ids, in name order.
    public private(set) var roots: [String] = []

    /// An empty map.
    public init(groupsParameterizedSegments: Bool = false) {
        self.groupsParameterizedSegments = groupsParameterizedSegments
    }

    /// A node.
    public func node(_ id: String) -> SiteMapNode? { nodes[id] }

    /// A node's children.
    public func children(of id: String) -> [SiteMapNode] {
        nodes[id]?.children.compactMap { nodes[$0] } ?? []
    }

    /// The host nodes.
    public var hosts: [SiteMapNode] { roots.compactMap { nodes[$0] } }

    /// Number of nodes.
    public var count: Int { nodes.count }

    /// Add a request that was seen (visited).
    public mutating func add(_ entry: SiteMapEntry) {
        insert(
            target: entry.target, path: entry.path, exchange: entry.id, visited: entry.visited,
            inScope: entry.inScope,
            found: entry.status != 404, mime: entry.mime)
    }

    /// Add a URL only referenced by a response (inferred, TGT-003). Non-http(s) URLs are ignored.
    public mutating func addInferred(url: String) {
        guard let target = HTTPTarget(url: url) else { return }
        insert(
            target: target, path: Self.path(of: url), exchange: nil, visited: false, inScope: false,
            found: false,
            mime: nil)
    }

    /// Every exchange at `id` or below it (the endpoints table for a selected node, TGT-002).
    public func exchanges(under id: String) -> [ExchangeID] {
        guard let node = nodes[id] else { return [] }
        return (node.exchanges + node.children.flatMap { exchanges(under: $0) }).sorted()
    }

    /// The nodes that pass `filter` (TGT-005), as a set of ids (their ancestors included so the
    /// tree still connects).
    public func visible(_ filter: SiteMapFilter) -> Set<String> {
        var keep: Set<String> = []
        func walk(_ id: String) -> Bool {
            guard let node = nodes[id] else { return false }
            var anyChild = false
            for child in node.children where walk(child) { anyChild = true }
            let passes =
                (!filter.inScopeOnly || node.inScope) && (!filter.visitedOnly || node.visited)
                && (!filter.hideNotFound || !node.visited || node.found)
                && (filter.mimes.isEmpty
                    || node.mimes.contains { mime in filter.mimes.contains { mime.contains($0) } })
                && (filter.search.isEmpty || id.localizedCaseInsensitiveContains(filter.search))
            guard anyChild || passes else { return false }
            keep.insert(id)
            return true
        }
        for root in roots { _ = walk(root) }
        return keep
    }

    // MARK: building

    private mutating func insert(
        target: HTTPTarget, path: String, exchange: ExchangeID?, visited: Bool, inScope: Bool, found: Bool,
        mime: String?
    ) {
        let hostKey = Self.hostKey(target)
        if nodes[hostKey] == nil {
            nodes[hostKey] = SiteMapNode(
                id: hostKey, kind: .host, name: hostKey, visited: false, inScope: false, exchanges: [],
                children: [])
            roots.insert(hostKey, at: roots.firstIndex { $0 > hostKey } ?? roots.endIndex)
        }
        var chain = [hostKey]
        var key = hostKey
        for raw in path.split(separator: "/", omittingEmptySubsequences: true) {
            let segment = groupsParameterizedSegments && Self.isParameter(raw) ? "{id}" : String(raw)
            let childKey = key + "/" + segment
            if nodes[childKey] == nil {
                nodes[childKey] = SiteMapNode(
                    id: childKey, kind: .segment, name: segment, visited: false, inScope: false,
                    exchanges: [],
                    children: [])
                let siblings = nodes[key]?.children ?? []
                let position = siblings.firstIndex { $0 > childKey } ?? siblings.endIndex
                nodes[key]?.children.insert(childKey, at: position)
            }
            key = childKey
            chain.append(key)
        }
        if let exchange { nodes[key]?.exchanges.append(exchange) }
        for id in chain {
            if visited { nodes[id]?.visited = true }
            if inScope { nodes[id]?.inScope = true }
            if found { nodes[id]?.found = true }
            if let mime { nodes[id]?.mimes.insert(mime) }
        }
    }

    /// `scheme://host:port` (the port always shown, so `:80` and `:8080` stay apart).
    public static func hostKey(_ target: HTTPTarget) -> String {
        "\(target.scheme.rawValue)://\(target.host.lowercased()):\(target.port)"
    }

    /// The path of an absolute URL (no query or fragment).
    static func path(of url: String) -> String {
        guard let schemeEnd = url.range(of: "://") else { return "/" }
        let rest = url[schemeEnd.upperBound...]
        guard let start = rest.firstIndex(of: "/") else { return "/" }
        return String(rest[start...].prefix { $0 != "?" && $0 != "#" })
    }

    /// A numeric or UUID-shaped segment (TGT-006).
    static func isParameter(_ segment: Substring) -> Bool {
        if !segment.isEmpty, segment.allSatisfy(\.isNumber) { return true }
        return segment.count == 36 && UUID(uuidString: String(segment)) != nil
    }
}

/// Site map show/hide filters (TGT-005).
public struct SiteMapFilter: Sendable, Hashable {
    /// Only nodes with in-scope traffic.
    public var inScopeOnly = false
    /// Hide inferred-only nodes.
    public var visitedOnly = false
    /// Hide visited nodes whose every response was a 404.
    public var hideNotFound = false
    /// Only nodes with a response whose MIME type contains one of these (e.g. `html`, `json`);
    /// empty = any.
    public var mimes: Set<String> = []
    /// Text that must appear in the node's URL.
    public var search = ""

    /// No filtering.
    public init(
        inScopeOnly: Bool = false, visitedOnly: Bool = false, hideNotFound: Bool = false,
        mimes: Set<String> = [], search: String = ""
    ) {
        self.inScopeOnly = inScopeOnly
        self.visitedOnly = visitedOnly
        self.hideNotFound = hideNotFound
        self.mimes = mimes
        self.search = search
    }
}

/// Finds URLs a response refers to (TGT-003 inferred nodes; shared with the Crawler, F09): `href`,
/// `src` and `action` attributes, the `Location` header, and absolute http(s) URLs in JSON or
/// script text. Relative references are resolved against the request URL.
public enum LinkExtractor {
    /// Upper bound on links taken from one response.
    public static let maxLinks = 500

    /// The absolute http(s) URLs `response` (to a request for `pageURL`) refers to.
    public static func urls(in response: RawResponse, pageURL: String) -> [String] {
        var found: [String] = []
        if let location = response.headerValue("location")?.string() { found.append(location) }
        let type = response.headerValue("content-type")?.string().lowercased() ?? ""
        let textual =
            type.isEmpty || type.contains("html") || type.contains("json") || type.contains("javascript")
            || type.contains("xml") || type.hasPrefix("text/")
        if textual, let body = response.parsed.dechunkedBody ?? Optional(response.bytes[response.parsed.body])
        {
            let text = String(decoding: body.rawBytes.prefix(2_000_000), as: UTF8.self)
            found += attributeValues(in: text) + absoluteURLs(in: text)
        }
        var seen: Set<String> = []
        var result: [String] = []
        for raw in found {
            guard let resolved = resolve(raw, against: pageURL), seen.insert(resolved).inserted else {
                continue
            }
            result.append(resolved)
            if result.count == maxLinks { break }
        }
        return result
    }

    private static let attribute = try? NSRegularExpression(
        pattern: #"(?:href|src|action)\s*=\s*["']([^"'<>\s]+)["']"#, options: [.caseInsensitive])
    private static let absolute = try? NSRegularExpression(
        pattern: #"https?://[A-Za-z0-9.\-]+(?::\d+)?[^\s"'<>\\)]*"#)

    static func attributeValues(in text: String) -> [String] {
        guard let attribute else { return [] }
        let range = NSRange(text.startIndex..., in: text)
        return attribute.matches(in: text, range: range).compactMap { match in
            Range(match.range(at: 1), in: text).map { String(text[$0]) }
        }
    }

    static func absoluteURLs(in text: String) -> [String] {
        guard let absolute else { return [] }
        let range = NSRange(text.startIndex..., in: text)
        return absolute.matches(in: text, range: range).compactMap {
            Range($0.range, in: text).map { String(text[$0]) }
        }
    }

    /// `reference` as an absolute http(s) URL, resolved against `page`; nil for other schemes
    /// (`mailto:`, `javascript:`, `data:`…) and fragments.
    public static func resolve(_ reference: String, against page: String) -> String? {
        let trimmed = reference.trimmingCharacters(in: .whitespaces)
        let lower = trimmed.lowercased()
        if lower.hasPrefix("http://") || lower.hasPrefix("https://") { return trimmed }
        if trimmed.isEmpty || trimmed.hasPrefix("#")
            || lower.range(of: "^[a-z][a-z0-9+.-]*:", options: .regularExpression) != nil
        {
            return nil
        }
        guard let schemeEnd = page.range(of: "://") else { return nil }
        let scheme = String(page[..<schemeEnd.lowerBound])
        let rest = page[schemeEnd.upperBound...]
        let authorityEnd = rest.firstIndex { $0 == "/" || $0 == "?" || $0 == "#" } ?? rest.endIndex
        let origin = scheme + "://" + rest[..<authorityEnd]
        if trimmed.hasPrefix("//") { return scheme + ":" + trimmed }
        if trimmed.hasPrefix("/") { return origin + trimmed }
        let pagePath = String(rest[authorityEnd...].prefix { $0 != "?" && $0 != "#" })
        let directory =
            pagePath.isEmpty ? "/" : String(pagePath[...(pagePath.lastIndex(of: "/") ?? pagePath.startIndex)])
        var segments: [Substring] = (directory + trimmed).split(
            separator: "/", omittingEmptySubsequences: false)
        var resolved: [Substring] = []
        for segment in segments.dropFirst() {
            switch segment {
            case ".": continue
            case "..": _ = resolved.popLast()
            default: resolved.append(segment)
            }
        }
        segments = resolved
        return origin + "/" + segments.joined(separator: "/")
    }
}
