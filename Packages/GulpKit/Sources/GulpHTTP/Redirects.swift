// GulpHTTP — following redirects (F03 `RedirectPolicy`, F06 REP-006). The engine sends each hop as
// its own exchange; this file decides whether a response is a redirect to follow and builds the
// next request from the previous one's bytes:
//   - 303 (and 301/302 after a POST, as browsers do) becomes a GET without the body and its
//     framing/type headers; 307/308 repeat the method and body unchanged;
//   - `Host` is rewritten when the authority changes; every other header is kept as written;
//   - `on-site` stays on the same host (any scheme/port); `in-scope` follows only to in-scope URLs
//     (the caller's `ScopeService`; with none, it behaves as `on-site`); `always` follows anywhere.

import GulpCore

/// Plans redirect hops.
public enum Redirects {
    /// Statuses that redirect with a `Location`.
    public static let statuses: Set<Int> = [301, 302, 303, 307, 308]

    /// The next request after `response` to `request` (sent to `target`), or nil when it isn't a
    /// redirect `policy` follows.
    public static func next(
        after response: RawResponse, request: RawRequest, target: HTTPTarget, policy: RedirectPolicy,
        scope: ScopeService? = nil
    ) -> (request: RawRequest, target: HTTPTarget)? {
        guard policy.mode != .never, statuses.contains(response.parsed.statusCode),
            let location = response.headerValue("location")?.string().trimmedOf(" \t"),
            !location.isEmpty
        else { return nil }
        let currentPath = request.bytes[request.parsed.target].string()
        guard let (nextTarget, path) = resolve(location, from: target, path: currentPath) else {
            return nil
        }
        switch policy.mode {
        case .never: return nil
        case .inScope where scope != nil:
            guard scope?.isInScope(nextTarget, path: path) == true else { return nil }
        case .onSite, .inScope:
            guard nextTarget.host.lowercased() == target.host.lowercased() else { return nil }
        case .always: break
        }
        let method = request.bytes[request.parsed.method].string()
        let status = response.parsed.statusCode
        let becomesGet =
            (status == 303 && method != "HEAD") || ((status == 301 || status == 302) && method == "POST")
        let newMethod = becomesGet ? "GET" : method
        var dropped: Set<String> = []
        if becomesGet { dropped = ["content-length", "content-type", "transfer-encoding"] }
        var cookies: [(String, String)] = []
        if policy.processCookies { cookies = setCookies(response) }

        var head = "\(newMethod) \(path) \(request.bytes[request.parsed.version].string())\r\n"
        let authority = authorityText(nextTarget)
        let changedAuthority = authority.lowercased() != authorityText(target).lowercased()
        var sawCookie = false
        for field in request.parsed.headers {
            let name = request.bytes[field.name].string()
            let lower = name.lowercased()
            if dropped.contains(lower) { continue }
            var value = request.bytes[field.value].string()
            if lower == "host", changedAuthority { value = authority }
            if lower == "cookie", !cookies.isEmpty {
                sawCookie = true
                value = merge(cookie: value, with: cookies)
            }
            head += "\(name): \(value)\r\n"
        }
        if !cookies.isEmpty, !sawCookie {
            head += "Cookie: " + cookies.map { "\($0.0)=\($0.1)" }.joined(separator: "; ") + "\r\n"
        }
        head += "\r\n"
        let all = request.bytes.rawBytes
        let bodyStart = request.parsed.headerBlockEnd
        let body = becomesGet || bodyStart >= all.count ? [] : Array(all[bodyStart...])
        return (RawRequest(Bytes(Array(head.utf8) + body)), nextTarget)
    }

    /// Resolve `location` against the request URL (absolute, scheme-relative, absolute-path or
    /// relative-path references; RFC 3986 §5.2, without dot-segment collapsing beyond `./`).
    static func resolve(
        _ location: String, from target: HTTPTarget, path currentPath: String
    ) -> (HTTPTarget, String)? {
        let lower = location.lowercased()
        if lower.hasPrefix("http://") || lower.hasPrefix("https://") {
            guard let next = HTTPTarget(url: location) else { return nil }
            return (next, pathPart(of: location))
        }
        if location.hasPrefix("//") {
            let url = target.scheme.rawValue + ":" + location
            guard let next = HTTPTarget(url: url) else { return nil }
            return (next, pathPart(of: url))
        }
        let same = target
        if location.hasPrefix("/") { return (same, location) }
        if location.hasPrefix("?") {
            let base = currentPath.split(separator: "?", maxSplits: 1).first.map(String.init) ?? "/"
            return (same, base + location)
        }
        // Relative path: replace the last segment of the current path.
        var base = currentPath.split(separator: "?", maxSplits: 1).first.map(String.init) ?? "/"
        if base.hasPrefix("http://") || base.hasPrefix("https://") { base = pathPart(of: base) }
        let lastSlash = base.lastIndex(of: "/") ?? base.startIndex
        let directory = base.hasSuffix("/") ? base : String(base[...lastSlash])
        var relative = location
        while relative.hasPrefix("./") { relative.removeFirst(2) }
        return (same, (directory.hasPrefix("/") ? directory : "/" + directory) + relative)
    }

    /// `/path?query` of an absolute URL (`/` when it has none); the fragment is dropped.
    static func pathPart(of url: String) -> String {
        guard let schemeEnd = url.range(of: "://") else { return url }
        let rest = url[schemeEnd.upperBound...]
        guard let start = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) else {
            return "/"
        }
        var path = String(rest[start...])
        if let hash = path.firstIndex(of: "#") { path = String(path[..<hash]) }
        if path.isEmpty || path.hasPrefix("?") { path = "/" + path }
        return path
    }

    static func authorityText(_ target: HTTPTarget) -> String {
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        return standard ? target.host : "\(target.host):\(target.port)"
    }

    /// `name=value` of each `Set-Cookie` in `response`.
    static func setCookies(_ response: RawResponse) -> [(String, String)] {
        response.parsed.headers.compactMap { field in
            guard response.bytes[field.name].string().lowercased() == "set-cookie" else { return nil }
            let pair = response.bytes[field.value].string().split(separator: ";", maxSplits: 1).first ?? ""
            guard let equals = pair.firstIndex(of: "=") else { return nil }
            let name = pair[..<equals].trimmedOf(" ")
            return name.isEmpty ? nil : (name, String(pair[pair.index(after: equals)...]))
        }
    }

    /// A `Cookie` value with `cookies` set (replacing same-named ones, keeping the others in order).
    static func merge(cookie: String, with cookies: [(String, String)]) -> String {
        var pairs: [(String, String)] = cookie.split(separator: ";").compactMap { piece in
            let trimmed = piece.trimmedOf(" ")
            guard let equals = trimmed.firstIndex(of: "=") else { return nil }
            return (String(trimmed[..<equals]), String(trimmed[trimmed.index(after: equals)...]))
        }
        for (name, value) in cookies {
            if let index = pairs.firstIndex(where: { $0.0 == name }) {
                pairs[index].1 = value
            } else {
                pairs.append((name, value))
            }
        }
        return pairs.map { "\($0.0)=\($0.1)" }.joined(separator: "; ")
    }
}

extension StringProtocol {
    /// Trim the given ASCII characters from both ends (no Foundation).
    fileprivate func trimmedOf(_ set: String) -> String {
        var s = Substring(self)
        while let f = s.first, set.contains(f) { s = s.dropFirst() }
        while let l = s.last, set.contains(l) { s = s.dropLast() }
        return String(s)
    }
}
