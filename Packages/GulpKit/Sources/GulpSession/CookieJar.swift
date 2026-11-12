// GulpSession — a per-project cookie jar (F15 SES-001). Cookies seen in tool/proxy responses are
// stored with their attributes (domain, path, Secure, HttpOnly, SameSite, expiry); a request to a
// host is given the cookies that match it (RFC 6265 domain/path/secure rules). The jar is a value
// type so it is easy to snapshot, partition per identity (SES-002) and test on Linux; the workspace
// persists it. Parsing follows RFC 6265 §5.2 closely enough for testing real apps, not every edge.

import Foundation
import GulpCore

/// One stored cookie (RFC 6265).
public struct StoredCookie: Sendable, Hashable, Codable {
    /// Name.
    public var name: String
    /// Value (as received; not decoded).
    public var value: String
    /// The host that may receive it. A leading dot (or `hostOnly == false`) means subdomains too.
    public var domain: String
    /// Path prefix it is sent to.
    public var path: String
    /// Only over HTTPS.
    public var secure: Bool
    /// Not readable from JavaScript (informational here).
    public var httpOnly: Bool
    /// `Strict`, `Lax`, `None` or nil.
    public var sameSite: String?
    /// Absolute expiry; nil is a session cookie (kept until cleared).
    public var expires: Date?
    /// Set only for an exact host (no `Domain` attribute): subdomains don't match.
    public var hostOnly: Bool
    /// When it was stored or last updated (RFC 6265 creation-time, for ordering).
    public var created: Date

    /// A cookie.
    public init(
        name: String, value: String, domain: String, path: String, secure: Bool = false,
        httpOnly: Bool = false, sameSite: String? = nil, expires: Date? = nil, hostOnly: Bool = true,
        created: Date = Date()
    ) {
        self.name = name
        self.value = value
        self.domain = domain.lowercased()
        self.path = path
        self.secure = secure
        self.httpOnly = httpOnly
        self.sameSite = sameSite
        self.expires = expires
        self.hostOnly = hostOnly
        self.created = created
    }

    /// RFC 6265 identity: same name, domain and path replace each other.
    var key: String { "\(domain)\t\(path)\t\(name)" }
}

/// A cookie jar (SES-001).
public struct CookieJar: Sendable, Hashable, Codable {
    /// Every stored cookie.
    public private(set) var cookies: [StoredCookie]

    /// An empty jar.
    public init(cookies: [StoredCookie] = []) { self.cookies = cookies }

    /// Store `cookie`, replacing any with the same name, domain and path (RFC 6265 §5.3).
    public mutating func store(_ cookie: StoredCookie) {
        if let index = cookies.firstIndex(where: { $0.key == cookie.key }) {
            var updated = cookie
            updated.created = cookies[index].created  // keep original creation time (RFC 6265)
            cookies[index] = updated
        } else {
            cookies.append(cookie)
        }
    }

    /// Record every `Set-Cookie` of a response received from `host` over `scheme` (SES-001). A
    /// cookie that expired in the past (`Max-Age<=0` or a past `Expires`) deletes its match instead.
    public mutating func store(setCookies: [String], from host: String, now: Date = Date()) {
        for header in setCookies {
            guard let parsed = Self.parse(header, host: host, now: now) else { continue }
            if let expiry = parsed.expires, expiry <= now {
                cookies.removeAll { $0.key == parsed.key }
            } else {
                store(parsed)
            }
        }
    }

    /// Drop expired cookies (SES-001 housekeeping).
    public mutating func removeExpired(now: Date = Date()) {
        cookies.removeAll { $0.expires.map { $0 <= now } ?? false }
    }

    /// Delete every cookie.
    public mutating func clear() { cookies.removeAll() }

    /// Delete the cookie with this name/domain/path.
    public mutating func remove(name: String, domain: String, path: String) {
        let key = "\(domain.lowercased())\t\(path)\t\(name)"
        cookies.removeAll { $0.key == key }
    }

    /// The `Cookie` header value for a request to `host`/`path` over `scheme`, or nil when no cookie
    /// matches (RFC 6265 §5.4: secure-only over HTTPS, domain- and path-match, longest path first).
    public func header(host: String, path: String, scheme: Scheme, now: Date = Date()) -> String? {
        let matches = cookies.filter {
            Self.domainMatches(host: host.lowercased(), cookie: $0)
                && Self.pathMatches(requestPath: path, cookiePath: $0.path)
                && (!$0.secure || scheme == .https)
                && ($0.expires.map { $0 > now } ?? true)
        }
        .sorted {
            $0.path.count != $1.path.count ? $0.path.count > $1.path.count : $0.created < $1.created
        }
        guard !matches.isEmpty else { return nil }
        return matches.map { "\($0.name)=\($0.value)" }.joined(separator: "; ")
    }

    // MARK: matching

    static func domainMatches(host: String, cookie: StoredCookie) -> Bool {
        if cookie.hostOnly { return host == cookie.domain }
        return host == cookie.domain || host.hasSuffix("." + cookie.domain)
    }

    static func pathMatches(requestPath: String, cookiePath: String) -> Bool {
        let request = requestPath.split(separator: "?", maxSplits: 1).first.map(String.init) ?? requestPath
        if request == cookiePath { return true }
        guard request.hasPrefix(cookiePath) else { return false }
        return cookiePath.hasSuffix("/") || request.dropFirst(cookiePath.count).hasPrefix("/")
    }

    // MARK: parsing

    /// Parse one `Set-Cookie` header value for a response from `host` (RFC 6265 §5.2).
    public static func parse(_ header: String, host: String, now: Date = Date()) -> StoredCookie? {
        var parts = header.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
        guard !parts.isEmpty else { return nil }
        let pair = parts.removeFirst()
        guard let equals = pair.firstIndex(of: "=") else { return nil }
        let name = String(pair[..<equals]).trimmingCharacters(in: .whitespaces)
        let value = String(pair[pair.index(after: equals)...])
        guard !name.isEmpty else { return nil }

        var domain = host.lowercased()
        var hostOnly = true
        var path = "/"
        var secure = false
        var httpOnly = false
        var sameSite: String?
        var expires: Date?
        var maxAge: Int?
        for attribute in parts {
            let lower = attribute.lowercased()
            if lower == "secure" {
                secure = true
            } else if lower == "httponly" {
                httpOnly = true
            } else if let equals = attribute.firstIndex(of: "=") {
                let key = attribute[..<equals].trimmingCharacters(in: .whitespaces).lowercased()
                let v = String(attribute[attribute.index(after: equals)...]).trimmingCharacters(
                    in: .whitespaces)
                switch key {
                case "domain" where !v.isEmpty:
                    domain = v.hasPrefix(".") ? String(v.dropFirst()) : v
                    domain = domain.lowercased()
                    hostOnly = false
                case "path" where v.hasPrefix("/"):
                    path = v
                case "samesite":
                    sameSite = v.capitalized
                case "max-age":
                    maxAge = Int(v)
                case "expires":
                    expires = parseDate(v)
                default:
                    break
                }
            }
        }
        // Max-Age wins over Expires (RFC 6265 §5.2.2).
        if let maxAge { expires = now.addingTimeInterval(TimeInterval(maxAge)) }
        // Domain must domain-match the host (RFC 6265 §5.3.6); otherwise reject the attribute.
        if !hostOnly, !(host.lowercased() == domain || host.lowercased().hasSuffix("." + domain)) {
            domain = host.lowercased()
            hostOnly = true
        }
        return StoredCookie(
            name: name, value: value, domain: domain, path: path, secure: secure, httpOnly: httpOnly,
            sameSite: sameSite, expires: expires, hostOnly: hostOnly, created: now)
    }

    static let dateFormats = [
        "EEE, dd-MMM-yyyy HH:mm:ss zzz", "EEE, dd MMM yyyy HH:mm:ss zzz", "EEE, dd-MMM-yy HH:mm:ss zzz",
        "EEE MMM d HH:mm:ss yyyy",
    ]

    static func parseDate(_ text: String) -> Date? {
        for format in dateFormats {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(identifier: "GMT")
            formatter.dateFormat = format
            if let date = formatter.date(from: text) { return date }
        }
        return nil
    }
}
