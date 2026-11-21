// GulpScanner — the SSO Workbench's OAuth 2.0 / OIDC analysis core (F25 SSO-001/003/004). The serious
// SSO bugs live in the *flow*, not in one token: a `redirect_uri` the authorization server over-accepts,
// a missing/replayable `state`, PKCE that downgrades to `plain`. This file reconstructs the flow from
// captured authorize/token traffic and derives the attack surface. It is pure and tested here; the
// macOS SSO tool (GulpFeatures) drives it, and the active probes it suggests go through ScopeGuard and
// the shared limiter before anything is sent. SAML lives in `SAMLWorkbench.swift`.

import Foundation

/// The OAuth 2.0 / OIDC grant type a flow uses (SSO-001).
public enum OAuthGrantType: String, Sendable, Equatable, CaseIterable {
    case authorizationCode = "authorization_code"
    case authorizationCodePKCE = "authorization_code+pkce"
    case implicit
    case hybrid
    case clientCredentials = "client_credentials"
    case deviceCode = "device_code"
    case unknown
}

/// A structured OAuth/OIDC authorization flow reconstructed from traffic (SSO-001).
public struct OAuthFlow: Sendable, Equatable {
    /// The grant type (inferred from `response_type` and PKCE when reconstructed from traffic).
    public var grantType: OAuthGrantType
    /// The `client_id` parameter.
    public var clientID: String?
    /// The `redirect_uri` parameter.
    public var redirectURI: String?
    /// The `scope` parameter.
    public var scope: String?
    /// The `state` parameter (CSRF protection).
    public var state: String?
    /// The `nonce` parameter (OIDC replay protection).
    public var nonce: String?
    /// The `response_type` parameter.
    public var responseType: String?
    /// The `response_mode` parameter.
    public var responseMode: String?
    /// The PKCE `code_challenge` parameter.
    public var codeChallenge: String?
    /// The PKCE `code_challenge_method` parameter (`S256` or `plain`).
    public var codeChallengeMethod: String?
    /// The authorize URL without its query.
    public var authorizeEndpoint: String?
    /// The token endpoint URL, when known.
    public var tokenEndpoint: String?
    /// The OIDC userinfo endpoint URL, when known.
    public var userinfoEndpoint: String?

    /// A flow; every field defaults to absent and the grant type to `.unknown`.
    public init(
        grantType: OAuthGrantType = .unknown, clientID: String? = nil, redirectURI: String? = nil,
        scope: String? = nil, state: String? = nil, nonce: String? = nil, responseType: String? = nil,
        responseMode: String? = nil, codeChallenge: String? = nil, codeChallengeMethod: String? = nil,
        authorizeEndpoint: String? = nil, tokenEndpoint: String? = nil, userinfoEndpoint: String? = nil
    ) {
        self.grantType = grantType
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scope = scope
        self.state = state
        self.nonce = nonce
        self.responseType = responseType
        self.responseMode = responseMode
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.authorizeEndpoint = authorizeEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.userinfoEndpoint = userinfoEndpoint
    }
}

/// A `redirect_uri` validation probe (SSO-003): a mutated callback URL and the attack class it tests.
public struct RedirectURIProbe: Sendable, Equatable {
    /// The `redirect_uri` validation weakness a probe tests.
    public enum Kind: String, Sendable, CaseIterable {
        case pathSuffix = "path-suffix"
        case pathTraversal = "path-traversal"
        case subdomain
        case siblingHost = "sibling-host"
        case atConfusion = "@-confusion"
        case openRedirectChain = "open-redirect-chain"
        case schemeDowngrade = "scheme-downgrade"
    }
    /// The attack class this probe tests.
    public let kind: Kind
    /// The mutated `redirect_uri` to send.
    public let value: String
    /// A probe.
    public init(kind: Kind, value: String) {
        self.kind = kind
        self.value = value
    }
}

/// A weakness in a flow's CSRF / code-injection protections (SSO-004).
public struct SSOProtectionFinding: Sendable, Equatable {
    /// The protection weakness found.
    public enum Kind: String, Sendable {
        case stateMissing = "state-missing"
        case stateStatic = "state-static"
        case pkceMissing = "pkce-missing"
        case pkcePlain = "pkce-plain"
        case nonceMissing = "nonce-missing"
    }
    /// The weakness found.
    public let kind: Kind
    /// A readable explanation for the report.
    public let detail: String
    /// A finding.
    public init(kind: Kind, detail: String) {
        self.kind = kind
        self.detail = detail
    }
}

/// The OAuth/OIDC analysis core (F25 SSO-001/003/004).
public enum SSOWorkbench {
    // MARK: Query parsing (own parser — no URL normalization, CLAUDE.md "raw bytes are the truth")

    /// Parse a URL's query string into ordered key/value pairs (percent-decoded). A value-less key maps
    /// to the empty string. `url` may be a full URL or a bare `a=b&c=d` query.
    public static func queryPairs(_ url: String) -> [(String, String)] {
        let query: Substring
        if let q = url.firstIndex(of: "?") {
            query = url[url.index(after: q)...]
        } else {
            query = Substring(url)
        }
        let body = query.split(separator: "#", maxSplits: 1).first ?? ""
        return body.split(separator: "&").map { pair in
            let kv = pair.split(separator: "=", maxSplits: 1)
            let key = percentDecode(String(kv[0]))
            let value = kv.count > 1 ? percentDecode(String(kv[1])) : ""
            return (key, value)
        }
    }

    /// The fragment (`#...`) of a URL, percent-decoded as a query (for implicit-flow token leakage).
    public static func fragmentPairs(_ url: String) -> [(String, String)] {
        guard let h = url.firstIndex(of: "#") else { return [] }
        return queryPairs("?" + url[url.index(after: h)...])
    }

    private static func percentDecode(_ s: String) -> String {
        s.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? s
    }

    private static func value(_ pairs: [(String, String)], _ key: String) -> String? {
        pairs.first { $0.0 == key }?.1
    }

    // MARK: SSO-001 — flow reconstruction

    /// Reconstruct the OAuth/OIDC flow from the authorize request URL (and, optionally, the token
    /// endpoint seen in traffic). Tolerates missing fields — reconstructs what is present.
    public static func reconstructOAuth(
        authorizeURL: String, tokenEndpoint: String? = nil, userinfoEndpoint: String? = nil
    ) -> OAuthFlow {
        let pairs = queryPairs(authorizeURL)
        let responseType = value(pairs, "response_type")
        let challenge = value(pairs, "code_challenge")
        var flow = OAuthFlow(
            clientID: value(pairs, "client_id"),
            redirectURI: value(pairs, "redirect_uri"),
            scope: value(pairs, "scope"),
            state: value(pairs, "state"),
            nonce: value(pairs, "nonce"),
            responseType: responseType,
            responseMode: value(pairs, "response_mode"),
            codeChallenge: challenge,
            codeChallengeMethod: value(pairs, "code_challenge_method"),
            authorizeEndpoint: authorizeURL.split(separator: "?", maxSplits: 1).first.map(String.init),
            tokenEndpoint: tokenEndpoint,
            userinfoEndpoint: userinfoEndpoint)
        flow.grantType = grantType(responseType: responseType, hasPKCE: challenge?.isEmpty == false)
        return flow
    }

    /// Classify the grant type from `response_type` and whether PKCE is present (SSO-001).
    public static func grantType(responseType: String?, hasPKCE: Bool) -> OAuthGrantType {
        guard let rt = responseType?.trimmingCharacters(in: .whitespaces), !rt.isEmpty else {
            return .unknown
        }
        let parts = Set(rt.split(separator: " ").map(String.init))
        if parts == ["code"] { return hasPKCE ? .authorizationCodePKCE : .authorizationCode }
        if parts == ["token"] || parts == ["id_token", "token"] || parts == ["id_token"] {
            return .implicit
        }
        if parts.contains("code") && (parts.contains("token") || parts.contains("id_token")) {
            return .hybrid
        }
        return .unknown
    }

    // MARK: SSO-003 — redirect_uri validation probes

    /// Generate `redirect_uri` mutation probes from the registered value (SSO-003). The caller sends
    /// each (scope-gated) and feeds the acceptances back to `acceptedRedirects`.
    public static func redirectProbes(for redirectURI: String, attackerHost: String = "evil.example")
        -> [RedirectURIProbe]
    {
        guard let parsed = splitURL(redirectURI) else { return [] }
        let base = "\(parsed.scheme)://\(parsed.host)\(parsed.path)"
        var probes: [RedirectURIProbe] = [
            .init(kind: .pathSuffix, value: base + "/../evil"),
            .init(kind: .pathTraversal, value: base + "/%2e%2e/evil"),
            .init(kind: .subdomain, value: "\(parsed.scheme)://\(attackerHost).\(parsed.host)\(parsed.path)"),
            .init(
                kind: .siblingHost, value: "\(parsed.scheme)://\(parsed.host).\(attackerHost)\(parsed.path)"),
            .init(
                kind: .atConfusion, value: "\(parsed.scheme)://\(parsed.host)@\(attackerHost)\(parsed.path)"),
            .init(kind: .openRedirectChain, value: base + "?next=https://\(attackerHost)/"),
        ]
        if parsed.scheme == "https" {
            probes.append(.init(kind: .schemeDowngrade, value: "http://\(parsed.host)\(parsed.path)"))
        }
        return probes
    }

    /// Given the registered `redirect_uri` and the set of mutated values the AS accepted (e.g. returned
    /// a code to), report the accepted probes — anything other than an exact match is a finding (SSO-003).
    public static func overAcceptedRedirects(registered: String, accepted: [String]) -> [RedirectURIProbe] {
        let probes = redirectProbes(for: registered)
        let acceptedSet = Set(accepted)
        return probes.filter { acceptedSet.contains($0.value) }
    }

    private static func splitURL(_ url: String) -> (scheme: String, host: String, path: String)? {
        guard let schemeEnd = url.range(of: "://") else { return nil }
        let scheme = String(url[url.startIndex..<schemeEnd.lowerBound])
        let rest = url[schemeEnd.upperBound...]
        let hostEnd = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? rest.endIndex
        let host = String(rest[rest.startIndex..<hostEnd])
        let pathPart = rest[hostEnd...]
        let path =
            String(pathPart.split(separator: "?", maxSplits: 1).first ?? "").isEmpty
            ? "" : String(pathPart.prefix(while: { $0 != "?" && $0 != "#" }))
        guard !scheme.isEmpty, !host.isEmpty else { return nil }
        return (scheme, host, path)
    }

    // MARK: SSO-004 — state / PKCE / nonce protections

    /// Analyse a flow (optionally across repeated authorize requests) for CSRF / code-injection
    /// weaknesses (SSO-004). `priorStates` are `state` values seen on earlier authorize requests to the
    /// same client — a repeated value means `state` is static (replayable).
    public static func protectionFindings(_ flow: OAuthFlow, priorStates: [String] = [])
        -> [SSOProtectionFinding]
    {
        var findings: [SSOProtectionFinding] = []
        let needsState =
            flow.grantType == .authorizationCode
            || flow.grantType == .authorizationCodePKCE || flow.grantType == .implicit
            || flow.grantType == .hybrid
        if needsState {
            if (flow.state ?? "").isEmpty {
                findings.append(
                    .init(kind: .stateMissing, detail: "No `state` on the authorize request — CSRF-exposed."))
            } else if let s = flow.state, priorStates.contains(s) {
                findings.append(
                    .init(
                        kind: .stateStatic,
                        detail: "`state` repeats a prior value (`\(s)`) — static/replayable, not CSRF-safe."))
            }
        }
        let isCodeFlow = flow.grantType == .authorizationCode || flow.grantType == .authorizationCodePKCE
        if isCodeFlow {
            let method = (flow.codeChallengeMethod ?? "").uppercased()
            if (flow.codeChallenge ?? "").isEmpty {
                findings.append(
                    .init(kind: .pkceMissing, detail: "No PKCE on a code flow — code-injection-exposed."))
            } else if method == "PLAIN" || (!method.isEmpty && method != "S256") {
                findings.append(
                    .init(
                        kind: .pkcePlain,
                        detail: "PKCE uses `\(flow.codeChallengeMethod ?? "")` not `S256` — downgradeable."))
            }
        }
        if (flow.grantType == .implicit || flow.grantType == .hybrid), (flow.nonce ?? "").isEmpty {
            findings.append(
                .init(kind: .nonceMissing, detail: "No `nonce` on an implicit/hybrid flow — ID-token replay.")
            )
        }
        return findings
    }
}
