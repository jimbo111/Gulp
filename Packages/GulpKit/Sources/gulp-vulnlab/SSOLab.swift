// gulp-vulnlab — OIDC authorization-server fixtures for the SSO Workbench DoD (F25 SSO-003/004). The
// vulnerable `/authorize` validates `redirect_uri` by prefix (so `/callback/../evil` and sibling hosts
// slip through) and accepts `code_challenge_method=plain`; the `/safe/authorize` twin requires an exact
// registered `redirect_uri` and `S256` PKCE. On accept it 302-redirects to the callback with a `code`;
// on reject it returns 400. A minimal discovery document backs SSO-007.

import Foundation
import GulpCore

enum SSOLab {
    /// The one registered callback the client app uses.
    static let registeredRedirect = "http://127.0.0.1:8088/callback"
    static let issuer = "http://127.0.0.1:8088"

    static func respond(_ request: RawRequest, path: String, query: [String: String]) -> VulnReply? {
        switch path {
        case "/.well-known/openid-configuration", "/safe/.well-known/openid-configuration":
            // Advertises S256 PKCE support (SSO-007); the vulnerable AS advertises but does not enforce it.
            let body = """
                {"issuer":"\(issuer)","authorization_endpoint":"\(issuer)/authorize",\
                "token_endpoint":"\(issuer)/token","userinfo_endpoint":"\(issuer)/userinfo",\
                "jwks_uri":"\(issuer)/jwks","code_challenge_methods_supported":["S256"],\
                "response_types_supported":["code"]}
                """
            return VulnReply(
                bytes: VulnLab.response(200, body: Array(body.utf8), type: "application/json"))

        case "/authorize", "/safe/authorize":
            let safe = path.hasPrefix("/safe/")
            let redirect = query["redirect_uri"] ?? ""
            let state = query["state"] ?? ""
            let method = (query["code_challenge_method"] ?? "").uppercased()
            let hasChallenge = !(query["code_challenge"] ?? "").isEmpty

            // redirect_uri validation: safe = exact; vulnerable = prefix match (the classic bug).
            let redirectOK = safe ? (redirect == registeredRedirect) : redirect.hasPrefix(registeredRedirect)
            // PKCE: safe requires S256; vulnerable accepts plain (or none).
            let pkceOK = safe ? (hasChallenge && method == "S256") : true

            guard redirectOK else {
                return reject("invalid redirect_uri")
            }
            guard pkceOK else {
                return reject("PKCE required (S256)")
            }
            // Accept: issue a code to the (possibly attacker-controlled) redirect_uri.
            let sep = redirect.contains("?") ? "&" : "?"
            let location =
                "\(redirect)\(sep)code=AUTH_\(abs(redirect.hashValue) % 100000)"
                + (state.isEmpty ? "" : "&state=\(state)")
            return VulnReply(bytes: VulnLab.response(302, body: [], headers: ["Location: \(location)"]))

        default:
            return nil
        }
    }

    private static func reject(_ reason: String) -> VulnReply {
        VulnReply(
            bytes: VulnLab.response(
                400, body: Array("{\"error\":\"invalid_request\",\"detail\":\"\(reason)\"}".utf8),
                type: "application/json"))
    }
}
