// gulp-cli — the SSO Workbench's headless surface (F25). `sso analyze` reconstructs an OAuth/OIDC flow
// from an authorize URL and reports its grant type and protection weaknesses (offline, SSO-001/004).
// `sso probe` sends the redirect_uri and PKCE variants against a live authorization server and reports
// which it accepts (SSO-003/004) — the operator-supplied `--target` is the authorization, as for the
// other active CLI probes (pollute, smuggle).

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpScanner

struct SSO: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sso",
        abstract: "Reconstruct and attack OAuth2/OIDC SSO flows (F25).",
        subcommands: [Analyze.self, Probe.self])

    /// `gulp sso analyze --authorize "<authorize url>"`
    struct Analyze: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Reconstruct an OAuth/OIDC flow from an authorize URL and list protection weaknesses.")
        @Option(help: "The full authorize-endpoint URL (with its query).") var authorize: String
        @Option(help: "The token endpoint, if known.") var token: String?

        func run() async throws {
            let flow = SSOWorkbench.reconstructOAuth(authorizeURL: authorize, tokenEndpoint: token)
            print("grant: \(flow.grantType.rawValue)")
            print("client_id: \(flow.clientID ?? "-")")
            print("redirect_uri: \(flow.redirectURI ?? "-")")
            print("scope: \(flow.scope ?? "-")")
            print("state: \(flow.state ?? "-")  pkce: \(flow.codeChallengeMethod ?? "none")")
            let findings = SSOWorkbench.protectionFindings(flow)
            if findings.isEmpty {
                print("protections: ok")
            } else {
                for f in findings { print("weakness \(f.kind.rawValue): \(f.detail)") }
            }
        }
    }

    /// `gulp sso probe --authorize "<url>" --target http://host`
    struct Probe: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Send redirect_uri and PKCE variants at a live AS and report what it accepts.")
        @Option(help: "A baseline authorize URL (valid redirect_uri + S256 PKCE).") var authorize: String
        @Option(help: "Where the probes go (the authorization server).") var target: String

        func run() async throws {
            guard let destination = HTTPTarget(url: target) else {
                throw ValidationError("Invalid --target \(target)")
            }
            let flow = SSOWorkbench.reconstructOAuth(authorizeURL: authorize)
            guard let redirect = flow.redirectURI, !redirect.isEmpty else {
                throw ValidationError("The authorize URL has no redirect_uri.")
            }
            let defaultPort = destination.scheme == .https ? 443 : 80
            let host = destination.port == defaultPort
                ? destination.host : "\(destination.host):\(destination.port)"
            let authorizePath = flow.authorizeEndpoint.flatMap { URLPath($0) } ?? "/authorize"

            let engine = NIOHTTPEngine()
            defer { Task { await engine.shutdown() } }
            let options = SendOptions(recordAs: .automation)

            /// Send an authorize request with these query pairs; return (accepted, location).
            func authorizeRequest(_ pairs: [(String, String)]) async -> (accepted: Bool, location: String) {
                let qs = pairs.map { "\($0.0)=\(encode($0.1))" }.joined(separator: "&")
                let raw = "GET \(authorizePath)?\(qs) HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n"
                let result = await engine.send(RawRequest(Bytes(raw)), to: destination, options: options)
                guard let response = result.exchange.response else { return (false, "") }
                let location = response.headerValue("location")?.string() ?? ""
                // Accepted = a redirect carrying an authorization code.
                return (response.parsed.statusCode == 302 && location.contains("code="), location)
            }

            func base(redirect: String, method: String?) -> [(String, String)] {
                var pairs: [(String, String)] = [
                    ("response_type", "code"), ("client_id", flow.clientID ?? "app"),
                    ("redirect_uri", redirect), ("state", "s1"),
                ]
                if let method {
                    pairs.append(("code_challenge", "abc123"))
                    pairs.append(("code_challenge_method", method))
                }
                return pairs
            }

            // SSO-003: redirect_uri matrix (baseline PKCE held at S256).
            print("sso probe: redirect_uri variants")
            let registeredAccepted = await authorizeRequest(base(redirect: redirect, method: "S256")).accepted
            print("  [registered] \(redirect) → \(registeredAccepted ? "accepted" : "rejected")")
            var overAccepted: [RedirectURIProbe] = []
            for probe in SSOWorkbench.redirectProbes(for: redirect) {
                let r = await authorizeRequest(base(redirect: probe.value, method: "S256"))
                print("  [\(probe.kind.rawValue)] \(probe.value) → \(r.accepted ? "ACCEPTED" : "rejected")")
                if r.accepted { overAccepted.append(probe) }
            }
            if overAccepted.isEmpty {
                print("redirect_uri: strict (only the exact registered value accepted)")
            } else {
                print("redirect_uri: OVER-ACCEPTS \(overAccepted.count) variant(s) — \(overAccepted.map(\.kind.rawValue).joined(separator: ", "))")
            }

            // SSO-004: PKCE downgrade (S256 → plain → none), redirect held at the registered value.
            print("sso probe: PKCE enforcement")
            let plain = await authorizeRequest(base(redirect: redirect, method: "plain")).accepted
            let none = await authorizeRequest(base(redirect: redirect, method: nil)).accepted
            print("  method=plain → \(plain ? "ACCEPTED" : "rejected")")
            print("  no PKCE → \(none ? "ACCEPTED" : "rejected")")
            if plain || none {
                print("pkce: DOWNGRADEABLE (plain or none accepted)")
            } else {
                print("pkce: enforced (S256 required)")
            }
        }

        private func encode(_ s: String) -> String {
            s.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? s
        }

        /// The path of a URL (everything from the first `/` after the host).
        private func URLPath(_ url: String) -> String? {
            guard let schemeEnd = url.range(of: "://") else { return url.hasPrefix("/") ? url : nil }
            let rest = url[schemeEnd.upperBound...]
            guard let slash = rest.firstIndex(of: "/") else { return "/" }
            return String(rest[slash...])
        }
    }
}
