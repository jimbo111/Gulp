// gulp-cli — the session layer headless (F15 M12a): `session sign` configures a signing session
// action and sends a request through the engine so the session hooks sign it (SES-016…018);
// `session reauth` configures a login macro + validity rule and shows that requests to an
// authenticated area stay logged in across session expiry (SES-012/020). Both print a status line.

import ArgumentParser
import Foundation
import GulpCodec
import GulpCore
import GulpHTTP
import GulpSession
import GulpWorkspace

struct SessionCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "session",
        abstract: "Session handling: request signing and login-macro re-authentication (F15).",
        subcommands: [Sign.self, Reauth.self])

    /// Send a request to `target` through a project's engine as Repeater traffic and return the
    /// response status (so the session hooks run). The raw request has its Content-Length fixed.
    static func send(_ session: ProjectSession, raw: [UInt8], target: HTTPTarget) async -> (
        status: Int, body: String
    ) {
        var options = SendOptions(recordAs: .repeater)
        options.updateContentLength = true
        options.timeouts.total = .seconds(30)
        let result = await session.http.send(RawRequest(Bytes(raw)), to: target, options: options)
        let response = result.exchange.response
        let body =
            response.map { String(decoding: $0.bytes.rawBytes[$0.parsed.body], as: UTF8.self) }
            ?? (result.error?.code ?? "no response")
        return (response?.parsed.statusCode ?? 0, body)
    }

    struct Sign: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Sign a request with a session action (dpop, http-sig or sigv4) and send it.")
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "File holding the exact request bytes.") var raw: String
        @Option(help: "Where to connect, e.g. http://127.0.0.1:8088.") var target: String
        @Option(help: "Signing scheme: dpop, http-sig or sigv4.") var scheme: String
        @Option(help: "HMAC key for http-sig (default matches VulnLab).") var hmacKey = "http-sig-secret"
        @Option(help: "AWS access key for sigv4.") var accessKey = "GULPACCESSKEY"
        @Option(help: "AWS secret key for sigv4.") var secretKey = "gulp/secret/key/EXAMPLEEXAMPLEEXAMPLE"
        @Option(help: "AWS region.") var region = "us-east-1"
        @Option(help: "AWS service.") var service = "execute-api"
        @Flag(help: "Send without configuring signing (the 'fails without it' case).") var noSign = false

        func signingScheme() throws -> SigningScheme {
            switch scheme {
            case "dpop":
                let key = try JWTKey.generate(for: "ES256")
                guard case .ecPrivate(let curve, let privateRaw) = key else {
                    throw ValidationError("key error")
                }
                return .dpop(secret: .ec(curve: curve, privateRaw: privateRaw))
            case "http-sig":
                return .httpMessageSignature(
                    secret: .hmac(Array(hmacKey.utf8)), algorithm: "hmac-sha256", keyID: "gulp-key",
                    components: ["@method", "@target-uri", "content-digest"])
            case "sigv4":
                return .sigV4(
                    secret: .aws(accessKey: accessKey, secretKey: secretKey, sessionToken: nil),
                    region: region,
                    service: service)
            default: throw ValidationError("Unknown --scheme \(scheme) (dpop, http-sig, sigv4)")
            }
        }

        func run() async throws {
            guard let data = FileManager.default.contents(atPath: raw) else {
                throw ValidationError("Cannot read \(raw)")
            }
            guard let destination = HTTPTarget(url: target) else { throw ValidationError("Invalid --target") }
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))
            if !noSign {
                let rule = SessionRule(
                    name: "sign \(scheme)", scope: RuleScope(hostGlob: destination.host),
                    actions: [.sign(try signingScheme())])
                try await session.setSessionSettings(SessionSettings(rules: [rule]))
            }
            // DPoP demands a nonce on the first try; the signer reads DPoP-Nonce from the first
            // response and the retry carries it (SES-016).
            var result = await SessionCommand.send(session, raw: [UInt8](data), target: destination)
            // DPoP demands a nonce on the first try; the retry carries it (SES-016). Only when signing.
            if !noSign, result.status == 401, scheme == "dpop" {
                result = await SessionCommand.send(session, raw: [UInt8](data), target: destination)
            }
            print(
                "session sign (\(noSign ? "no signature" : scheme)): \(result.status) \(result.body.trimmingCharacters(in: .newlines))"
            )
            try await session.close()
            // Signing must succeed; without it the fixture must reject (the DoD greps the printed line).
            if !noSign, result.status != 200 { throw ExitCode(1) }
        }
    }

    struct Reauth: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Configure a login macro + validity rule and keep an authenticated area logged in.")
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "Base URL, e.g. http://127.0.0.1:8088.") var base: String
        @Option(help: "Username.") var username = "alice"
        @Option(help: "Password.") var password = "wonderland"
        @Option(help: "Protected path to fetch.") var path = "/account"
        @Option(help: "Path that expires the session between fetches (optional).") var expire: String?

        func run() async throws {
            guard let destination = HTTPTarget(url: base) else { throw ValidationError("Invalid --base") }
            let host = destination.hostHeader
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))

            // Macro: GET /login (capture csrf), POST /login with the carried cookie and csrf.
            let getLogin = MacroStep(
                request: Array("GET /login HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8), target: destination,
                extractions: [
                    MacroExtraction(variable: "csrf", from: .regex(#"name="csrf" value="([^"]+)""#))
                ])
            let body = "username=${username}&password=${password}&csrf=${csrf}"
            let postLogin = MacroStep(
                request: Array(
                    "POST /login HTTP/1.1\r\nHost: \(host)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n\(body)"
                        .utf8),
                target: destination)
            let macro = Macro(name: "login", steps: [getLogin, postLogin])
            var identity = Identity(name: username, variables: ["username": username, "password": password])
            identity.loginMacro = macro.id
            let rule = SessionRule(
                name: "stay logged in", scope: RuleScope(hostGlob: destination.host, pathPrefix: path),
                identity: identity.id,
                actions: [
                    .checkValidity(ValidityCheck(redirectContains: "/login", bodyAbsent: "Please log in")),
                    .useCookies,
                ])
            try await session.setSessionSettings(
                SessionSettings(
                    identities: [identity], rules: [rule], macros: [macro], activeIdentity: identity.id))
            // Force an initial re-auth by marking the session stale.
            await session.sessionState.markStale(identity.id)

            func fetch() async -> Int {
                await SessionCommand.send(
                    session, raw: Array("GET \(path) HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8),
                    target: destination
                ).status
            }
            let first = await fetch()
            print("reauth: first fetch of \(path) → \(first)")
            if let expire {
                _ = await SessionCommand.send(
                    session, raw: Array("GET \(expire) HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8),
                    target: destination)
                await session.sessionState.markStale(identity.id)
                let second = await fetch()
                print("reauth: after expiry, fetch of \(path) → \(second)")
                try await session.close()
                if first != 200 || second != 200 { throw ExitCode(1) }
                return
            }
            try await session.close()
            if first != 200 { throw ExitCode(1) }
        }
    }
}
