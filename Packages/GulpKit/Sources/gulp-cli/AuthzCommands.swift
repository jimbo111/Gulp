// gulp-cli — the Authorization Matrix headless (F23 ADV-001…003, M12b): `authz orders` logs in two
// users, builds identities from their session cookies, and replays a set of requests as each,
// printing the verdict grid and raising access-control issues for bypasses.

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpSession
import GulpWorkspace

struct AuthzCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "authz", abstract: "Authorization Matrix: replay requests as several identities (F23).",
        subcommands: [Orders.self])

    /// Log a VulnLab user in and return their session cookie value.
    static func login(
        _ session: ProjectSession, base: HTTPTarget, host: String, user: String, password: String
    ) async -> String? {
        let get = await SessionCommand.send(
            session, raw: Array("GET /login HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8), target: base)
        guard
            let csrf = get.body.range(of: #"name="csrf" value="([^"]+)""#, options: .regularExpression)
                .map({ String(get.body[$0]) })?.components(separatedBy: "\"").dropLast().last
        else { return nil }
        let body = "username=\(user)&password=\(password)&csrf=\(csrf)"
        let raw =
            "POST /login HTTP/1.1\r\nHost: \(host)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
        let engine = session.http
        var options = SendOptions(recordAs: .session)
        options.applyHooks = []
        let result = await engine.send(RawRequest(Bytes(Array(raw.utf8))), to: base, options: options)
        for header in result.exchange.response?.headerValues("set-cookie").map({ $0.string() }) ?? [] {
            if let cookie = CookieJar.parse(header, host: base.host), cookie.name == "session" {
                return cookie.value
            }
        }
        return nil
    }

    struct Orders: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Demo the matrix on VulnLab's order endpoints (IDOR vs the enforcing twin).")
        @Option(help: "Project file (created if missing).") var project: String
        @Option(help: "Base URL, e.g. http://127.0.0.1:8088.") var base: String

        func run() async throws {
            guard let destination = HTTPTarget(url: base) else { throw ValidationError("Invalid --base") }
            let host = destination.hostHeader
            let session = try await ProjectSession.open(at: URL(fileURLWithPath: project))

            // Log in bob (owns order 2) and alice (owns order 1).
            guard
                let bobSession = await AuthzCommand.login(
                    session, base: destination, host: host, user: "bob", password: "builder"),
                let aliceSession = await AuthzCommand.login(
                    session, base: destination, host: host, user: "alice", password: "wonderland")
            else { throw ValidationError("couldn't log the demo users in") }

            var bob = Identity(name: "bob")
            bob.cookies.store(setCookies: ["session=\(bobSession); Path=/"], from: destination.host)
            var alice = Identity(name: "alice")
            alice.cookies.store(setCookies: ["session=\(aliceSession); Path=/"], from: destination.host)
            // bob is the authorized owner of order 2; alice and the unauthenticated user are the testers.
            try await session.setSessionSettings(
                SessionSettings(identities: [bob, alice], activeIdentity: bob.id))

            func request(_ path: String) -> (RawRequest, HTTPTarget) {
                (RawRequest(Bytes(Array("GET \(path) HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8))), destination)
            }
            let paths = ["/api/orders/2", "/safe/api/orders/2"]
            let matrix = try await session.runAuthzMatrix(paths.map(request), authorizedIdentity: bob.id)

            let columnNames = matrix.columns.map { id in
                id.flatMap { cid in [bob, alice].first { $0.id == cid }?.name } ?? "unauth"
            }
            print("authz: request\t" + columnNames.joined(separator: "\t"))
            for (index, label) in matrix.requests.enumerated() {
                let cells = matrix.columns.map {
                    matrix.cell(request: index, identity: $0)?.verdict.rawValue ?? "-"
                }
                print("\(label)\t" + cells.joined(separator: "\t"))
            }
            print("authz: \(matrix.issuesRaised.count) access-control issue(s) raised")
            try await session.close()
        }
    }
}
