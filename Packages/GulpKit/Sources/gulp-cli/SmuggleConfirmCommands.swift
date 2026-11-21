// gulp-cli — Smuggling confirmation workbench (F23 ADV-032). Constructs a desync confirmation (an
// attack that poisons the next request on its back-end connection — the tester's follow-up, or
// another user's on a shared connection — plus an innocuous follow-up whose poisoned response proves
// the desync), with prominent warnings and scope gating. It is a DRY RUN by default and NEVER sends
// automatically: an actual send needs both an in-scope target and an explicit authorization flag.

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpScanner

/// `gulp-cli smuggle-confirm --raw req.txt --target http://host --vector CL.TE [--i-am-authorized]`
struct SmuggleConfirm: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "smuggle-confirm",
        abstract: "Construct a scope-gated, non-destructive desync confirmation (dry run by default).")

    @Option(help: "A raw request file giving the target path and Host.") var raw: String
    @Option(help: "Where the confirmation would go, e.g. http://127.0.0.1:8088.") var target: String
    @Option(help: "The vector to confirm: CL.TE or TE.CL.") var vector = "CL.TE"
    @Option(help: "The host that is in scope for this test (default: the target's host).")
    var scopeHost: String?
    @Flag(
        help:
            "Explicitly authorize sending the confirmation. Without this, nothing is sent (dry run).")
    var iAmAuthorized = false

    func run() async throws {
        guard let data = FileManager.default.contents(atPath: raw) else {
            throw ValidationError("Cannot read \(raw)")
        }
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        guard let vector = SmugglingVector(rawValue: vector) else {
            let names = SmugglingVector.allCases.map(\.rawValue).joined(separator: ", ")
            throw ValidationError("--vector must be one of: \(names)")
        }
        let base = RawRequest(Bytes([UInt8](data)))
        let confirmation = SmugglingProbe.confirmation(vector, base: base)

        print("================ SMUGGLING CONFIRMATION (ADV-032) ================")
        print("!! WARNING: request smuggling can corrupt live traffic and break sites.")
        print("!! Only run against systems you are explicitly authorized to test.")
        print("!! The smuggled prefix poisons the NEXT request on that back-end connection, which can be")
        print("!! another user's when the front-end shares back-end connections between clients.")
        print("vector: \(vector.rawValue)")
        print("expected signal: \(confirmation.expectedSignal)")
        print("--- attack request (smuggles a \(SmugglingProbe.confirmationMethod) request-start) ---")
        print(confirmation.attack.bytes.string().replacingOccurrences(of: "\r", with: "\\r"))
        print("--- follow-up request (its poisoned response proves the desync) ---")
        print(confirmation.followUp.bytes.string().replacingOccurrences(of: "\r", with: "\\r"))

        // Scope gating: the destination must be in the named scope.
        let host = scopeHost ?? destination.host
        let scope = ScopeService(rules: [ScopeRule(host: host)])
        let targetPath = base.bytes[base.parsed.target].string()
        let inScope = scope.isInScope(destination, path: targetPath.isEmpty ? "/" : targetPath)

        guard iAmAuthorized else {
            print("DRY RUN: nothing was sent. Re-run with --i-am-authorized to send (scope permitting).")
            return
        }
        guard inScope else {
            print("REFUSED: \(destination.host) is not in scope (\(host)); the confirmation was not sent.")
            return
        }

        print("SENDING confirmation (authorized, in scope) …")
        let engine = ScopedSender(scope: .pinned(destination))
        defer { Task { await engine.shutdown() } }
        var options = SendOptions(recordAs: .automation)
        options.timeouts.total = .seconds(20)
        _ = try await engine.send(confirmation.attack, to: destination, options: options)
        let followResult = try await engine.send(confirmation.followUp, to: destination, options: options)
        let status = followResult.exchange.response?.parsed.statusCode
        print("follow-up status: \(status.map(String.init) ?? "(no response)")")
        print("Compare against the endpoint's normal status; a 4xx here is the desync signal.")
    }
}
