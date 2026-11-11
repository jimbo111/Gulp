// GulpOAST — the default OAST transport: Gulp's own engine, unrecorded (OAST polling is Gulp's
// traffic, not the user's), ungoverned (the panic stop pauses payload injection, not the poll that
// reports what already happened) and with no hooks.

import Foundation
import GulpCore
import GulpHTTP

/// Sends OAST protocol requests through an `HTTPEngine`.
public struct EngineOASTTransport: OASTTransport {
    let engine: any HTTPEngine
    let timeout: Duration

    /// A transport over `engine`.
    public init(engine: any HTTPEngine, timeout: Duration = .seconds(15)) {
        self.engine = engine
        self.timeout = timeout
    }

    public func send(method: String, url: String, body: [UInt8]?, headers: [String: String]) async throws -> (
        status: Int, body: [UInt8]
    ) {
        guard let target = HTTPTarget(url: url) else { throw OASTError("invalid server URL \(url)") }
        let afterScheme = url.split(separator: "/", maxSplits: 3, omittingEmptySubsequences: false)
        let path = afterScheme.count > 3 ? "/" + afterScheme[3] : "/"
        let standard = target.port == (target.scheme == .https ? 443 : 80)
        var lines = [
            "\(method) \(path) HTTP/1.1", "Host: \(target.host)\(standard ? "" : ":\(target.port)")",
        ]
        lines += headers.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }
        lines.append("Content-Length: \(body?.count ?? 0)")
        let request = RawRequest(
            Bytes(Array((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8) + (body ?? [])))
        var options = SendOptions(recordAs: .automation)
        options.record = false
        options.governed = false
        options.applyHooks = []
        options.timeouts.total = timeout
        let result = await engine.send(request, to: target, options: options)
        if let error = result.error { throw OASTError("\(url): \(error.code)") }
        guard let response = result.exchange.response else { throw OASTError("\(url): no response") }
        let decoded = ((try? response.decodedBody(limit: 32 * 1024 * 1024)) ?? nil)?.rawBytes ?? []
        return (response.parsed.statusCode, decoded)
    }
}
