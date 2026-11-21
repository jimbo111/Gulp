// GulpScanner — Parameter Discovery (F23 ADV-020). Brute-force hidden query parameters a request does
// not advertise and detect which ones the server actually processes, by adding batches of candidate
// names with unique canary values and watching the response: a canary reflected in the body means the
// name is read back (unless the page echoes its whole query string, which a random control parameter
// reveals); a change in status or (echo-normalized) length means it changed behavior, and a binary
// search isolates which name in the batch caused it. The engine `send` is injected, so this is
// tested without a network.

import Foundation
import GulpCore

/// A hidden parameter the server was found to process.
public struct DiscoveredParam: Sendable, Equatable {
    /// The parameter name.
    public let name: String
    /// Why it was flagged: `reflected` or `behavior change`.
    public let evidence: String
}

/// Finds hidden parameters the server processes.
public enum ParamMiner {
    static let canaryPrefix = "gulpcan"

    /// Append `pairs` as query parameters to a request's target, byte-exactly.
    public static func appendingQuery(_ request: RawRequest, _ pairs: [(String, String)]) -> RawRequest {
        let target = request.bytes[request.parsed.target].string()
        let separator = target.contains("?") ? "&" : "?"
        return request.replacing(
            request.parsed.target, with: Bytes(Array((target + separator + query(pairs)).utf8)))
    }

    /// Discover which of `names` the server at `base` processes. `batchSize` candidates go per request.
    public static func discover(
        base: RawRequest, names: [String], batchSize: Int = 24,
        send: @Sendable (RawRequest) async -> RawResponse
    ) async -> [DiscoveredParam] {
        var canaries: [String: String] = [:]
        for name in names { canaries[name] = canaryPrefix + token() }

        let control = [(canaryPrefix + token(), canaryPrefix + token())]
        let baseline = await send(appendingQuery(base, control))
        let baseSignature = signature(baseline, appended: control)
        // Control: a page that echoes its query string reflects any name, the random one included,
        // so there a reflected canary says nothing about whether the name is processed.
        let echoesQuery = bodyText(baseline).contains(control[0].1)

        var found: [DiscoveredParam] = []
        var seen = Set<String>()
        for batch in chunk(names, batchSize) {
            let pairs = batch.map { ($0, canaries[$0]!) }
            let response = await send(appendingQuery(base, pairs))
            let text = bodyText(response)
            for name in batch where !echoesQuery && text.contains(canaries[name]!) {
                if seen.insert(name).inserted {
                    found.append(DiscoveredParam(name: name, evidence: "reflected"))
                }
            }
            if signature(response, appended: pairs) != baseSignature {
                let candidates = echoesQuery ? batch : batch.filter { !text.contains(canaries[$0]!) }
                let culprits = await isolate(
                    candidates, base: base, canaries: canaries, baseSignature: baseSignature, send: send)
                for name in culprits where seen.insert(name).inserted {
                    found.append(DiscoveredParam(name: name, evidence: "behavior change"))
                }
            }
        }
        return found
    }

    /// Binary-search a group for the parameter(s) whose presence changes the response.
    private static func isolate(
        _ group: [String], base: RawRequest, canaries: [String: String], baseSignature: (Int, Int),
        send: @Sendable (RawRequest) async -> RawResponse
    ) async -> [String] {
        guard !group.isEmpty else { return [] }
        let pairs = group.map { ($0, canaries[$0]!) }
        let response = await send(appendingQuery(base, pairs))
        guard signature(response, appended: pairs) != baseSignature else { return [] }
        if group.count == 1 { return group }
        let middle = group.count / 2
        let left = await isolate(
            Array(group[..<middle]), base: base, canaries: canaries, baseSignature: baseSignature,
            send: send)
        let right = await isolate(
            Array(group[middle...]), base: base, canaries: canaries, baseSignature: baseSignature,
            send: send)
        return left + right
    }

    // MARK: helpers

    private static func bodyText(_ response: RawResponse) -> String {
        (response.parsed.dechunkedBody ?? response.bytes[response.parsed.body]).string()
    }

    private static func query(_ pairs: [(String, String)]) -> String {
        pairs.map { "\($0.0)=\($0.1)" }.joined(separator: "&")
    }

    /// A response signature that ignores echoes of what was `appended` (the whole query string, then
    /// any canary), so reflection doesn't masquerade as behavior.
    private static func signature(_ response: RawResponse, appended: [(String, String)]) -> (Int, Int) {
        let normalized = bodyText(response).replacingOccurrences(of: query(appended), with: "")
            .replacingOccurrences(of: "\(canaryPrefix)[a-z0-9]+", with: "", options: .regularExpression)
        return (response.parsed.statusCode, normalized.count)
    }

    static func token() -> String {
        String((0..<8).map { _ in "abcdefghijklmnopqrstuvwxyz0123456789".randomElement()! })
    }

    private static func chunk(_ names: [String], _ size: Int) -> [[String]] {
        stride(from: 0, to: names.count, by: size).map { Array(names[$0..<min($0 + size, names.count)]) }
    }
}
