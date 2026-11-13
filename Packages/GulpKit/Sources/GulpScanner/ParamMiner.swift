// GulpScanner — Parameter Discovery (F23 ADV-020). Brute-force hidden query parameters a request does
// not advertise and detect which ones the server actually processes, by adding batches of candidate
// names with unique canary values and watching the response: a canary reflected in the body means the
// name is read back; a change in status or (canary-normalized) length means it changed behavior, and a
// binary search isolates which name in the batch caused it. The engine `send` is injected, so this is
// tested without a network.

import Foundation
import GulpCore

/// A hidden parameter the server was found to process.
public struct DiscoveredParam: Sendable, Equatable {
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
        let query = pairs.map { "\($0.0)=\($0.1)" }.joined(separator: "&")
        return request.replacing(
            request.parsed.target, with: Bytes(Array((target + separator + query).utf8)))
    }

    /// Discover which of `names` the server at `base` processes. `batchSize` candidates go per request.
    public static func discover(
        base: RawRequest, names: [String], batchSize: Int = 24,
        send: @Sendable (RawRequest) async -> RawResponse
    ) async -> [DiscoveredParam] {
        var canaries: [String: String] = [:]
        for name in names { canaries[name] = canaryPrefix + token() }

        let baseline = await send(
            appendingQuery(base, [(canaryPrefix + token(), canaryPrefix + token())]))
        let baseSignature = signature(baseline)

        var found: [DiscoveredParam] = []
        var seen = Set<String>()
        for batch in chunk(names, batchSize) {
            let response = await send(appendingQuery(base, batch.map { ($0, canaries[$0]!) }))
            let text = bodyText(response)
            for name in batch where text.contains(canaries[name]!) {
                if seen.insert(name).inserted {
                    found.append(DiscoveredParam(name: name, evidence: "reflected"))
                }
            }
            if signature(response) != baseSignature {
                let candidates = batch.filter { !text.contains(canaries[$0]!) }
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
        let response = await send(appendingQuery(base, group.map { ($0, canaries[$0]!) }))
        guard signature(response) != baseSignature else { return [] }
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

    /// A response signature that ignores canary echoes, so reflection doesn't masquerade as behavior.
    private static func signature(_ response: RawResponse) -> (Int, Int) {
        let normalized = bodyText(response).replacingOccurrences(
            of: "\(canaryPrefix)[a-z0-9]+", with: "", options: .regularExpression)
        return (response.parsed.statusCode, normalized.count)
    }

    static func token() -> String {
        String((0..<8).map { _ in "abcdefghijklmnopqrstuvwxyz0123456789".randomElement()! })
    }

    private static func chunk(_ names: [String], _ size: Int) -> [[String]] {
        stride(from: 0, to: names.count, by: size).map { Array(names[$0..<min($0 + size, names.count)]) }
    }
}
