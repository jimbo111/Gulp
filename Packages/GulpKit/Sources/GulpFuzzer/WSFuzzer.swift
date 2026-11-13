// WebSocket Fuzzer (F07 §2.6, WSX-002). Unlike the HTTP fuzzer, which runs an exchange loop over many
// connections, the WS fuzzer iterates a message template's payloads as frames over *one* persistent
// `openWebSocket` connection, reusing only the F07 payload generators/processors (`PayloadSet`,
// `PayloadPipeline`) and the grep/extract/reflection analysis (`ResponseAnalyzer`). Each result is the
// returned WS message, not an HTTP exchange.

import Foundation
import GulpCore

/// One persistent WebSocket, seen by the fuzzer as "send one message, get the next reply". The live
/// implementation wraps `WebSocketSession`; tests supply a scripted channel.
public protocol WSFuzzChannel: Sendable {
    /// Send one text message and return the next text reply, or nil if none arrives before the reply
    /// deadline (or the socket closed).
    func exchange(_ message: [UInt8]) async throws -> [UInt8]?
}

/// A WebSocket fuzz configuration: the `§…§`-marked message template, one payload set applied in
/// sniper fashion (one position at a time), and the grep/extract columns.
public struct WSFuzzConfig: Sendable {
    /// The message template, with `marker` pairs around each payload position.
    public var template: [UInt8]
    /// The position marker (default `§`).
    public var marker: String
    /// The payload source and its processing.
    public var payloadSet: PayloadSet
    /// Grep columns run on each reply.
    public var matches: [GrepMatch]
    /// Extract columns run on each reply.
    public var extracts: [GrepExtract]
    /// Delay between sends, in milliseconds (politeness / ordering).
    public var delayMs: Int
    /// Stop as soon as a reply matches a grep column.
    public var stopOnFirstMatch: Bool

    /// A configuration.
    public init(
        template: [UInt8], marker: String = "§", payloadSet: PayloadSet, matches: [GrepMatch] = [],
        extracts: [GrepExtract] = [], delayMs: Int = 0, stopOnFirstMatch: Bool = false
    ) {
        self.template = template
        self.marker = marker
        self.payloadSet = payloadSet
        self.matches = matches
        self.extracts = extracts
        self.delayMs = delayMs
        self.stopOnFirstMatch = stopOnFirstMatch
    }
}

/// One WS fuzz result: the payload, the message sent, the reply, and the grep/extract/reflection
/// findings on the reply.
public struct WSFuzzResult: Sendable, Hashable, Codable {
    /// 1-based index in send order.
    public var index: Int
    /// The (processed) payload spliced in.
    public var payload: String
    /// The position the payload went into.
    public var position: Int
    /// The rendered message sent on the wire.
    public var sent: String
    /// The reply text (empty if none arrived).
    public var reply: String
    /// Per grep column: did the reply match.
    public var matches: [Bool]
    /// Per extract column: the captured text, if any.
    public var extracts: [String?]
    /// Whether the payload came back in the reply.
    public var reflected: Reflection

    /// A result.
    public init(
        index: Int, payload: String, position: Int, sent: String, reply: String, matches: [Bool],
        extracts: [String?], reflected: Reflection
    ) {
        self.index = index
        self.payload = payload
        self.position = position
        self.sent = sent
        self.reply = reply
        self.matches = matches
        self.extracts = extracts
        self.reflected = reflected
    }
}

/// Runs a `WSFuzzConfig` over one live socket, sequentially (WS ordering is significant).
public struct WSFuzzEngine: Sendable {
    /// The configuration.
    public let config: WSFuzzConfig
    let template: FuzzTemplate
    let pipeline: PayloadPipeline
    let analyzer: ResponseAnalyzer

    /// Compile the template, payload pipeline and grep/extract columns (invalid regexes or an
    /// unbalanced template throw).
    public init(_ config: WSFuzzConfig) throws {
        self.config = config
        template = try FuzzTemplate(config.template, marker: config.marker)
        guard template.positionCount >= 1 else {
            throw FuzzTemplateError(
                message: "the WS fuzz template has no \(config.marker) positions to fuzz")
        }
        pipeline = try PayloadPipeline(config.payloadSet.processors)
        analyzer = try ResponseAnalyzer(matches: config.matches, extracts: config.extracts)
    }

    /// Send every payload into every position (sniper), one at a time, over `channel`; returns one
    /// result per sent message in order.
    public func run(on channel: any WSFuzzChannel) async throws -> [WSFuzzResult] {
        var results: [WSFuzzResult] = []
        var index = 0
        for position in 0..<template.positionCount {
            for raw in config.payloadSet.source.payloads(base: template.baseValues[position]) {
                guard let processed = try pipeline.process(raw) else { continue }
                var payloads = [[UInt8]?](repeating: nil, count: template.positionCount)
                payloads[position] = processed
                let message = template.render(payloads)
                let reply = (try await channel.exchange(message)) ?? []
                let text = String(decoding: reply, as: UTF8.self)
                let findings = analyzer.analyze(text: text, payloads: [processed])
                index += 1
                results.append(
                    WSFuzzResult(
                        index: index, payload: String(decoding: processed, as: UTF8.self),
                        position: position, sent: String(decoding: message, as: UTF8.self), reply: text,
                        matches: findings.matches, extracts: findings.extracts,
                        reflected: findings.reflection))
                if config.stopOnFirstMatch, findings.matches.contains(true) { return results }
                if config.delayMs > 0 {
                    try? await Task.sleep(nanoseconds: UInt64(config.delayMs) * 1_000_000)
                }
            }
        }
        return results
    }
}
