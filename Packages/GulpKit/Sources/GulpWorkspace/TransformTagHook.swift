// GulpWorkspace — Transform Tags in the send pipeline (F12 DEC-022): a request hook that evaluates
// `«op{…}»` tags for the tools that opt in (Repeater, Fuzzer; per-send via `SendOptions.applyHooks`),
// with the project's variables. Proxied, scanner and agent traffic is never rewritten. The engine
// keeps the pre-hook request as the exchange's original, so history shows both the tags and the
// bytes that were sent; "Update Content-Length" runs after hooks.

import Foundation
import GulpCodec
import GulpCore
import GulpHTTP

/// Evaluates Transform Tags before a send.
public struct TransformTagHook: RequestHook {
    /// Hook family (toggled per send).
    public let kind = HookSet.transformTags
    /// The tags' variables and counters.
    public let state: TagState
    /// The parser (delimiters).
    public let tags: TransformTags

    /// Tools whose requests carry tags.
    public static let sources: Set<String> = ["repeater", "fuzzer"]

    /// A hook over `state`.
    public init(state: TagState, tags: TransformTags = TransformTags()) {
        self.state = state
        self.tags = tags
    }

    public func willSend(_ req: inout OutgoingRequest, context: HookContext) async throws {
        guard Self.sources.contains(context.source.rawValue) else { return }
        let bytes = req.request.bytes.rawBytes
        guard tags.containsTags(bytes) else { return }
        req.request = RawRequest(Bytes(try tags.evaluate(bytes, state: state)))
    }
}

extension ProjectSession {
    /// The project's Transform Tag variables (`var(name)`).
    public func tagVariables() -> [String: String] {
        settings.get(VariablesSettings.self).values
    }

    /// Store the Transform Tag variables in the project and use them from the next send.
    public func setTagVariables(_ values: [String: String]) async throws {
        try await settings.set(VariablesSettings(values: values), scope: .project)
        tagState.setVariables(values)
    }

    /// What `request` becomes after Transform Tags (DEC-022's preview), without consuming
    /// counters. Throws `TransformTagError` with the tag's offset.
    public nonisolated func previewTags(_ request: [UInt8]) throws -> [UInt8] {
        let tags = TransformTags()
        guard tags.containsTags(request) else { return request }
        return try tags.evaluate(request, state: tagState, advance: false)
    }
}
