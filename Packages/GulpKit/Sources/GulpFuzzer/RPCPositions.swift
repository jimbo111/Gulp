// GulpFuzzer — payload positions inside a protobuf message (F33 GRP-005). Instead of `§` markers in
// the bytes, a position is a field path (field numbers, outer to inner) inside one message of a
// gRPC, gRPC-Web or Connect request. Each payload replaces that field's value with the same wire
// type where it parses (see `ProtoValue.parsing`), and the message is re-encoded: the field's length,
// every enclosing message's length, the 5-byte envelope and Content-Length are all recomputed.
// Unknown fields and field order are kept exactly as decoded.

import Foundation
import GulpCodec
import GulpCore

/// Fuzzer positions that are fields inside a protobuf message of an RPC request.
public struct RPCPositions: Sendable, Hashable {
    /// The base request (exact bytes).
    public let request: [UInt8]
    /// The message (0-based) of the request body whose fields are positions.
    public let messageIndex: Int
    /// One field path per position.
    public let paths: [[Int]]
    /// The decoded base message.
    let message: ProtoMessage
    /// Each position's wire type in the base message.
    let wireTypes: [ProtoWireType]
    /// Each position's base value as text.
    let baseValues: [[UInt8]]

    /// Positions at `paths` inside message `messageIndex` of `request`. Throws when the request
    /// isn't a protobuf RPC request or a path doesn't exist.
    public init(request: [UInt8], paths: [[Int]], messageIndex: Int = 0) throws {
        let raw = RawRequest(Bytes(request))
        guard let call = RPC.parse(request: raw, response: nil) else {
            throw FuzzTemplateError(message: "not a gRPC, gRPC-Web or Connect request")
        }
        guard call.requests.indices.contains(messageIndex) else {
            throw FuzzTemplateError(message: "the request has no message \(messageIndex + 1)")
        }
        let chosen = call.requests[messageIndex]
        guard !chosen.json else {
            throw FuzzTemplateError(message: "the message is JSON; mark positions in it with markers instead")
        }
        guard !paths.isEmpty else { throw FuzzTemplateError(message: "no protobuf fields chosen") }
        let message: ProtoMessage
        do { message = try Protobuf.decode(chosen.payload) } catch {
            throw FuzzTemplateError(message: "message \(messageIndex + 1) isn't protobuf: \(error)")
        }
        var wireTypes: [ProtoWireType] = []
        var baseValues: [[UInt8]] = []
        for path in paths {
            guard let value = message.value(at: path) else {
                throw FuzzTemplateError(
                    message: "field \(path.map(String.init).joined(separator: ".")) isn't in the message")
            }
            wireTypes.append(value.wireType)
            baseValues.append(Array(value.editableText.utf8))
        }
        self.request = request
        self.messageIndex = messageIndex
        self.paths = paths
        self.message = message
        self.wireTypes = wireTypes
        self.baseValues = baseValues
    }

    /// The request with `payloads` (nil: base value) written into the fields and re-encoded.
    public func render(_ payloads: [[UInt8]?]) -> [UInt8] {
        var edited = message
        for (index, path) in paths.enumerated() {
            guard index < payloads.count, let payload = payloads[index] else { continue }
            edited = edited.setting(path, to: ProtoValue.parsing(payload, as: wireTypes[index])) ?? edited
        }
        return RPC.replacingMessage(RawRequest(Bytes(request)), at: messageIndex, with: edited.encoded)?
            .bytes.rawBytes ?? request
    }
}
