// GulpWorkspace — "Send to Comparer / Decoder" (F13 CMP-001, F12 DEC-004): the items the Comparer
// lists and the Decoder's current input, fed from History, Repeater and the site map, plus a stream
// the window watches to bring the tool forward. UI-free so it is tested on Linux.

import Foundation
import GulpCore
import GulpStore

/// One item in the Comparer's list (CMP-001).
public struct ComparerItem: Sendable, Hashable, Identifiable {
    /// Stable id.
    public var id: UUID
    /// A label, e.g. "#12 response".
    public var label: String
    /// Where it came from (`proxy`, `repeater`, `paste`…).
    public var source: String
    /// The bytes.
    public var bytes: [UInt8]

    /// An item.
    public init(id: UUID = UUID(), label: String, source: String, bytes: [UInt8]) {
        self.id = id
        self.label = label
        self.source = source
        self.bytes = bytes
    }
}

/// Which part of an exchange to send.
public enum ExchangePart: String, Sendable, CaseIterable {
    /// The request.
    case request
    /// The response (wire bytes).
    case response
}

/// The tool a send brought forward.
public enum InboxTool: Sendable, Equatable {
    /// The Comparer.
    case comparer
    /// The Decoder.
    case decoder
}

/// The Comparer's items and the Decoder's input for one project session.
public actor ToolInbox {
    /// The Comparer's items, oldest first (capped).
    public private(set) var comparerItems: [ComparerItem] = []
    /// The Decoder's input (the last thing sent to it).
    public private(set) var decoderInput: [UInt8] = []
    /// At most this many Comparer items are kept (the oldest drop off).
    public static let maxItems = 100
    private var watchers: [UUID: AsyncStream<InboxTool>.Continuation] = [:]

    /// An empty inbox.
    public init() {}

    /// A stream of the tools that received something (the window selects them).
    public func opened() -> AsyncStream<InboxTool> {
        let (stream, continuation) = AsyncStream.makeStream(
            of: InboxTool.self, bufferingPolicy: .bufferingNewest(4))
        let id = UUID()
        watchers[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { await self?.removeWatcher(id) } }
        return stream
    }

    private func removeWatcher(_ id: UUID) { watchers[id] = nil }

    /// Add an item to the Comparer.
    @discardableResult
    public func addToComparer(_ item: ComparerItem) -> ComparerItem {
        comparerItems.append(item)
        if comparerItems.count > Self.maxItems {
            comparerItems.removeFirst(comparerItems.count - Self.maxItems)
        }
        announce(.comparer)
        return item
    }

    /// Remove Comparer items.
    public func removeFromComparer(_ ids: Set<UUID>) {
        comparerItems.removeAll { ids.contains($0.id) }
    }

    /// Put bytes in the Decoder.
    public func sendToDecoder(_ bytes: [UInt8]) {
        decoderInput = bytes
        announce(.decoder)
    }

    private func announce(_ tool: InboxTool) {
        for watcher in watchers.values { watcher.yield(tool) }
    }
}

extension ProjectSession {
    /// Send exchanges' requests or responses to the Comparer (CMP-001). Returns the items added.
    @discardableResult
    public func sendToComparer(_ ids: [ExchangeID], part: ExchangePart) async throws -> [ComparerItem] {
        var added: [ComparerItem] = []
        for exchange in try await store.exchanges(ids: ids) {
            let bytes: [UInt8]
            switch part {
            case .request: bytes = exchange.request.bytes.rawBytes
            case .response:
                guard let response = exchange.response else { continue }
                bytes = response.wireBytes.rawBytes
            }
            added.append(
                await inbox.addToComparer(
                    ComparerItem(
                        label: "#\(exchange.id) \(part.rawValue)", source: exchange.source.rawValue,
                        bytes: bytes)))
        }
        return added
    }

    /// Send an exchange's request or response to the Decoder (DEC-004).
    public func sendToDecoder(_ id: ExchangeID, part: ExchangePart) async throws {
        guard let exchange = try await store.exchange(id: id) else { return }
        let bytes =
            part == .request ? exchange.request.bytes.rawBytes : exchange.response?.wireBytes.rawBytes ?? []
        await inbox.sendToDecoder(bytes)
    }
}
