// GulpBrowser — a small Chrome DevTools Protocol client (F16 BRW-005). CDP is JSON over a WebSocket:
// commands are `{"id":N,"method":…,"params":…}` and the browser answers with `{"id":N,"result":…}`
// (or an error) and streams `{"method":…,"params":…}` events. The transport is abstracted so the
// client's id-correlation and event routing are unit-tested without a real browser; in production the
// transport is a WebSocket through Gulp's own engine.

import Foundation
import GulpCore
import GulpHTTP

/// A CDP failure.
public enum CDPError: Error, Sendable, Equatable {
    case transport(String)
    case remote(code: Int, message: String)
    case malformed(String)
    case closed
}

/// A CDP event (`Target.attachedToTarget`, `Runtime.bindingCalled`, …).
public struct CDPEvent: Sendable, Equatable {
    public let method: String
    /// The event's `params` object as a JSON string.
    public let params: String
    /// The flattened session the event came from, if any.
    public let sessionId: String?
}

/// Carries CDP JSON text both ways. The WebSocket transport is production; a fake drives the tests.
public protocol CDPTransport: Sendable {
    func send(_ text: String) async throws
    func receiveLoop(_ onText: @Sendable @escaping (String) -> Void) async
    func close() async
}

/// A CDP connection: send a command and await its result; subscribe to events.
public actor CDPClient {
    private let transport: CDPTransport
    private var nextID = 0
    private var pending: [Int: CheckedContinuation<String, Error>] = [:]
    private var closed = false
    private let eventStream: AsyncStream<CDPEvent>
    private let eventContinuation: AsyncStream<CDPEvent>.Continuation
    private var reader: Task<Void, Never>?

    /// Events the browser pushed (responses are returned by `send`, not here).
    public nonisolated let events: AsyncStream<CDPEvent>

    /// A client over `transport`; call `start()` to begin reading.
    public init(transport: CDPTransport) {
        self.transport = transport
        let (stream, continuation) = AsyncStream<CDPEvent>.makeStream()
        eventStream = stream
        eventContinuation = continuation
        events = stream
    }

    /// Start reading from the transport (call once, after init).
    public func start() {
        guard reader == nil else { return }
        let transport = self.transport
        reader = Task { [self] in
            await transport.receiveLoop { text in
                Task { await self.ingest(text) }
            }
            await self.failAll(.closed)
        }
    }

    /// Send a command and await its `result` object as a JSON string. `params` is a JSON object
    /// string; `sessionId` targets a flattened page session.
    public func send(_ method: String, params: String = "{}", sessionId: String? = nil) async throws
        -> String
    {
        guard !closed else { throw CDPError.closed }
        nextID += 1
        let id = nextID
        var message: [String: Any] = ["id": id, "method": method]
        if let object = try? JSONSerialization.jsonObject(with: Data(params.utf8)) {
            message["params"] = object
        }
        if let sessionId { message["sessionId"] = sessionId }
        guard let data = try? JSONSerialization.data(withJSONObject: message) else {
            throw CDPError.malformed("cannot encode \(method)")
        }
        return try await withCheckedThrowingContinuation { continuation in
            pending[id] = continuation
            Task {
                do { try await transport.send(String(decoding: data, as: UTF8.self)) } catch {
                    if let waiting = pending.removeValue(forKey: id) {
                        waiting.resume(throwing: CDPError.transport("\(error)"))
                    }
                }
            }
        }
    }

    /// Close the connection and fail every outstanding command.
    public func close() async {
        closed = true
        reader?.cancel()
        await transport.close()
        failAll(.closed)
        eventContinuation.finish()
    }

    // MARK: routing

    private func ingest(_ text: String) {
        guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
            return
        }
        if let id = object["id"] as? Int, let continuation = pending.removeValue(forKey: id) {
            if let error = object["error"] as? [String: Any] {
                let code = error["code"] as? Int ?? -1
                let message = error["message"] as? String ?? "CDP error"
                continuation.resume(throwing: CDPError.remote(code: code, message: message))
            } else {
                let result = object["result"] ?? [String: Any]()
                let data = (try? JSONSerialization.data(withJSONObject: result)) ?? Data("{}".utf8)
                continuation.resume(returning: String(decoding: data, as: UTF8.self))
            }
            return
        }
        if let method = object["method"] as? String {
            let params = object["params"] ?? [String: Any]()
            let data = (try? JSONSerialization.data(withJSONObject: params)) ?? Data("{}".utf8)
            eventContinuation.yield(
                CDPEvent(
                    method: method, params: String(decoding: data, as: UTF8.self),
                    sessionId: object["sessionId"] as? String))
        }
    }

    private func failAll(_ error: CDPError) {
        for (_, continuation) in pending { continuation.resume(throwing: error) }
        pending.removeAll()
    }
}

/// The production transport: CDP over a WebSocket opened through Gulp's engine.
public struct WebSocketCDPTransport: CDPTransport {
    private let session: WebSocketSession

    public init(session: WebSocketSession) { self.session = session }

    public func send(_ text: String) async throws { try await session.send(text: text) }

    public func receiveLoop(_ onText: @Sendable @escaping (String) -> Void) async {
        for await message in session.messages where message.opcode == WSOpcode.text.rawValue {
            onText(String(decoding: message.payload, as: UTF8.self))
        }
    }

    public func close() async { await session.close() }
}
