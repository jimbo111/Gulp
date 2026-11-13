// GulpExtensions — the out-of-process extension host (F18 EXT-002/004). It speaks JSON-RPC 2.0 to a
// child process: Gulp calls the extension (`initialize`, `passiveCheck`), and the extension calls back
// into Gulp (`host/log`, `http/send`). Every inbound call is checked against the manifest's approved
// permissions and denied + logged on violation. The transport is abstracted so the full protocol is
// unit-tested against a mock; the production transport is a real process's stdio.

import Foundation

/// Carries framed JSON-RPC bytes to and from an extension.
public protocol ExtensionTransport: Sendable {
    func send(_ bytes: [UInt8]) async throws
    func receiveLoop(_ onData: @Sendable @escaping ([UInt8]) -> Void) async
    func close() async
}

/// A passive check an extension declared at `initialize` time.
public struct ExtensionCheck: Sendable, Codable, Equatable {
    public let id: String
    public let name: String
}

/// Drives one out-of-process extension.
public actor ExtensionHost {
    /// The extension's manifest (identity, runtime, approved permissions).
    public let manifest: ExtensionManifest
    private let transport: ExtensionTransport
    /// Handles an approved `http/send` call (params JSON -> response JSON). Injected so tests and the
    /// workspace supply their own; nil denies the call even when the permission is present.
    private let httpSend: (@Sendable (String) async -> String)?

    private var nextID = 0
    private var pending: [Int: CheckedContinuation<String, Error>] = [:]
    private var framer = JSONRPCFramer()
    private var reader: Task<Void, Never>?
    private var closed = false
    /// Lines the extension logged (EXT-005 console), newest last.
    public private(set) var log: [String] = []
    /// Permission violations that were denied (for the manager/audit).
    public private(set) var denials: [String] = []

    /// A host for `manifest` over `transport`; `httpSend` handles approved `http/send` calls.
    public init(
        manifest: ExtensionManifest, transport: ExtensionTransport,
        httpSend: (@Sendable (String) async -> String)? = nil
    ) {
        self.manifest = manifest
        self.transport = transport
        self.httpSend = httpSend
    }

    /// Start reading frames from the transport.
    public func start() {
        guard reader == nil else { return }
        let transport = self.transport
        reader = Task { [self] in
            await transport.receiveLoop { bytes in Task { await self.ingest(bytes) } }
            await self.failAll()
        }
    }

    /// Handshake: tell the extension our API version and read back the checks it registers (EXT-002).
    @discardableResult
    public func initialize(apiVersion: Int = 1) async throws -> [ExtensionCheck] {
        let result = try await call("initialize", params: ["apiVersion": apiVersion])
        guard let object = try? JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any],
            let checks = object["passiveChecks"] as? [[String: Any]]
        else { return [] }
        return checks.compactMap { entry in
            guard let id = entry["id"] as? String, let name = entry["name"] as? String else { return nil }
            return ExtensionCheck(id: id, name: name)
        }
    }

    /// Run the extension's passive check over one exchange and collect its findings. Findings are only
    /// returned if the extension declared `create-issues` (EXT-004).
    public func runPassiveCheck(requestText: String, responseText: String) async throws -> [ExtensionFinding]
    {
        let result = try await call(
            "passiveCheck", params: ["request": requestText, "response": responseText])
        guard manifest.allows(.createIssues) else {
            denials.append("passiveCheck returned findings without the create-issues permission")
            return []
        }
        guard let object = try? JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any],
            let raw = object["findings"],
            let data = try? JSONSerialization.data(withJSONObject: raw)
        else { return [] }
        return (try? JSONDecoder().decode([ExtensionFinding].self, from: data)) ?? []
    }

    /// Stop the extension, cancel the reader and fail any outstanding calls.
    public func close() async {
        closed = true
        reader?.cancel()
        await transport.close()
        failAll()
    }

    // MARK: Gulp -> extension

    private func call(_ method: String, params: [String: Any]) async throws -> String {
        guard !closed else { throw ExtensionError.closed }
        nextID += 1
        let id = nextID
        guard
            let data = try? JSONSerialization.data(
                withJSONObject: ["jsonrpc": "2.0", "id": id, "method": method, "params": params])
        else { throw ExtensionError.malformed }
        let frame = [UInt8](JSONRPCFraming.frame(data))  // Sendable; register the waiter before sending
        return try await withCheckedThrowingContinuation { continuation in
            pending[id] = continuation
            Task {
                do { try await transport.send(frame) } catch {
                    if let waiting = pending.removeValue(forKey: id) {
                        waiting.resume(throwing: ExtensionError.closed)
                    }
                }
            }
        }
    }

    // MARK: extension -> Gulp

    private func ingest(_ bytes: [UInt8]) async {
        for data in framer.feed(bytes) {
            guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                continue
            }
            // A response to one of our calls.
            if let id = object["id"] as? Int, pending[id] != nil,
                object["method"] == nil
            {
                let continuation = pending.removeValue(forKey: id)
                if let error = object["error"] as? [String: Any] {
                    continuation?.resume(
                        throwing: ExtensionError.remote(error["message"] as? String ?? "error"))
                } else {
                    let result = object["result"] ?? [String: Any]()
                    let data = (try? JSONSerialization.data(withJSONObject: result)) ?? Data("{}".utf8)
                    continuation?.resume(returning: String(decoding: data, as: UTF8.self))
                }
                continue
            }
            // A call from the extension into Gulp.
            if let method = object["method"] as? String {
                await handleInbound(method: method, id: object["id"] as? Int, params: object["params"])
            }
        }
    }

    private func handleInbound(method: String, id: Int?, params: Any?) async {
        switch method {
        case "host/log":
            if let text = (params as? [String: Any])?["message"] as? String { log.append(text) }
            if let id { try? await reply(id: id, result: [:]) }
        case "http/send":
            guard manifest.allows(.httpSend) else {
                denials.append("http/send denied: extension lacks the http-send permission")
                if let id { try? await replyError(id: id, message: "permission denied: http-send") }
                return
            }
            let paramsJSON =
                (params as? [String: Any]).flatMap {
                    try? JSONSerialization.data(withJSONObject: $0)
                }.map { String(decoding: $0, as: UTF8.self) } ?? "{}"
            let response = await (httpSend?(paramsJSON) ?? "{}")
            if let id {
                let object = (try? JSONSerialization.jsonObject(with: Data(response.utf8))) ?? [:]
                try? await reply(id: id, result: object)
            }
        default:
            if let id { try? await replyError(id: id, message: "unknown method \(method)") }
        }
    }

    private func reply(id: Int, result: Any) async throws {
        try await write(["jsonrpc": "2.0", "id": id, "result": result])
    }

    private func replyError(id: Int, message: String) async throws {
        try await write(["jsonrpc": "2.0", "id": id, "error": ["code": -32000, "message": message]])
    }

    private func write(_ object: [String: Any]) async throws {
        guard let data = try? JSONSerialization.data(withJSONObject: object) else {
            throw ExtensionError.malformed
        }
        try await transport.send([UInt8](JSONRPCFraming.frame(data)))
    }

    private func failAll() {
        for (_, continuation) in pending { continuation.resume(throwing: ExtensionError.closed) }
        pending.removeAll()
    }
}

/// An extension-host failure.
public enum ExtensionError: Error, Sendable, Equatable {
    case closed
    case malformed
    case remote(String)
}
