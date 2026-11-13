import Foundation
import Testing

@testable import GulpExtensions

@Suite("GulpExtensions scaffolding")
struct GulpExtensionsScaffolding {
    @Test("module marker is wired")
    func moduleMarker() { #expect(GulpExtensions.moduleName == "GulpExtensions") }
}

@Suite("Extensions — JSON-RPC framing (EXT-002)")
struct FramingTests {
    @Test("frames round-trip, even split across arbitrary byte chunks")
    func roundTrip() {
        let a = Data(#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#.utf8)
        let b = Data(#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#.utf8)
        let wire = [UInt8](JSONRPCFraming.frame(a) + JSONRPCFraming.frame(b))
        var framer = JSONRPCFramer()
        var messages: [Data] = []
        // Feed one byte at a time to prove the framer reassembles partial headers and bodies.
        for byte in wire { messages += framer.feed([byte]) }
        #expect(messages.count == 2)
        #expect(messages.first == a)
        #expect(messages.last == b)
    }
}

@Suite("Extensions — manifest (EXT-003)")
struct ManifestTests {
    @Test("a gulp-extension.json parses with its runtime, permissions and hooks")
    func decode() throws {
        let json = Data(
            #"""
            {"id":"com.acme.leak","name":"Leak finder","version":"1.0","runtime":"process",
             "command":["/bin/bash","ext.sh"],"minAPIVersion":1,
             "permissions":["read-traffic","create-issues"],"hooks":["passive-check"]}
            """#.utf8)
        let manifest = try ExtensionManifest.decode(json)
        #expect(manifest.id == "com.acme.leak")
        #expect(manifest.runtime == .process)
        #expect(manifest.allows(.createIssues))
        #expect(!manifest.allows(.httpSend))
        #expect(manifest.hooks == ["passive-check"])
    }
}

/// A mock extension: answers initialize and passiveCheck, and records the frames the host sent.
final class MockExtensionTransport: ExtensionTransport, @unchecked Sendable {
    private let (stream, continuation) = AsyncStream<[UInt8]>.makeStream()
    private let lock = NSLock()
    private var framer = JSONRPCFramer()
    private var _sent: [[String: Any]] = []
    var sent: [[String: Any]] { lock.withLock { _sent } }

    func send(_ bytes: [UInt8]) async throws {
        let messages: [[String: Any]] = lock.withLock {
            framer.feed(bytes).compactMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        }
        for object in messages {
            lock.withLock { _sent.append(object) }
            guard let id = object["id"] as? Int, let method = object["method"] as? String else { continue }
            respond(to: method, id: id, params: object["params"])
        }
    }

    private func respond(to method: String, id: Int, params: Any?) {
        var result: [String: Any] = [:]
        switch method {
        case "initialize":
            result = ["passiveChecks": [["id": "ext.header-leak", "name": "Header leak"]]]
        case "passiveCheck":
            let response = (params as? [String: Any])?["response"] as? String ?? ""
            result =
                response.contains("X-Debug-Token")
                ? [
                    "findings": [
                        [
                            "typeID": "ext.header-leak", "name": "Debug header leak", "severity": "low",
                            "detail": "a debug header is exposed", "marker": "X-Debug-Token",
                        ]
                    ]
                ]
                : ["findings": []]
        default: break
        }
        emit(["jsonrpc": "2.0", "id": id, "result": result])
    }

    /// Push a raw message to the host (e.g. an inbound API call from the extension).
    func emit(_ object: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: object) else { return }
        continuation.yield([UInt8](JSONRPCFraming.frame(data)))
    }

    func receiveLoop(_ onData: @Sendable @escaping ([UInt8]) -> Void) async {
        for await bytes in stream { onData(bytes) }
    }

    func close() async { continuation.finish() }
}

@Suite("Extensions — host protocol and permissions (EXT-002/004)")
struct ExtensionHostTests {
    func manifest(_ permissions: [ExtensionPermission]) -> ExtensionManifest {
        ExtensionManifest(
            id: "x", name: "x", version: "1", runtime: .process, command: ["/bin/true"],
            permissions: permissions, hooks: ["passive-check"])
    }

    @Test("initialize reads the extension's declared checks")
    func initialize() async throws {
        let mock = MockExtensionTransport()
        let host = ExtensionHost(manifest: manifest([.readTraffic, .createIssues]), transport: mock)
        await host.start()
        let checks = try await host.initialize()
        #expect(checks == [ExtensionCheck(id: "ext.header-leak", name: "Header leak")])
        await host.close()
    }

    @Test("a passive check returns findings only when create-issues is granted")
    func passiveCheckPermission() async throws {
        let response = "HTTP/1.1 200 OK\r\nX-Debug-Token: abc\r\n\r\n"
        // Granted.
        let granted = ExtensionHost(
            manifest: manifest([.readTraffic, .createIssues]), transport: MockExtensionTransport())
        await granted.start()
        let findings = try await granted.runPassiveCheck(
            requestText: "GET / HTTP/1.1", responseText: response)
        #expect(findings.map(\.typeID) == ["ext.header-leak"])
        await granted.close()
        // Denied: findings are dropped and the violation is recorded.
        let denied = ExtensionHost(manifest: manifest([.readTraffic]), transport: MockExtensionTransport())
        await denied.start()
        let none = try await denied.runPassiveCheck(requestText: "GET / HTTP/1.1", responseText: response)
        #expect(none.isEmpty)
        #expect(await !denied.denials.isEmpty)
        await denied.close()
    }

    @Test("an inbound http/send is denied without the http-send permission")
    func inboundPermission() async throws {
        let mock = MockExtensionTransport()
        let host = ExtensionHost(manifest: manifest([.readTraffic]), transport: mock)
        await host.start()
        _ = try await host.initialize()
        mock.emit(["jsonrpc": "2.0", "id": 500, "method": "http/send", "params": ["url": "http://x/"]])
        try await Task.sleep(for: .milliseconds(200))
        let reply = mock.sent.first { $0["id"] as? Int == 500 }
        #expect((reply?["error"] as? [String: Any])?["message"] as? String == "permission denied: http-send")
        #expect(await !host.denials.isEmpty)
        await host.close()
    }
}

@Suite("Extensions — a real subprocess extension (EXT-002)", .serialized)
struct ProcessExtensionTests {
    @Test("a bash extension over real stdio registers a check and reports a finding")
    func bashExtension() async throws {
        guard FileManager.default.isExecutableFile(atPath: "/bin/bash") else { return }
        let script = """
            #!/usr/bin/env bash
            emit() { local b="$1"; printf 'Content-Length: %d\\r\\n\\r\\n%s' "${#b}" "$b"; }
            while true; do
              len=0
              while IFS= read -r line; do line=${line%$'\\r'}; [ -z "$line" ] && break
                case "$line" in "Content-Length:"*) len=${line#Content-Length: };; esac; done
              [ "$len" -gt 0 ] || exit 0
              body=$(head -c "$len")
              id=$(printf '%s' "$body" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')
              if printf '%s' "$body" | grep -q '"method":"initialize"'; then
                emit "{\\"jsonrpc\\":\\"2.0\\",\\"id\\":$id,\\"result\\":{\\"passiveChecks\\":[{\\"id\\":\\"ext.header-leak\\",\\"name\\":\\"Header leak\\"}]}}"
              elif printf '%s' "$body" | grep -q '"method":"passiveCheck"'; then
                if printf '%s' "$body" | grep -q 'X-Debug-Token'; then
                  emit "{\\"jsonrpc\\":\\"2.0\\",\\"id\\":$id,\\"result\\":{\\"findings\\":[{\\"typeID\\":\\"ext.header-leak\\",\\"name\\":\\"Debug header leak\\",\\"severity\\":\\"low\\",\\"detail\\":\\"debug header\\",\\"marker\\":\\"X-Debug-Token\\"}]}}"
                else
                  emit "{\\"jsonrpc\\":\\"2.0\\",\\"id\\":$id,\\"result\\":{\\"findings\\":[]}}"
                fi
              fi
            done
            """
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("gulp-ext-\(UUID()).sh")
        try script.write(to: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: path) }

        let transport = try ProcessExtensionTransport(command: ["/bin/bash", path.path])
        let host = ExtensionHost(
            manifest: ExtensionManifest(
                id: "x", name: "x", version: "1", runtime: .process,
                permissions: [.readTraffic, .createIssues],
                hooks: ["passive-check"]),
            transport: transport)
        await host.start()
        let checks = try await host.initialize()
        #expect(checks.map(\.id) == ["ext.header-leak"])
        let findings = try await host.runPassiveCheck(
            requestText: "GET / HTTP/1.1", responseText: "HTTP/1.1 200 OK\r\nX-Debug-Token: 1\r\n\r\n")
        #expect(findings.map(\.typeID) == ["ext.header-leak"])
        let clean = try await host.runPassiveCheck(
            requestText: "GET / HTTP/1.1", responseText: "HTTP/1.1 200 OK\r\n\r\n")
        #expect(clean.isEmpty)
        await host.close()
    }
}
