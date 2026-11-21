// GulpWorkspace — OAST in a project (F10 BCN-001…BCN-006). OAST is off by default (BCN-004): once
// configured, the session registers with the server when the project opens (one interactsh session
// per open project — payloads minted in an earlier session are not reported to a later one), arms
// the `beacon()` Transform Tag, watches recorded requests for its payloads (linking each to the
// exchange that carried it, so Fuzzer, Repeater and Scanner traffic are all correlated), polls in
// the background, and stores interactions. The server token lives in the Keychain on macOS and only
// in memory elsewhere (CLAUDE.md §4).

import Foundation
import GulpCodec
import GulpCore
import GulpHTTP
import GulpOAST
import GulpStore

/// OAST configuration (BCN-004). Off until the user sets a server.
public struct OASTSettings: SettingsGroup {
    /// Storage key.
    public static let key = "oast"
    /// Off; no server.
    public static let defaultValue = OASTSettings()

    /// OAST is on.
    public var enabled: Bool
    /// The server: the dev Beacon (`http://127.0.0.1:8090`) or an interactsh server.
    public var serverURL: String
    /// The payload domain (default: the server's host).
    public var domain: String
    /// Background polling interval in seconds.
    public var pollSeconds: Double
    /// Where "Test Beacon" connects for payload hosts (`host:port`), for a dev Beacon whose domain
    /// doesn't resolve; nil resolves the payload host normally.
    public var connectTo: String?
    /// The user confirmed that a public (third-party) server sees the interactions (BCN-005).
    public var thirdPartyAcknowledged: Bool

    /// Settings.
    public init(
        enabled: Bool = false, serverURL: String = "", domain: String = "", pollSeconds: Double = 5,
        connectTo: String? = nil, thirdPartyAcknowledged: Bool = false
    ) {
        self.enabled = enabled
        self.serverURL = serverURL
        self.domain = domain
        self.pollSeconds = pollSeconds
        self.connectTo = connectTo
        self.thirdPartyAcknowledged = thirdPartyAcknowledged
    }

    /// A server on loopback or a private address (the dev Beacon, a self-hosted server on the LAN)
    /// rather than a public third party.
    public var isLocal: Bool {
        guard let host = HTTPTarget(url: serverURL)?.host.lowercased() else { return false }
        return host == "localhost" || host.hasPrefix("127.") || host == "::1" || host.hasPrefix("10.")
            || host.hasPrefix("192.168.") || host.hasSuffix(".local")
    }
}

/// BCN-006: what the status bar shows.
public struct OASTHealth: Sendable, Hashable {
    /// OAST is configured and registered.
    public var registered = false
    /// The server.
    public var server = ""
    /// The payload domain.
    public var domain = ""
    /// The last successful poll.
    public var lastPoll: Date?
    /// The last interaction received.
    public var lastInteraction: Date?
    /// The last error.
    public var lastError: String?
    /// Payloads minted this session.
    public var payloads = 0
    /// Interactions received this session.
    public var interactions = 0

    /// A fresh health record; the defaults are the not-yet-registered state.
    public init(registered: Bool = false, server: String = "", domain: String = "") {
        self.registered = registered
        self.server = server
        self.domain = domain
    }
}

/// BCN-006 "Test Beacon": the self-injected request's outcome.
public struct BeaconTestResult: Sendable {
    /// The interaction arrived.
    public var ok: Bool
    /// The payload used.
    public var payload: OASTPayload
    /// Seconds until it arrived (or the wait, when it didn't).
    public var seconds: Double
    /// Protocols seen (`dns`, `http`…).
    public var protocols: [String]
    /// Why it failed, if it did.
    public var problem: String?
}

/// The project's OAST session.
public actor OASTService {
    let engine: NIOHTTPEngine
    let store: @Sendable () async -> ProjectStore
    let tagState: TagState
    let events: EventBus
    private var client: InteractshClient?
    private var poller: Task<Void, Never>?
    private var settings = OASTSettings()
    private var health = OASTHealth()
    private var seen: [String: [String]] = [:]

    init(
        engine: NIOHTTPEngine, store: @escaping @Sendable () async -> ProjectStore, tagState: TagState,
        events: EventBus
    ) {
        self.engine = engine
        self.store = store
        self.tagState = tagState
        self.events = events
    }

    /// The status (BCN-006).
    public var currentHealth: OASTHealth { health }

    /// The session's correlation id (nil when not registered).
    public var correlationID: String? {
        get async { await client?.correlationID }
    }

    /// Register with `settings.serverURL` and start polling.
    func start(_ settings: OASTSettings, token: String?) async throws {
        await stop()
        guard !settings.serverURL.isEmpty else { throw OASTError("no OAST server configured") }
        let client = try InteractshClient(
            serverURL: settings.serverURL, domain: settings.domain.isEmpty ? nil : settings.domain,
            token: token,
            transport: EngineOASTTransport(engine: engine))
        try await client.register()
        self.client = client
        self.settings = settings
        let correlation = await client.correlationID
        let domain = await client.domain
        health = OASTHealth(registered: true, server: settings.serverURL, domain: domain)
        tagState.setOASTMinter {
            correlation + Interactsh.random(Interactsh.nonceLength, from: Interactsh.zbase32Alphabet) + "."
                + domain
        }
        let interval = max(0.5, settings.pollSeconds)
        poller = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                guard let self else { return }
                _ = try? await self.poll()
            }
        }
    }

    /// Stop polling and deregister.
    func stop() async {
        poller?.cancel()
        poller = nil
        tagState.setOASTMinter(nil)
        if let client { try? await client.deregister() }
        client = nil
        health.registered = false
    }

    /// A new payload for `context` (BCN-001), remembered in the project.
    public func mint(_ context: OASTContext) async throws -> OASTPayload {
        guard let client else {
            throw OASTError("OAST is off: configure a Beacon or interactsh server first")
        }
        let payload = await client.newPayload()
        try await store().addOASTPayload(payload.id, host: payload.host, context: context)
        health.payloads += 1
        return payload
    }

    /// Link payloads found in a recorded request to its exchange (minting the payload row when a
    /// Transform Tag created it).
    func attach(_ ids: [String], exchange: ExchangeID, source: ToolSource) async {
        let store = await store()
        for id in ids {
            await persisting("an OAST payload", events: events) {
                try await store.addOASTPayload(
                    id, host: "\(id).\(health.domain)",
                    context: OASTContext(tool: source.rawValue, note: "in request"))
            }
        }
        await persisting("OAST payload links", events: events) {
            try await store.attachOASTPayloads(ids, to: exchange)
        }
        health.payloads += ids.count
    }

    /// Poll now; stores and returns the new interactions (BCN-002).
    @discardableResult
    public func poll() async throws -> [StoredOASTInteraction] {
        guard let client else { throw OASTError("OAST is off") }
        let interactions: [OASTInteraction]
        do {
            interactions = try await client.poll()
        } catch {
            health.lastError = "\(error)"
            throw error
        }
        health.lastPoll = Date()
        health.lastError = nil
        let store = await store()
        var stored: [StoredOASTInteraction] = []
        for interaction in interactions {
            let summary =
                interaction.proto == "dns"
                ? "\(interaction.queryType ?? "?") \(interaction.fullID)"
                : String(interaction.rawRequest.split(whereSeparator: \.isNewline).first ?? "")
            let row = try await store.recordOASTInteraction(
                uniqueID: interaction.uniqueID, proto: interaction.proto,
                remoteAddress: interaction.remoteAddress,
                at: interaction.timestamp, raw: Array(interaction.rawRequest.utf8), summary: summary)
            stored.append(row)
            await events.publish(.oastInteraction(row.id))
            seen[interaction.uniqueID, default: []].append(interaction.proto)
        }
        if !interactions.isEmpty {
            health.interactions += interactions.count
            health.lastInteraction = Date()
        }
        return stored
    }

    /// Poll until an interaction for `id` arrives or `timeout` passes; returns the protocols seen.
    public func wait(for id: String, timeout: Duration) async -> [String] {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            if let protocols = seen[id], !protocols.isEmpty { return protocols }
            _ = try? await poll()
            if let protocols = seen[id], !protocols.isEmpty { return protocols }
            try? await Task.sleep(for: .milliseconds(250))
        }
        return seen[id] ?? []
    }

    /// Poll until no new interaction has arrived for `quiet`, or `timeout` passes (a scan's grace
    /// period, F10 §4).
    public func drain(timeout: Duration, quiet: Duration = .seconds(1)) async {
        let deadline = ContinuousClock.now + timeout
        var lastNew = ContinuousClock.now
        while ContinuousClock.now < deadline {
            let new = (try? await poll()) ?? []
            if !new.isEmpty { lastNew = .now }
            if ContinuousClock.now - lastNew >= quiet { return }
            try? await Task.sleep(for: .milliseconds(250))
        }
    }

    /// BCN-006: inject a payload into a Gulp-initiated request to itself and wait for it.
    public func test(timeout: Duration = .seconds(15)) async throws -> BeaconTestResult {
        let payload = try await mint(OASTContext(tool: "manual", note: "test beacon"))
        var target = HTTPTarget(scheme: .http, host: payload.host)
        if let connect = settings.connectTo, !connect.isEmpty {
            let parts = connect.split(separator: ":")
            target.ipOverride = String(parts[0])
            if parts.count > 1, let port = Int(parts[1]) { target.port = port }
        }
        var options = SendOptions(recordAs: .automation)
        options.record = false
        options.governed = false
        options.applyHooks = []
        options.timeouts.total = .seconds(10)
        let started = ContinuousClock.now
        let request = RawRequest(
            Bytes("GET /gulp-test HTTP/1.1\r\nHost: \(payload.host)\r\nUser-Agent: Gulp Test Beacon\r\n\r\n"))
        let sent = await engine.send(request, to: target, options: options)
        let protocols = await wait(for: payload.id, timeout: timeout)
        let elapsed = ContinuousClock.now - started
        let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        var problem: String?
        if protocols.isEmpty {
            problem =
                sent.error.map { "the test request failed (\($0.code)); is the payload domain reachable?" }
                ?? "no interaction arrived within \(Int(timeout.components.seconds)) s"
        }
        return BeaconTestResult(
            ok: !protocols.isEmpty, payload: payload, seconds: seconds, protocols: protocols, problem: problem
        )
    }

    /// The payload ids in `bytes` carrying the correlation id `prefix` (lowercase, as minted).
    nonisolated static func payloadIDs(in bytes: [UInt8], prefix: [UInt8]) -> [String] {
        guard !prefix.isEmpty, bytes.count >= prefix.count + Interactsh.nonceLength else { return [] }
        let alphabet = Set(Interactsh.zbase32Alphabet.compactMap(\.asciiValue))
        var ids: [String] = []
        var index = 0
        let last = bytes.count - prefix.count - Interactsh.nonceLength
        while index <= last {
            if bytes[index] == prefix[0], Array(bytes[index..<index + prefix.count]) == prefix {
                let nonce = bytes[(index + prefix.count)..<(index + prefix.count + Interactsh.nonceLength)]
                if nonce.allSatisfy(alphabet.contains) {
                    let id = String(
                        decoding: bytes[index..<(index + prefix.count + Interactsh.nonceLength)],
                        as: UTF8.self)
                    if !ids.contains(id) { ids.append(id) }
                    index += prefix.count + Interactsh.nonceLength
                    continue
                }
            }
            index += 1
        }
        return ids
    }
}

/// Secrets that must not sit in project or settings files (the OAST server token): the Keychain on
/// macOS, process memory elsewhere (headless runs pass it on the command line or environment).
enum OASTTokenStore {
    static let service = "com.gulp.oast"
    // nonisolated(unsafe): `memory` is only read or written while holding `lock`.
    nonisolated(unsafe) static var memory: [String: String] = [:]
    static let lock = NSLock()

    static func get(_ account: String) -> String? {
        #if canImport(Security)
        if let value = keychainGet(account) { return value }
        #endif
        return lock.withLock { memory[account] }
    }

    static func set(_ account: String, _ value: String?) {
        lock.withLock { memory[account] = value }
        #if canImport(Security)
        keychainSet(account, value)
        #endif
    }
}

#if canImport(Security)
import Security

extension OASTTokenStore {
    static func keychainGet(_ account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: account, kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data
        else {
            return nil
        }
        return String(decoding: data, as: UTF8.self)
    }

    static func keychainSet(_ account: String, _ value: String?) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(base as CFDictionary)
        guard let value else { return }
        var item = base
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }
}
#endif

extension ProjectSession {
    /// Configure OAST (BCN-004): store the settings (and the token in the secret store), then
    /// register and start polling when enabled.
    public func configureOAST(_ value: OASTSettings, token: String? = nil) async throws {
        try await settings.set(value, scope: .project)
        if let token { OASTTokenStore.set(value.serverURL, token.isEmpty ? nil : token) }
        if value.enabled { try await startOAST() } else { await stopOAST() }
    }

    /// Register and watch for payloads with the stored settings.
    public func startOAST(token: String? = nil) async throws {
        let value = settings.get(OASTSettings.self)
        let secret =
            token ?? OASTTokenStore.get(value.serverURL)
            ?? ProcessInfo.processInfo.environment["GULP_OAST_TOKEN"]
        try await oast.start(value, token: secret)
        let oast = self.oast
        let prefix = await oast.correlationID
        await recorder.setOASTWatch(prefix: prefix) { ids, exchange, source in
            await oast.attach(ids, exchange: exchange, source: source)
        }
    }

    /// Stop OAST (deregister).
    public func stopOAST() async {
        await recorder.setOASTWatch(prefix: nil, handler: nil)
        await oast.stop()
    }
}
