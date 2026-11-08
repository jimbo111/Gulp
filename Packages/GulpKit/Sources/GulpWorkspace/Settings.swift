// GulpWorkspace — the layered settings model (doc 04 §6): project override → user setting → default.
// Values are Codable groups; project values live in the project's `settings` table, user values in a
// JSON file outside projects (doc 04 §5).

import Foundation
import GulpProxy
import GulpStore
import GulpTLS

/// A versionable group of settings stored under one key.
public protocol SettingsGroup: Codable, Sendable {
    /// Storage key, e.g. `proxy`.
    static var key: String { get }
    /// The value used when neither the project nor the user set one.
    static var defaultValue: Self { get }
}

/// Where a settings value is written.
public enum SettingsScope: Sendable { case user, project }

/// Settings lookup for one project: project override → user setting → default. Reads are
/// synchronous from an in-memory snapshot; writes persist before they return.
public final class LayeredSettings: @unchecked Sendable {
    // @unchecked: every mutable property below is only touched while holding `lock`, and the
    // persistence targets (`userFile`, `store`) are themselves thread-safe.
    private let lock = NSLock()
    private var user: [String: Data]
    private var project: [String: Data]
    private let userFile: URL
    private var store: ProjectStore

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    init(userFile: URL, store: ProjectStore) async throws {
        self.userFile = userFile
        self.store = store
        self.user = Self.readUserFile(userFile)
        self.project = try await store.allSettingsJSON()
    }

    /// The effective value of `G`.
    public func get<G: SettingsGroup>(_: G.Type) -> G {
        let (projectData, userData) = locked { (project[G.key], user[G.key]) }
        let decoder = JSONDecoder()
        if let projectData, let value = try? decoder.decode(G.self, from: projectData) { return value }
        if let userData, let value = try? decoder.decode(G.self, from: userData) { return value }
        return G.defaultValue
    }

    /// Set `value` at `scope` and persist it.
    public func set<G: SettingsGroup>(_ value: G, scope: SettingsScope) async throws {
        let data = try JSONEncoder().encode(value)
        switch scope {
        case .user:
            let snapshot = locked {
                user[G.key] = data
                return user
            }
            try Self.writeUserFile(snapshot, to: userFile)
        case .project:
            let target = locked {
                project[G.key] = data
                return store
            }
            try await target.setSettingsJSON(G.key, data)
        }
    }

    /// Point project writes at a new store (after Save As).
    func switchStore(_ newStore: ProjectStore) {
        locked { store = newStore }
    }

    /// Copy every project-scope value into this project (PRJ-005 "Use settings from…").
    func importProjectSettings(_ values: [String: Data]) async throws {
        let target = locked {
            project.merge(values) { _, imported in imported }
            return store
        }
        for (key, data) in values { try await target.setSettingsJSON(key, data) }
    }

    static func readUserFile(_ url: URL) -> [String: Data] {
        guard let data = try? Data(contentsOf: url),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return [:] }
        var result: [String: Data] = [:]
        for (key, value) in object {
            result[key] = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed])
        }
        return result
    }

    static func writeUserFile(_ values: [String: Data], to url: URL) throws {
        var object: [String: Any] = [:]
        for (key, data) in values {
            object[key] = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        }
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    }
}

/// Match & Replace rules (PRX-020…PRX-022), stored with the project.
public struct MatchReplaceSettings: SettingsGroup, Hashable {
    /// Storage key.
    public static let key = "proxy.matchReplace"
    /// The built-in presets, all disabled.
    public static let defaultValue = MatchReplaceSettings(rules: MatchReplaceRule.presets)

    /// Rules, applied in order.
    public var rules: [MatchReplaceRule]

    /// Rules settings.
    public init(rules: [MatchReplaceRule]) {
        self.rules = rules
    }
}

/// Intercept toggles and rules (PRX-010…PRX-014), stored with the project.
public struct InterceptSettings: SettingsGroup, Hashable {
    /// Storage key.
    public static let key = "proxy.intercept"
    /// Off, with the default request rule (skip static assets).
    public static let defaultValue = InterceptSettings()

    /// Hold matching requests.
    public var interceptRequests = false
    /// Hold matching responses.
    public var interceptResponses = false
    /// Request rule conditions.
    public var requestRules = InterceptCondition.defaultRequestRules
    /// Response rule conditions.
    public var responseRules: [InterceptCondition] = []

    /// Default settings.
    public init() {}
}

/// Proxy settings (PRX-001): the listeners to run.
public struct ProxySettings: SettingsGroup, Hashable {
    /// Storage key.
    public static let key = "proxy"
    /// One loopback listener on 8080.
    public static let defaultValue = ProxySettings(listeners: [ProxyListenerConfig()])

    /// Settings format version.
    public var version = 1
    /// Listeners, in display order.
    public var listeners: [ProxyListenerConfig]
    /// Host globs whose TLS is not intercepted (PRX-007), e.g. `*.apple.com`.
    public var passThroughHosts: [String] = []
    /// PRX-008: never offer HTTP/2 to clients.
    public var forceHTTP1ToClient = false
    /// PRX-008: never offer HTTP/2 to servers.
    public var forceHTTP1ToServer = false

    /// Create proxy settings.
    public init(listeners: [ProxyListenerConfig], passThroughHosts: [String] = []) {
        self.listeners = listeners
        self.passThroughHosts = passThroughHosts
    }

    enum CodingKeys: String, CodingKey {
        case version, listeners, passThroughHosts, forceHTTP1ToClient, forceHTTP1ToServer
    }

    /// Interception options for `minter` from these settings.
    public func tlsOptions(minter: LeafMinter) -> ProxyTLSOptions {
        ProxyTLSOptions(
            minter: minter, passThroughHosts: passThroughHosts, forceHTTP1ToClient: forceHTTP1ToClient,
            forceHTTP1ToServer: forceHTTP1ToServer)
    }

    /// Decode, accepting settings saved before a field existed.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 1
        listeners = try container.decode([ProxyListenerConfig].self, forKey: .listeners)
        passThroughHosts = try container.decodeIfPresent([String].self, forKey: .passThroughHosts) ?? []
        forceHTTP1ToClient = try container.decodeIfPresent(Bool.self, forKey: .forceHTTP1ToClient) == true
        forceHTTP1ToServer = try container.decodeIfPresent(Bool.self, forKey: .forceHTTP1ToServer) == true
    }
}
