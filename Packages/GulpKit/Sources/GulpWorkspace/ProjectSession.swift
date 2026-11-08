// GulpWorkspace — `ProjectSession` (doc 01 §5.2): everything for one open project. The app holds one
// per window (PRJ-004); the CLI and automation API use the same type, so headless and GUI behave the
// same. M2 wires the store, settings, events, HTTP engine and proxy; later milestones add the rest.

import Foundation
import GulpCore
import GulpHTTP
import GulpProxy
import GulpStore
import GulpTLS

/// Where user-level data lives (doc 04 §5). Injectable so tests and the CLI can isolate it.
public struct WorkspaceEnvironment: Sendable {
    /// `~/Library/Application Support/Gulp` (user settings, recent projects).
    public var supportDirectory: URL
    /// `~/Library/Caches/Gulp` (temporary projects).
    public var cachesDirectory: URL
    /// Where the user's Gulp CA lives (TLS-002): the Keychain for the macOS app, a 0600 file elsewhere.
    public var caStore: any CAStore
    /// Key type for a CA generated on first use (TLS-001: RSA-2048 by default).
    public var caKeyType: CAKeyType = .rsa2048

    /// The platform's standard locations.
    public static var standard: WorkspaceEnvironment {
        let fm = FileManager.default
        let support = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        let caches = fm.urls(for: .cachesDirectory, in: .userDomainMask).first
        let supportDirectory = (support ?? fm.temporaryDirectory).appendingPathComponent("Gulp")
        #if canImport(Security)
        let caStore: any CAStore = KeychainCAStore(
            directory: supportDirectory.appendingPathComponent("CA", isDirectory: true))
        #else
        let caStore: any CAStore = FileCAStore(
            directory: supportDirectory.appendingPathComponent("ca", isDirectory: true))
        #endif
        let cachesDirectory = (caches ?? fm.temporaryDirectory).appendingPathComponent("Gulp")
        return WorkspaceEnvironment(
            supportDirectory: supportDirectory, cachesDirectory: cachesDirectory, caStore: caStore)
    }

    /// Create an environment rooted at the given directories. Without `caStore`, the CA is a file
    /// store under `supportDirectory/ca`.
    public init(supportDirectory: URL, cachesDirectory: URL, caStore: (any CAStore)? = nil) {
        self.supportDirectory = supportDirectory
        self.cachesDirectory = cachesDirectory
        let directory = supportDirectory.appendingPathComponent("ca", isDirectory: true)
        self.caStore = caStore ?? FileCAStore(directory: directory)
    }

    /// The user's CA, generated and saved on first use (TLS-001).
    public func certificateAuthority() throws -> CertificateAuthority {
        try CertificateAuthority.loadOrCreate(from: caStore, keyType: caKeyType)
    }

    var userSettingsFile: URL { supportDirectory.appendingPathComponent("user-settings.json") }
    var recentProjectsFile: URL { supportDirectory.appendingPathComponent("recent-projects.json") }
}

/// The recent-projects list (PRJ-002), most recent first.
public enum RecentProjects {
    /// How many entries are kept.
    public static let limit = 10

    /// The list, skipping files that no longer exist.
    public static func list(in environment: WorkspaceEnvironment) -> [URL] {
        guard let data = try? Data(contentsOf: environment.recentProjectsFile),
            let paths = try? JSONDecoder().decode([String].self, from: data)
        else { return [] }
        let urls = paths.map { URL(fileURLWithPath: $0) }
        return urls.filter { FileManager.default.fileExists(atPath: $0.path) }
    }

    /// Move `url` to the front of the list.
    public static func note(_ url: URL, in environment: WorkspaceEnvironment) {
        var paths = list(in: environment).map(\.path).filter { $0 != url.path }
        paths.insert(url.path, at: 0)
        let fm = FileManager.default
        try? fm.createDirectory(at: environment.supportDirectory, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(Array(paths.prefix(limit))) {
            try? data.write(to: environment.recentProjectsFile, options: .atomic)
        }
    }
}

/// Where a new project's settings come from (PRJ-005 "Use settings from…").
public enum SettingsSource: Sendable {
    /// Built-in defaults (plus user settings).
    case defaults
    /// Copy the project settings of another `.gulp` file.
    case project(URL)
}

/// Records the engine's exchanges into whichever store the session currently uses, so Save As can
/// switch files without rebuilding the engine.
actor ProjectRecorder: ExchangeRecorder {
    private var writer: StoreWriter
    private var paused = false
    private var held: [(Exchange, CheckedContinuation<ExchangeID, Never>)] = []

    init(writer: StoreWriter) {
        self.writer = writer
    }

    func record(_ exchange: Exchange) async -> ExchangeID {
        if paused {
            return await withCheckedContinuation { held.append((exchange, $0)) }
        }
        return await writer.record(exchange)
    }

    /// Hold new recordings (Save As copies the file meanwhile, PRJ-002).
    func pause() {
        paused = true
    }

    /// Continue recording into `newWriter`, first writing everything held during the pause, in order.
    func resume(with newWriter: StoreWriter) async {
        writer = newWriter
        while !held.isEmpty {
            let batch = held
            held = []
            for (exchange, continuation) in batch {
                continuation.resume(returning: await newWriter.record(exchange))
            }
        }
        paused = false
    }
}

/// One open project.
public actor ProjectSession {
    /// Session identity.
    public nonisolated let id = UUID()
    /// Typed events for UI and tools.
    public nonisolated let events: EventBus
    /// The HTTP engine every tool sends through (records into this project).
    public nonisolated let http: NIOHTTPEngine
    /// The proxy listeners.
    public nonisolated let proxy: ProxyServer
    /// Layered settings (project → user → default).
    public nonisolated let settings: LayeredSettings
    /// User-level locations.
    public nonisolated let environment: WorkspaceEnvironment

    /// The project database.
    public private(set) var store: ProjectStore
    /// A temporary project is deleted on close unless saved (PRJ-001).
    public private(set) var isTemporary: Bool
    private let recorder: ProjectRecorder
    /// Mints leaves for TLS interception; nil when the CA could not be loaded (CONNECT then fails
    /// with a clear page instead of the project failing to open).
    public nonisolated let minter: LeafMinter?

    private init(
        store: ProjectStore, events: EventBus, settings: LayeredSettings, isTemporary: Bool,
        environment: WorkspaceEnvironment, minter: LeafMinter?
    ) {
        self.store = store
        self.events = events
        self.settings = settings
        self.isTemporary = isTemporary
        self.environment = environment
        let recorder = ProjectRecorder(writer: store.writer)
        self.recorder = recorder
        let engine = NIOHTTPEngine(recorder: recorder)
        self.http = engine
        self.minter = minter
        let proxySettings = settings.get(ProxySettings.self)
        self.proxy = ProxyServer(engine: engine, tls: minter.map { proxySettings.tlsOptions(minter: $0) })
    }

    /// The project file.
    public var url: URL { store.url }

    /// Start instantly with a temporary project in the caches directory (PRJ-001).
    public static func openTemporary(
        environment: WorkspaceEnvironment = .standard
    ) async throws -> ProjectSession {
        let fm = FileManager.default
        try fm.createDirectory(at: environment.cachesDirectory, withIntermediateDirectories: true)
        let url = environment.cachesDirectory.appendingPathComponent("temp-\(UUID().uuidString).gulp")
        return try await make(url: url, environment: environment, temporary: true, settingsFrom: .defaults)
    }

    /// Open the project at `url`, creating it if it does not exist (PRJ-002). The file is the live
    /// database, so opening needs no import step.
    public static func open(
        at url: URL, environment: WorkspaceEnvironment = .standard, settingsFrom: SettingsSource = .defaults
    ) async throws -> ProjectSession {
        let session = try await make(
            url: url, environment: environment, temporary: false, settingsFrom: settingsFrom)
        RecentProjects.note(url, in: environment)
        return session
    }

    private static func make(
        url: URL, environment: WorkspaceEnvironment, temporary: Bool, settingsFrom: SettingsSource
    ) async throws -> ProjectSession {
        let events = EventBus()
        let isNew = !FileManager.default.fileExists(atPath: url.path)
        let store = try ProjectStore.open(at: url, eventBus: events)
        let settings = try await LayeredSettings(userFile: environment.userSettingsFile, store: store)
        if isNew, case .project(let source) = settingsFrom {
            let template = try ProjectStore.open(at: source)
            let values = try await template.allSettingsJSON()
            try await template.close()
            try await settings.importProjectSettings(values)
        }
        let minter = (try? environment.certificateAuthority()).flatMap { try? LeafMinter(authority: $0) }
        return ProjectSession(
            store: store, events: events, settings: settings, isTemporary: temporary,
            environment: environment, minter: minter)
    }

    /// Save the project to `url` and continue working there (PRJ-002). A saved temporary project
    /// becomes a normal one and its temporary file is removed.
    public func saveAs(_ destination: URL) async throws {
        let current = store.url.standardizedFileURL.resolvingSymlinksInPath()
        guard destination.standardizedFileURL.resolvingSymlinksInPath() != current else {
            throw GulpError(
                message: "The project is already saved at \(destination.lastPathComponent).",
                recoverySuggestion: "Choose a different file name.")
        }
        // Recordings made while the file is copied are held, then written to the new file, so
        // nothing lands in the old file after the copy (and no id is handed out twice).
        // Overwriting a project that is open elsewhere would destroy it: its lock says so.
        try ProjectStore.ensureNotOpen(destination)
        await recorder.pause()
        let newStore: ProjectStore
        do {
            Self.removeDatabaseFiles(destination)
            try await store.backup(to: destination)
            newStore = try ProjectStore.open(at: destination, eventBus: events)
        } catch {
            await recorder.resume(with: store.writer)
            throw error
        }
        let oldStore = store
        settings.switchStore(newStore)
        store = newStore
        await recorder.resume(with: newStore.writer)
        try await oldStore.close()
        if isTemporary { Self.removeDatabaseFiles(oldStore.url) }
        isTemporary = false
        RecentProjects.note(destination, in: environment)
    }

    /// Start every enabled proxy listener from the settings (PRX-001). Returns the bound port per
    /// listener, or the user-facing bind error.
    public func startProxyListeners() async -> [UUID: Result<Int, GulpError>] {
        var results: [UUID: Result<Int, GulpError>] = [:]
        if let minter { await proxy.setTLS(settings.get(ProxySettings.self).tlsOptions(minter: minter)) }
        for listener in settings.get(ProxySettings.self).listeners where listener.enabled {
            do {
                results[listener.id] = .success(try await proxy.start(listener))
            } catch let error as GulpError {
                results[listener.id] = .failure(error)
            } catch {
                results[listener.id] = .failure(GulpError(message: "\(error)"))
            }
        }
        return results
    }

    /// Project name and notes (PRJ-006), stored in `meta`.
    public func setInfo(name: String?, notes: String?) async throws {
        if let name { try await store.setMeta("name", name) }
        if let notes { try await store.setMeta("notes", notes) }
    }

    /// Stop the proxy, flush everything and close the file. A temporary project is deleted unless
    /// `keepTemporary` (PRJ-001: "prompt to save on close (or discard)").
    public func close(keepTemporary: Bool = false) async throws {
        await proxy.stopAll()
        await http.shutdown()
        try await store.close()
        if isTemporary && !keepTemporary { Self.removeDatabaseFiles(store.url) }
    }

    static func removeDatabaseFiles(_ url: URL) {
        for suffix in ["", "-wal", "-shm", ".gulplock"] {
            try? FileManager.default.removeItem(atPath: url.path + suffix)
        }
    }
}
