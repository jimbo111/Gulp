// GulpWorkspace — `ProjectSession` (doc 01 §5.2): everything for one open project. The app holds one
// per window (PRJ-004); the CLI and automation API use the same type, so headless and GUI behave the
// same. M2 wires the store, settings, events, HTTP engine and proxy; later milestones add the rest.

import Foundation
import GulpCodec
import GulpCore
import GulpHTTP
import GulpProxy
import GulpQuery
import GulpRepeater
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
    /// Where signing keys and other secrets live instead of the project file: the Keychain for the
    /// macOS app, 0600 files under `supportDirectory/secrets` elsewhere.
    public var secretStore: any SecretStore

    /// The platform's standard locations. `GULP_SUPPORT_DIR` overrides them with one folder and a
    /// file CA store (automation and CI: no Keychain, nothing shared with the user's install).
    public static var standard: WorkspaceEnvironment {
        let fm = FileManager.default
        if let override = ProcessInfo.processInfo.environment["GULP_SUPPORT_DIR"], !override.isEmpty {
            let root = URL(fileURLWithPath: override, isDirectory: true)
            return WorkspaceEnvironment(
                supportDirectory: root, cachesDirectory: root.appendingPathComponent("Caches"))
        }
        let support = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        let caches = fm.urls(for: .cachesDirectory, in: .userDomainMask).first
        let supportDirectory = (support ?? fm.temporaryDirectory).appendingPathComponent("Gulp")
        #if canImport(Security)
        let caStore: any CAStore = KeychainCAStore(
            directory: supportDirectory.appendingPathComponent("CA", isDirectory: true))
        let secretStore: any SecretStore = KeychainSecretStore()
        #else
        let caStore: any CAStore = FileCAStore(
            directory: supportDirectory.appendingPathComponent("ca", isDirectory: true))
        let secretStore: any SecretStore = FileSecretStore(
            directory: supportDirectory.appendingPathComponent("secrets", isDirectory: true))
        #endif
        let cachesDirectory = (caches ?? fm.temporaryDirectory).appendingPathComponent("Gulp")
        return WorkspaceEnvironment(
            supportDirectory: supportDirectory, cachesDirectory: cachesDirectory, caStore: caStore,
            secretStore: secretStore)
    }

    /// Create an environment rooted at the given directories. Without `caStore`, the CA is a file
    /// store under `supportDirectory/ca`; without `secretStore`, secrets are 0600 files under
    /// `supportDirectory/secrets`.
    public init(
        supportDirectory: URL, cachesDirectory: URL, caStore: (any CAStore)? = nil,
        secretStore: (any SecretStore)? = nil
    ) {
        self.supportDirectory = supportDirectory
        self.cachesDirectory = cachesDirectory
        let directory = supportDirectory.appendingPathComponent("ca", isDirectory: true)
        self.caStore = caStore ?? FileCAStore(directory: directory)
        self.secretStore =
            secretStore
            ?? FileSecretStore(
                directory: supportDirectory.appendingPathComponent("secrets", isDirectory: true))
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

/// Records the engine's exchanges (and the proxy's WebSocket traffic) into whichever store the
/// session currently uses, so Save As can switch files without rebuilding the engine.
actor ProjectRecorder: ExchangeRecorder, WebSocketRecorder {
    private var store: ProjectStore
    private var writer: StoreWriter
    private var paused = false
    /// Recordings and updates that arrived during a pause, in arrival order.
    private var held: [HeldWrite] = []
    private var waiting: [CheckedContinuation<Void, Never>] = []
    /// TGT-024: when set, proxy exchanges out of this scope are not recorded.
    private var proxyScope: ScopeService?
    /// F10: the OAST session's correlation id; requests carrying it have their payloads linked to
    /// the exchange by `oastHandler`.
    private var oastPrefix: [UInt8]?
    private var oastHandler: (@Sendable ([String], ExchangeID, ToolSource) async -> Void)?

    /// Watch recorded requests for OAST payloads with `prefix` (nil stops watching).
    func setOASTWatch(
        prefix: String?, handler: (@Sendable ([String], ExchangeID, ToolSource) async -> Void)?
    ) {
        oastPrefix = prefix.map { Array($0.utf8) }
        oastHandler = handler
    }

    /// Drop out-of-scope proxy exchanges (`scope`), or record everything (nil).
    func setProxyScope(_ scope: ScopeService?) {
        proxyScope = scope
    }

    /// The id that stands for "not recorded" (an out-of-scope proxy exchange, TGT-024).
    static let notRecorded: ExchangeID = 0

    init(store: ProjectStore) {
        self.store = store
        self.writer = store.writer
    }

    func record(_ exchange: Exchange) async -> ExchangeID {
        if exchange.source == .proxy, let proxyScope {
            let path = (exchange.derived.path ?? "/") + (exchange.derived.query.map { "?" + $0 } ?? "")
            if !proxyScope.isInScope(exchange.target, path: path) { return Self.notRecorded }
        }
        let id: ExchangeID
        if paused {
            id = await withCheckedContinuation { held.append(.record(exchange, $0)) }
        } else {
            id = await writer.record(exchange)
        }
        if let oastPrefix, let oastHandler, id != Self.notRecorded {
            let ids = OASTService.payloadIDs(in: exchange.request.bytes.rawBytes, prefix: oastPrefix)
            if !ids.isEmpty {
                let source = exchange.source
                Task { await oastHandler(ids, id, source) }
            }
        }
        return id
    }

    func update(_ exchange: Exchange) async {
        guard exchange.id != Self.notRecorded else { return }
        if paused {
            held.append(.update(exchange))
        } else {
            await writer.update(exchange)
        }
    }

    /// A write held while Save As copies the file.
    private enum HeldWrite {
        case record(Exchange, CheckedContinuation<ExchangeID, Never>)
        case update(Exchange)
    }

    /// Hold new recordings and updates (Save As copies the file meanwhile, PRJ-002).
    func pause() {
        paused = true
    }

    /// Continue recording into `newStore`, first writing everything held during the pause, in order.
    func resume(with newStore: ProjectStore) async {
        store = newStore
        let newWriter = newStore.writer
        writer = newWriter
        while !held.isEmpty {
            let batch = held
            held = []
            for write in batch {
                switch write {
                case .record(let exchange, let continuation):
                    continuation.resume(returning: await newWriter.record(exchange))
                case .update(let exchange):
                    await newWriter.update(exchange)
                }
            }
        }
        paused = false
        let woken = waiting
        waiting = []
        for continuation in woken { continuation.resume() }
    }

    /// The store to write WebSocket rows to, once any Save As copy has finished.
    private func currentStore() async -> ProjectStore {
        while paused { await withCheckedContinuation { waiting.append($0) } }
        return store
    }

    func webSocketOpened(upgradeExchangeID: ExchangeID?, url: String) async -> Int64? {
        guard upgradeExchangeID != Self.notRecorded else { return nil }  // its upgrade was out of scope
        return try? await currentStore().openWebSocket(upgradeExchangeID: upgradeExchangeID, url: url)
    }

    func webSocketMessage(
        _ connection: Int64, direction: WSDirection, message: WSMessage, original: [UInt8]?, dropped: Bool
    ) async {
        _ = try? await currentStore().recordWebSocketMessage(
            connection: connection, direction: direction.rawValue, opcode: Int(message.opcode),
            payload: message.payload, frames: message.frames, originalPayload: original,
            comment: dropped ? "Dropped in Intercept" : nil)
    }

    func webSocketClosed(_ connection: Int64, code: Int?) async {
        try? await currentStore().closeWebSocket(connection, code: code)
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
    /// Session handling state (cookie jar, identities, rules, macros; F15).
    public nonisolated let sessionState: SessionState
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
    /// Ports of the listeners started by `startProxyListeners`, in settings order.
    public private(set) var listenerPorts: [Int] = []
    /// Long-running work tied to the session (the site map's listener); cancelled and awaited by
    /// `close()` so nothing reads the store while it closes.
    var backgroundTasks: [Task<Void, Never>] = []
    let recorder: ProjectRecorder
    /// Mints leaves for TLS interception; nil when the CA could not be loaded (CONNECT then fails
    /// with a clear page instead of the project failing to open).
    public nonisolated let minter: LeafMinter?
    /// The intercept queue (PRX-010…PRX-014).
    public nonisolated let intercept: InterceptQueue
    /// Match & Replace for proxy traffic and, per rule, every tool (PRX-020…PRX-022).
    public nonisolated let matchReplace: MatchReplaceHook
    /// Transform Tag variables and counters (F12 DEC-021), shared by every send of the project.
    public nonisolated let tagState: TagState
    /// The Comparer's items and the Decoder's input (CMP-001, DEC-004).
    public nonisolated let inbox = ToolInbox()
    /// The Repeater's tabs and sends (F06), stored in this project.
    public nonisolated let repeater: RepeaterService
    /// ScopeGuard (F04 TGT-023): active tools ask it before sending; manual sends ask the user.
    public nonisolated let scopeGuard: ScopeGuard
    /// The live site map (F04 TGT-001).
    public nonisolated let siteMap: SiteMapService
    /// The coverage index (F04 JRN-001).
    public nonisolated let coverage: CoverageService
    /// The live passive scanner (F08 §4).
    public nonisolated let passiveScan: PassiveScanService
    /// Running active tasks, for the panic stop (F20 GOV-001).
    public nonisolated let activeTasks = ActiveTasks()
    /// OAST (F10): payloads, polling, interactions.
    public nonisolated let oast: OASTService
    /// The file the session writes to now: long-running work resolves the store through it, so it
    /// follows Save As instead of writing to the closed old file.
    nonisolated let currentStore: CurrentStore

    private init(
        store: ProjectStore, events: EventBus, settings: LayeredSettings, isTemporary: Bool,
        environment: WorkspaceEnvironment, minter: LeafMinter?
    ) {
        self.store = store
        self.events = events
        self.settings = settings
        self.isTemporary = isTemporary
        self.environment = environment
        let recorder = ProjectRecorder(store: store)
        self.recorder = recorder
        let matchReplace = MatchReplaceHook(rules: settings.get(MatchReplaceSettings.self).rules)
        self.matchReplace = matchReplace
        let tagState = TagState(variables: settings.get(VariablesSettings.self).values)
        self.tagState = tagState
        let sessionLog: @Sendable (String) -> Void = { message in
            Task {
                await events.publish(.log(LogEntry(level: .info, message: message, module: "gulp.session")))
            }
        }
        // Signing keys come from the secret store, never the project file (see SessionSecrets.swift).
        let (sessionSettings, missingSecrets) = settings.get(SessionSettings.self)
            .resolvingSigningSecrets(from: environment.secretStore)
        if !missingSecrets.isEmpty {
            let message =
                "\(missingSecrets.count) signing key(s) of this project aren't in this machine's secret store; "
                + "re-enter them in the session rules to sign requests."
            Task {
                await events.publish(
                    .log(LogEntry(level: .warning, message: message, module: "gulp.session")))
            }
        }
        let sessionState = SessionState(sessionSettings, log: sessionLog)
        self.sessionState = sessionState
        let engine = NIOHTTPEngine(
            requestHooks: [
                SessionRequestHook(state: sessionState), TransformTagHook(state: tagState), matchReplace,
                SessionSignerHook(state: sessionState),
            ],
            responseHooks: [matchReplace, SessionResponseHook(state: sessionState)], recorder: recorder)
        self.http = engine
        self.minter = minter
        let intercept = InterceptQueue(events: events)
        self.intercept = intercept
        let proxySettings = settings.get(ProxySettings.self)
        self.proxy = ProxyServer(
            engine: engine, tls: minter.map { proxySettings.tlsOptions(minter: $0) }, intercept: intercept,
            matchReplace: matchReplace, webSockets: recorder)
        let currentStore = CurrentStore(store)
        self.currentStore = currentStore
        let scopeGuard = ScopeGuard()
        self.scopeGuard = scopeGuard
        self.repeater = RepeaterService(
            engine: engine, persistence: StoreRepeaterPersistence(currentStore),
            scope: { await scopeGuard.current })
        self.siteMap = SiteMapService { await currentStore.store }
        self.coverage = CoverageService { await currentStore.store }
        self.oast = OASTService(
            engine: engine, store: { await currentStore.store }, tagState: tagState, events: events)
        self.passiveScan = PassiveScanService(
            store: { await currentStore.store }, config: { settings.get(PassiveScanConfig.self) },
            scopeIsEmpty: { await scopeGuard.current.rules.isEmpty }, events: events)
    }

    /// Apply the stored intercept settings to the queue (call after opening or changing them).
    public func applyInterceptSettings() async {
        let stored = settings.get(InterceptSettings.self)
        await intercept.setRules(
            requests: stored.requestRules, responses: stored.responseRules, webSockets: stored.webSocketRules)
        await intercept.setIntercepting(
            requests: stored.interceptRequests, responses: stored.interceptResponses)
        await intercept.setInterceptingWebSockets(stored.interceptWebSockets)
        // Stored queries were validated when set; one that no longer parses falls back to the rules.
        await intercept.setQueries(
            request: stored.requestQuery.isEmpty ? nil : try? GulpQLPredicate(stored.requestQuery),
            response: stored.responseQuery.isEmpty ? nil : try? GulpQLPredicate(stored.responseQuery))
    }

    /// Store and apply Match & Replace rules (PRX-020).
    public func setMatchReplaceRules(_ rules: [MatchReplaceRule]) async throws {
        for rule in rules where !rule.when.isEmpty {
            _ = try GulpQLPredicate(rule.when)  // PRX-025: a condition that doesn't parse is refused
        }
        try await settings.set(MatchReplaceSettings(rules: rules), scope: .project)
        matchReplace.setRules(rules)
    }

    /// Store and apply intercept settings (PRX-010…PRX-014).
    public func setInterceptSettings(_ value: InterceptSettings) async throws {
        for query in [value.requestQuery, value.responseQuery] where !query.isEmpty {
            _ = try GulpQLPredicate(query)  // a rule that doesn't parse is refused, not stored
        }
        try await settings.set(value, scope: .project)
        await applyInterceptSettings()
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
        let session = ProjectSession(
            store: store, events: events, settings: settings, isTemporary: temporary,
            environment: environment, minter: minter)
        await session.applyInterceptSettings()
        try? await session.repeater.load()
        if let scope = try? await store.loadScope() { await session.scopeGuard.set(scope) }
        await session.applyProxyScope()
        await session.startSiteMap()
        await session.startPassiveScan()
        await session.applyNetworkSettings()
        await session.startSession()
        await session.moveInlineSigningSecrets()
        if session.settings.get(OASTSettings.self).enabled {
            do {
                try await session.startOAST()
            } catch {
                await events.publish(
                    .log(LogEntry(level: .warning, message: "OAST: \(error)", module: "gulp.oast")))
            }
        }
        return session
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
        await repeater.flush()  // pending Repeater drafts go into the copy
        await recorder.pause()
        let newStore: ProjectStore
        do {
            Self.removeDatabaseFiles(destination)
            try await store.backup(to: destination)
            newStore = try ProjectStore.open(at: destination, eventBus: events)
            _ = try? await newStore.loadScope()
        } catch {
            await recorder.resume(with: store)
            throw error
        }
        let oldStore = store
        settings.switchStore(newStore)
        store = newStore
        await currentStore.set(newStore)
        await coverage.invalidate()
        await recorder.resume(with: newStore)
        await siteMap.idle()  // a site-map read still on the old file would make close fail
        try await oldStore.close()
        if isTemporary { Self.removeDatabaseFiles(oldStore.url) }
        isTemporary = false
        RecentProjects.note(destination, in: environment)
    }

    /// Apply "Use scope for the proxy" (TGT-024) with the current scope.
    func applyProxyScope() async {
        let on = settings.get(ProxySettings.self).useScope
        let current = await scopeGuard.current
        await recorder.setProxyScope(on ? current : nil)
        // GulpQL rules (HIS-027) see the project's scope whether or not the proxy is limited to it.
        await intercept.setScope(current)
        matchReplace.setScope(current)
    }

    /// "Use scope for the proxy" (TGT-024 / PRX-045): store it in the project and apply it now.
    public func setUseScopeForProxy(_ on: Bool) async throws {
        var proxySettings = settings.get(ProxySettings.self)
        proxySettings.useScope = on
        try await settings.set(proxySettings, scope: .project)
        await applyProxyScope()
    }

    /// Start every enabled proxy listener from the settings (PRX-001). Returns the bound port per
    /// listener, or the user-facing bind error.
    public func startProxyListeners() async -> [UUID: Result<Int, GulpError>] {
        await applyProxyScope()
        var results: [UUID: Result<Int, GulpError>] = [:]
        if let minter { await proxy.setTLS(settings.get(ProxySettings.self).tlsOptions(minter: minter)) }
        listenerPorts = []
        for listener in settings.get(ProxySettings.self).listeners where listener.enabled {
            do {
                let port = try await proxy.start(listener)
                listenerPorts.append(port)
                results[listener.id] = .success(port)
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

    /// Stop active tools and the proxy, flush everything and close the file. A temporary project is
    /// deleted unless `keepTemporary` (PRJ-001: "prompt to save on close (or discard)").
    public func close(keepTemporary: Bool = false) async throws {
        await activeTasks.cancelAll()  // scans, attacks, crawls: stopped and their results written
        let tasks = backgroundTasks
        backgroundTasks = []
        for task in tasks { task.cancel() }
        for task in tasks { await task.value }
        await repeater.flush()
        await proxy.stopAll()
        await stopOAST()
        await http.shutdown()
        await passiveScan.drain()  // headless runs (gulp-cli proxy) finish scanning what they recorded
        try await store.close()
        if isTemporary && !keepTemporary { Self.removeDatabaseFiles(store.url) }
    }

    static func removeDatabaseFiles(_ url: URL) {
        for suffix in ["", "-wal", "-shm", ".gulplock"] {
            try? FileManager.default.removeItem(atPath: url.path + suffix)
        }
    }
}
