// GulpStore — one open `.gulp` project file (doc 04 §4): a WAL-mode SQLite database with schema
// migrations, the write coalescer, and async paged reads (the main thread never waits on the
// database, CLAUDE.md §4).

import Foundation
import GRDB
import GulpCore

/// An open project database.
public final class ProjectStore: Sendable {
    /// The `.gulp` file.
    public let url: URL
    /// Batched exchange writes; also the engine's recorder (via GulpWorkspace).
    public let writer: StoreWriter
    let pool: DatabasePool
    /// Where changes outside the writer (WebSocket rows) are announced.
    let eventBus: EventBus?
    private let lock: ProjectLock

    private init(url: URL, pool: DatabasePool, writer: StoreWriter, lock: ProjectLock, eventBus: EventBus?) {
        self.url = url
        self.pool = pool
        self.writer = writer
        self.lock = lock
        self.eventBus = eventBus
    }

    /// Open (creating if needed) the project at `url`, migrating it to the current schema.
    public static func open(
        at url: URL, eventBus: EventBus? = nil, durable: Bool = false
    ) throws -> ProjectStore {
        let lock = try ProjectLock(for: url)
        do {
            return try openLocked(at: url, eventBus: eventBus, durable: durable, lock: lock)
        } catch {
            lock.release()
            throw error
        }
    }

    /// Throw `StoreError.alreadyOpen` if another session has the project at `url` open.
    public static func ensureNotOpen(_ url: URL) throws {
        try ProjectLock(for: url).release()
    }

    private static func openLocked(
        at url: URL, eventBus: EventBus?, durable: Bool, lock: ProjectLock
    ) throws -> ProjectStore {
        var configuration = Configuration()
        configuration.prepareDatabase { db in
            try db.execute(sql: "PRAGMA synchronous = NORMAL")
            db.add(function: StoreFunctions.regexp)  // GulpQL regex push-down (HIS-024)
        }
        let pool = try DatabasePool(path: url.path, configuration: configuration)
        // A file written by a newer Gulp has migrations this build doesn't know: refuse, don't guess.
        if try pool.read({ db in try Schema.migrator().hasBeenSuperseded(db) }) {
            throw StoreError.newerSchema(Schema.version)
        }
        try Schema.migrator().migrate(pool)
        try pool.write { db in
            try db.execute(
                sql: "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
                arguments: [String(Schema.version)])
        }
        let nextID = try pool.write { db -> ExchangeID in
            let hasUUID = try String.fetchOne(db, sql: "SELECT value FROM meta WHERE key = 'project_uuid'")
            if hasUUID == nil {
                let meta: [(String, String)] = [
                    ("schema_version", String(Schema.version)), ("project_uuid", UUID().uuidString),
                    ("created_at", String(Date().timeIntervalSince1970)), ("app_version", "0.2.0"),
                ]
                for (key, value) in meta {
                    try db.execute(
                        sql: "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                        arguments: [key, value])
                }
            }
            let next = "SELECT COALESCE(MAX(id), 0) + 1 FROM exchanges"
            return try ExchangeID.fetchOne(db, sql: next) ?? 1
        }
        let writer = StoreWriter(pool: pool, nextID: nextID, eventBus: eventBus, durable: durable)
        return ProjectStore(url: url, pool: pool, writer: writer, lock: lock, eventBus: eventBus)
    }

    /// Flush pending writes, checkpoint the WAL into the main file, and release the file. The store
    /// must not be used afterwards.
    public func close() async throws {
        await writer.flush()
        try? await updateStatistics()  // so the next open plans GulpQL queries well (HIS-024)
        try await pool.writeWithoutTransaction { db in
            try db.checkpoint(.truncate)
        }
        try pool.close()
        // Unlink while still holding the lock, so nobody can lock the old file in between.
        try? FileManager.default.removeItem(atPath: ProjectLock.path(for: url))
        lock.release()
    }

    /// Write a consistent copy of the whole project to `url` (Save As, PRJ-002), using SQLite's
    /// online backup so it is safe while the project is in use.
    public func backup(to url: URL) async throws {
        await writer.flush()
        let destination = try DatabaseQueue(path: url.path)
        try pool.backup(to: destination)
        try destination.close()
    }

    /// Every project-scope settings value, by key (for "Use settings from…", PRJ-005).
    public func allSettingsJSON() async throws -> [String: Data] {
        let rows = try await pool.read { db in
            try Row.fetchAll(db, sql: "SELECT key, value_json FROM settings WHERE scope = 'project'")
                .map { (row: Row) -> (String, String) in (row["key"], row["value_json"] ?? "null") }
        }
        return Dictionary(rows.map { ($0.0, Data($0.1.utf8)) }, uniquingKeysWith: { _, last in last })
    }

    // MARK: reads

    /// The full exchange (bytes included), if it exists.
    public func exchange(id: ExchangeID) async throws -> Exchange? {
        try await pool.read { db in try ExchangeRows.load(id, from: db) }
    }

    /// One page of History rows (HIS-002): never more than `limit` rows are loaded.
    public func summaries(
        filter: HistoryFilter = HistoryFilter(), sort: HistorySort = .idAscending, offset: Int, limit: Int
    ) async throws -> [ExchangeSummary] {
        let (clause, arguments) = filter.sql()
        let sql = """
            SELECT \(ExchangeRows.summaryColumns) FROM exchanges WHERE \(clause) ORDER BY \(sort.sql) \
            LIMIT ? OFFSET ?
            """
        let all = arguments + [max(0, limit).databaseValue, max(0, offset).databaseValue]
        return try await pool.read { db in
            try Row.fetchAll(db, sql: sql, arguments: StatementArguments(all)).map(ExchangeRows.summary)
        }
    }

    /// The number of rows matching `filter`.
    public func count(filter: HistoryFilter = HistoryFilter()) async throws -> Int {
        let (clause, arguments) = filter.sql()
        let sql = "SELECT COUNT(*) FROM exchanges WHERE \(clause)"
        return try await pool.read { db in
            try Int.fetchOne(db, sql: sql, arguments: StatementArguments(arguments)) ?? 0
        }
    }

    /// A `meta` value (schema_version, project_uuid, created_at, app_version, name, notes, …).
    public func meta(_ key: String) async throws -> String? {
        try await pool.read { db in
            try String.fetchOne(db, sql: "SELECT value FROM meta WHERE key = ?", arguments: [key])
        }
    }

    /// A project-scope settings value as JSON (doc 04 §6).
    public func settingsJSON(_ key: String) async throws -> Data? {
        let json = try await pool.read { db in
            let sql = "SELECT value_json FROM settings WHERE scope = 'project' AND key = ?"
            return try String.fetchOne(db, sql: sql, arguments: [key])
        }
        return json.map { Data($0.utf8) }
    }

    // MARK: writes (annotations, deletes, settings)

    /// Set or clear the highlight of exchanges (HIS-005).
    public func setHighlight(_ highlight: Highlight?, for ids: [ExchangeID]) async throws {
        let sql = "UPDATE exchanges SET highlight = ? WHERE id = ?"
        try await updateEach(ids, sql: sql, value: highlight?.rawValue)
    }

    /// Set or clear the comment of exchanges (HIS-005).
    public func setComment(_ comment: String?, for ids: [ExchangeID]) async throws {
        try await updateEach(ids, sql: "UPDATE exchanges SET comment = ? WHERE id = ?", value: comment)
    }

    private func updateEach(_ ids: [ExchangeID], sql: String, value: String?) async throws {
        await writer.flush()
        try await pool.write { db in
            for id in ids { try db.execute(sql: sql, arguments: [value, id]) }
        }
    }

    /// Delete exchanges and their search entries (HIS-004). Blobs are reclaimed by Compact.
    public func delete(_ ids: [ExchangeID]) async throws {
        await writer.flush()
        try await pool.write { db in
            for id in ids {
                try db.execute(sql: "DELETE FROM fts_exchanges WHERE rowid = ?", arguments: [id])
                try db.execute(sql: "DELETE FROM exchanges WHERE id = ?", arguments: [id])
            }
        }
    }

    /// Set a `meta` value.
    public func setMeta(_ key: String, _ value: String) async throws {
        try await pool.write { db in
            let sql = "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)"
            try db.execute(sql: sql, arguments: [key, value])
        }
    }

    /// Store a project-scope settings value as JSON (doc 04 §6).
    public func setSettingsJSON(_ key: String, _ json: Data) async throws {
        let text = String(decoding: json, as: UTF8.self)
        try await pool.write { db in
            try db.execute(
                sql: "INSERT OR REPLACE INTO settings (scope, key, value_json) VALUES ('project', ?, ?)",
                arguments: [key, text])
        }
    }
}
