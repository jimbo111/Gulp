// GulpStore — WebSocket connections and messages (F01 PRX-031/PRX-032; doc 04 §4 `ws_connections`,
// `ws_messages`). Messages are written one at a time: sockets are far less chatty than HTTP traffic,
// and a message should be visible as soon as it passes.

import Foundation
import GRDB
import GulpCore

/// One recorded WebSocket connection (PRX-032 connection list).
public struct WebSocketConnectionSummary: Sendable, Hashable, Identifiable {
    /// Row id.
    public var id: Int64
    /// The upgrade request's exchange, if recorded.
    public var upgradeExchangeID: ExchangeID?
    /// `ws://` / `wss://` URL.
    public var url: String
    /// When it opened.
    public var openedAt: Date
    /// When it closed (nil while open).
    public var closedAt: Date?
    /// Close code from the close frame, if any.
    public var closeCode: Int?
    /// Messages recorded.
    public var messageCount: Int
}

/// One recorded WebSocket message (PRX-031).
public struct WebSocketMessageRecord: Sendable, Hashable, Identifiable {
    /// Row id.
    public var id: Int64
    /// 0 = client → server, 1 = server → client.
    public var direction: Int
    /// Opcode (1 text, 2 binary, 8 close, 9 ping, 10 pong).
    public var opcode: Int
    /// When it passed.
    public var createdAt: Date
    /// The (reassembled) payload.
    public var payload: [UInt8]
    /// Frame boundaries.
    public var frames: [WSFrameInfo]
}

extension ProjectStore {
    /// Record a newly opened connection; returns its id.
    public func openWebSocket(upgradeExchangeID: ExchangeID?, url: String) async throws -> Int64 {
        // The upgrade's id is handed out before its row is written (writes are coalesced): flush so
        // the foreign key finds it.
        if upgradeExchangeID != nil { await writer.flush() }
        let id = try await pool.write { db in
            try db.execute(
                sql: "INSERT INTO ws_connections (upgrade_exchange_id, url, opened_at) VALUES (?, ?, ?)",
                arguments: [upgradeExchangeID, url, Date().timeIntervalSince1970])
            return db.lastInsertedRowID
        }
        await eventBus?.publish(.wsConnectionChanged(id))
        return id
    }

    /// Record one message; returns its id.
    @discardableResult
    public func recordWebSocketMessage(
        connection: Int64, direction: Int, opcode: Int, payload: [UInt8], frames: [WSFrameInfo]
    ) async throws -> Int64 {
        let framesJSON = String(decoding: try JSONEncoder().encode(frames), as: UTF8.self)
        let id = try await pool.write { db in
            let blob = try BlobStore.store(payload, in: db)
            try db.execute(
                sql: """
                    INSERT INTO ws_messages (connection_id, direction, opcode, created_at, payload_blob, \
                    length, frames_json) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                arguments: [
                    connection, direction, opcode, Date().timeIntervalSince1970, blob, payload.count,
                    framesJSON,
                ])
            return db.lastInsertedRowID
        }
        await eventBus?.publish(.wsMessage(id))
        return id
    }

    /// Mark a connection closed.
    public func closeWebSocket(_ connection: Int64, code: Int?) async throws {
        try await pool.write { db in
            try db.execute(
                sql: "UPDATE ws_connections SET closed_at = ?, close_code = ? WHERE id = ?",
                arguments: [Date().timeIntervalSince1970, code, connection])
        }
        await eventBus?.publish(.wsConnectionChanged(connection))
    }

    /// All connections, newest last, with their message counts.
    public func webSocketConnections() async throws -> [WebSocketConnectionSummary] {
        try await pool.read { db in
            let sql = """
                SELECT c.id, c.upgrade_exchange_id, c.url, c.opened_at, c.closed_at, c.close_code,
                (SELECT COUNT(*) FROM ws_messages m WHERE m.connection_id = c.id) AS message_count
                FROM ws_connections c ORDER BY c.id
                """
            return try Row.fetchAll(db, sql: sql).map { row in
                let closed: Double? = row["closed_at"]
                return WebSocketConnectionSummary(
                    id: row["id"], upgradeExchangeID: row["upgrade_exchange_id"], url: row["url"] ?? "",
                    openedAt: Date(timeIntervalSince1970: row["opened_at"] ?? 0),
                    closedAt: closed.map(Date.init(timeIntervalSince1970:)), closeCode: row["close_code"],
                    messageCount: row["message_count"] ?? 0)
            }
        }
    }

    /// A connection's messages in order.
    public func webSocketMessages(connection: Int64) async throws -> [WebSocketMessageRecord] {
        try await pool.read { db in
            let sql = "SELECT * FROM ws_messages WHERE connection_id = ? ORDER BY id"
            let rows = try Row.fetchAll(db, sql: sql, arguments: [connection])
            return try rows.map { row in
                let blob: Int64? = row["payload_blob"]
                let payload = try blob.flatMap { try BlobStore.load($0, from: db) } ?? []
                let json: String = row["frames_json"] ?? "[]"
                let frames = (try? JSONDecoder().decode([WSFrameInfo].self, from: Data(json.utf8))) ?? []
                return WebSocketMessageRecord(
                    id: row["id"], direction: row["direction"], opcode: row["opcode"],
                    createdAt: Date(timeIntervalSince1970: row["created_at"]), payload: payload,
                    frames: frames)
            }
        }
    }
}

/// The WebSockets History filter (PRX-032): direction, kind of message and text.
public struct WebSocketMessageFilter: Sendable, Hashable {
    /// Which messages by opcode.
    public enum Kind: String, Sendable, CaseIterable {
        /// Everything.
        case all = "All"
        /// Text and binary messages.
        case data = "Data"
        /// Close, ping and pong.
        case control = "Control"
    }

    /// Only this direction (nil = both).
    public var direction: WSDirection?
    /// Which opcodes.
    public var kind = Kind.all
    /// Case-insensitive text the payload must contain (empty = any).
    public var text = ""

    /// No filtering.
    public init(direction: WSDirection? = nil, kind: Kind = .all, text: String = "") {
        self.direction = direction
        self.kind = kind
        self.text = text
    }

    /// Whether `message` passes.
    public func matches(_ message: WebSocketMessageRecord) -> Bool {
        if let direction, message.direction != direction.rawValue { return false }
        switch kind {
        case .all: break
        case .data where message.opcode >= 8: return false
        case .control where message.opcode < 8: return false
        default: break
        }
        guard !text.isEmpty else { return true }
        // UTF-8 for text, Latin-1 so bytes of a binary payload can match too.
        let needle = text.lowercased()
        let utf8 = String(decoding: message.payload, as: UTF8.self)
        let latin1 = String(String.UnicodeScalarView(message.payload.map { Unicode.Scalar($0) }))
        return utf8.lowercased().contains(needle) || latin1.lowercased().contains(needle)
    }
}
