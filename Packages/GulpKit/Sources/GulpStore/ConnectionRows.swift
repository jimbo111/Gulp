// GulpStore — the connection view (F05 HIS-042): exchanges grouped by the TCP/TLS/HTTP-2 connection
// that carried them, showing reuse, the negotiated protocol and when it was used.

import Foundation
import GRDB
import GulpCore

/// One connection's use.
public struct ConnectionSummary: Sendable, Hashable, Identifiable {
    /// The engine's connection id.
    public var id: UInt64
    /// `scheme://host:port`.
    public var origin: String
    /// HTTP version of its exchanges.
    public var httpVersion: String
    /// ALPN, when TLS negotiated one.
    public var alpn: String?
    /// Exchanges it carried (more than one = reused).
    public var exchanges: Int
    /// The first and last exchange ids.
    public var firstID: ExchangeID
    /// The last exchange id.
    public var lastID: ExchangeID
    /// When it was first and last used.
    public var firstUsed: Date
    /// Last use.
    public var lastUsed: Date
}

extension ProjectStore {
    /// Connections, most recently used first (exchanges without a connection id are left out).
    public func connectionSummaries(limit: Int = 1_000) async throws -> [ConnectionSummary] {
        await writer.flush()
        return try await pool.read { db in
            try Row.fetchAll(
                db,
                sql: """
                    SELECT connection_id, scheme, host, port, http_version, COUNT(*) AS n, MIN(id) AS first, \
                    MAX(id) AS last, MIN(created_at) AS t0, MAX(created_at) AS t1, MAX(tls_json) AS tls \
                    FROM exchanges WHERE connection_id IS NOT NULL AND connection_id != 0 \
                    GROUP BY connection_id ORDER BY last DESC LIMIT ?
                    """,
                arguments: [limit]
            ).map { row in
                let tlsJSON: String? = row["tls"]
                let tls = tlsJSON.flatMap { try? JSONDecoder().decode(TLSInfo.self, from: Data($0.utf8)) }
                let connection: Int64 = row["connection_id"]
                let scheme: String = row["scheme"]
                let host: String = row["host"]
                let port: Int = row["port"]
                return ConnectionSummary(
                    id: UInt64(bitPattern: connection), origin: "\(scheme)://\(host):\(port)",
                    httpVersion: row["http_version"], alpn: tls?.alpn, exchanges: row["n"],
                    firstID: row["first"],
                    lastID: row["last"], firstUsed: Date(timeIntervalSince1970: row["t0"]),
                    lastUsed: Date(timeIntervalSince1970: row["t1"]))
            }
        }
    }
}
