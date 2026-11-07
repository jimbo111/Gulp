// GulpStore — content-addressed blob storage (doc 04 §4 `blobs`): message bytes are stored once per
// SHA-256 and zlib-compressed when larger than 4 KB and the saving is at least 10 %.

import CZlib
import Crypto
import Foundation
import GRDB

/// Reads and writes rows of the `blobs` table.
enum BlobStore {
    /// Bodies at or below this size are stored uncompressed.
    static let compressionThreshold = 4 * 1024

    /// Store `bytes` (or find the identical blob already stored) and return its row id.
    static func store(_ bytes: [UInt8], in db: Database) throws -> Int64 {
        let digest = Data(SHA256.hash(data: bytes))
        let lookup = "SELECT id FROM blobs WHERE sha256 = ?"
        if let existing = try Int64.fetchOne(db, sql: lookup, arguments: [digest]) { return existing }
        var compression = 0
        var stored = bytes
        let packed = bytes.count > compressionThreshold ? deflate(bytes) : nil
        if let packed, saves(packed.count, of: bytes.count) {
            compression = 1
            stored = packed
        }
        try db.execute(
            sql: "INSERT INTO blobs (sha256, size, compression, data) VALUES (?, ?, ?, ?)",
            arguments: [digest, bytes.count, compression, Data(stored)])
        return db.lastInsertedRowID
    }

    /// The original bytes of blob `id`, or nil if it does not exist.
    static func load(_ id: Int64, from db: Database) throws -> [UInt8]? {
        let sql = "SELECT size, compression, data FROM blobs WHERE id = ?"
        guard let row = try Row.fetchOne(db, sql: sql, arguments: [id]) else { return nil }
        let size: Int = row["size"]
        let compression: Int = row["compression"]
        let data: Data = row["data"] ?? Data()
        guard compression == 1 else { return [UInt8](data) }
        guard let bytes = inflate([UInt8](data), size: size) else {
            throw StoreError.corruptBlob(id)
        }
        return bytes
    }

    /// True when `compressed` is at most 90 % of `original` (a saving of at least 10 %).
    static func saves(_ compressed: Int, of original: Int) -> Bool {
        compressed * 10 <= original * 9
    }

    static func deflate(_ source: [UInt8]) -> [UInt8]? {
        var length = compressBound(uLong(source.count))
        var output = [UInt8](repeating: 0, count: Int(length))
        guard compress2(&output, &length, source, uLong(source.count), Z_DEFAULT_COMPRESSION) == Z_OK else {
            return nil
        }
        return Array(output[0..<Int(length)])
    }

    static func inflate(_ source: [UInt8], size: Int) -> [UInt8]? {
        var length = uLong(size)
        var output = [UInt8](repeating: 0, count: size)
        guard uncompress(&output, &length, source, uLong(source.count)) == Z_OK, Int(length) == size else {
            return nil
        }
        return output
    }
}

/// Store failures surfaced to callers.
public enum StoreError: Error, Sendable, Equatable {
    /// A blob's compressed data could not be decoded.
    case corruptBlob(Int64)
    /// The file is a project from a newer schema than this build understands.
    case newerSchema(Int)
}
