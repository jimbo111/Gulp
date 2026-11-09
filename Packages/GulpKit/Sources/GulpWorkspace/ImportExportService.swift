// GulpWorkspace — the import/export service (F20 PRJ-012). Every entry point (History import/export
// HIS-044, Project → Import/merge PRJ-008, the site map TGT-009, API import ADV-051, the CLI AUT-004
// and MCP) calls this one service. UI-free.
//
// Imports never send traffic. They are dedup-aware (an exchange with the same target and the same
// request and response bytes as one already stored — or earlier in the same file — is skipped),
// tag what they add `imported`, keep the source the file states (default proxy), comments and
// highlights, and feed the site map through the normal `exchangeRecorded` events (request-only
// imports such as OpenAPI operations show there as inferred). The report says what was skipped and
// why.

import Foundation
import GulpCodec
import GulpCore
import GulpStore

/// What an import did.
public struct ImportReport: Sendable {
    /// The format read.
    public var format: String
    /// Exchanges added.
    public var imported: Int
    /// Exchanges already in the project (or repeated in the file).
    public var duplicates: Int
    /// Items not imported, with the reason.
    public var skipped: [ImportSkip]
    /// Ids of the added exchanges.
    public var ids: [ExchangeID]

    /// A one-line summary.
    public var summary: String {
        "\(format): imported \(imported), duplicates \(duplicates), skipped \(skipped.count)"
    }
}

/// Export formats (HIS-044).
public enum ExportFormat: String, Sendable, CaseIterable {
    /// HTTP Archive (with Gulp's exact bytes in `_gulp`).
    case har
    /// CSV for spreadsheets.
    case csv
}

/// The tag every imported exchange carries.
public let importedTag = "imported"

/// Import and export for one project (PRJ-012).
public struct ImportExportService: Sendable {
    let session: ProjectSession

    /// Read `data` (format detected unless given) and add its exchanges to the project.
    /// `baseURL` is where an OpenAPI document came from; `defaultSource` is used when the file
    /// doesn't say which tool produced an exchange.
    public func importFile(
        _ data: Data, format: TrafficFormat? = nil, baseURL: String? = nil, defaultSource: ToolSource = .proxy
    ) async throws -> ImportReport {
        let batch = try TrafficImport.read(data, as: format, baseURL: baseURL)
        return try await add(
            batch.exchanges, format: batch.format.title, skipped: batch.skipped, defaultSource: defaultSource)
    }

    /// Merge another `.gulp` project's exchanges into this one (PRJ-008), keeping their source,
    /// timing, comments and highlights.
    public func importProject(at url: URL) async throws -> ImportReport {
        let own = await session.store.url.standardizedFileURL.resolvingSymlinksInPath()
        guard url.standardizedFileURL.resolvingSymlinksInPath() != own else {
            throw GulpError(message: "That is this project; choose another .gulp file.")
        }
        let other = try ProjectStore.open(at: url)
        do {
            let ids = try await other.exchangeIDs()
            var items: [ImportedExchange] = []
            for chunk in stride(from: 0, to: ids.count, by: 500) {
                for exchange in try await other.exchanges(
                    ids: Array(ids[chunk..<min(chunk + 500, ids.count)]))
                {
                    items.append(
                        ImportedExchange(
                            target: exchange.target, request: exchange.request, response: exchange.response,
                            httpVersion: exchange.httpVersion, startedAt: exchange.timing.start,
                            durationMs: exchange.timing.totalMs, comment: exchange.annotation.comment,
                            highlight: exchange.annotation.highlight, source: exchange.source))
                }
            }
            try await other.close()
            return try await add(items, format: "Gulp project", skipped: [], defaultSource: .proxy)
        } catch {
            try? await other.close()
            throw error
        }
    }

    /// Store `items`, skipping duplicates.
    func add(_ items: [ImportedExchange], format: String, skipped: [ImportSkip], defaultSource: ToolSource)
        async throws -> ImportReport
    {
        let store = await session.store
        await store.writer.flush()
        var report = ImportReport(format: format, imported: 0, duplicates: 0, skipped: skipped, ids: [])
        var seen: Set<DedupKey> = []
        for item in items {
            let key = Self.dedupKey(item)
            if !seen.insert(key).inserted {
                report.duplicates += 1
                continue
            }
            if try await store.containsExchange(
                target: item.target, request: item.request.bytes, response: item.response?.wireBytes)
            {
                report.duplicates += 1
                continue
            }
            var timing = Timing(start: item.startedAt ?? Date())
            timing.totalMs = item.durationMs
            let exchange = Exchange(
                source: item.source ?? defaultSource, target: item.target, httpVersion: item.httpVersion,
                request: item.request, response: item.response, state: .complete, timing: timing,
                annotation: Annotation(comment: item.comment, highlight: item.highlight, tags: [importedTag]))
            report.ids.append(await store.writer.record(exchange))
            report.imported += 1
        }
        await store.writer.flush()
        return report
    }

    /// Target + exact bytes: what makes two exchanges the same for dedup.
    struct DedupKey: Hashable {
        var scheme: String
        var host: String
        var port: Int
        var request: [UInt8]
        var response: [UInt8]?
    }

    static func dedupKey(_ item: ImportedExchange) -> DedupKey {
        DedupKey(
            scheme: item.target.scheme.rawValue, host: item.target.host, port: item.target.port,
            request: item.request.bytes.rawBytes, response: item.response?.wireBytes.rawBytes)
    }

    /// Export exchanges (`ids`, or every one matching `filter`) as HAR or CSV (HIS-044).
    public func export(
        ids: [ExchangeID]? = nil, filter: HistoryFilter = HistoryFilter(), as format: ExportFormat
    ) async throws -> Data {
        let store = await session.store
        let selected: [ExchangeID]
        if let ids { selected = ids } else { selected = try await store.exchangeIDs(filter: filter) }
        var exchanges: [Exchange] = []
        for chunk in stride(from: 0, to: selected.count, by: 500) {
            exchanges += try await store.exchanges(
                ids: Array(selected[chunk..<min(chunk + 500, selected.count)]))
        }
        switch format {
        case .har: return try HAR.export(exchanges)
        case .csv: return HAR.csv(exchanges)
        }
    }

    /// Export exchanges as a new `.gulp` project at `url` ("`.gulp` items", HIS-044). Returns how
    /// many were written.
    @discardableResult
    public func exportProject(
        ids: [ExchangeID]? = nil, filter: HistoryFilter = HistoryFilter(), to url: URL
    ) async throws -> Int {
        guard !FileManager.default.fileExists(atPath: url.path) else {
            throw GulpError(
                message: "\(url.lastPathComponent) already exists.",
                recoverySuggestion: "Choose a new file name.")
        }
        let store = await session.store
        let selected: [ExchangeID]
        if let ids { selected = ids } else { selected = try await store.exchangeIDs(filter: filter) }
        let target = try ProjectStore.open(at: url)
        var written = 0
        for chunk in stride(from: 0, to: selected.count, by: 500) {
            for var exchange in try await store.exchanges(
                ids: Array(selected[chunk..<min(chunk + 500, selected.count)]))
            {
                exchange.id = 0
                _ = await target.writer.record(exchange)
                written += 1
            }
        }
        try await target.close()
        return written
    }
}

extension ProjectSession {
    /// The project's import/export service (PRJ-012).
    public nonisolated var importExport: ImportExportService { ImportExportService(session: self) }
}
