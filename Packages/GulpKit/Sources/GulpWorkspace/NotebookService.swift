// GulpWorkspace — the Notebook for a project session (F14): saving exchanges and notes, the list's
// filter and grouping (NB-004), and sending an item's stored request back to a tool (NB-006).
// UI-free, so it is tested on Linux.

import Foundation
import GulpCore
import GulpStore

/// The Notebook's filter (NB-004), written like a search box: free words match the title, note,
/// tags and location; `status:`, `tag:`, `host:` and `is:note`/`is:exchange` narrow it.
/// `status:confirmed tag:xss login` → confirmed items tagged xss mentioning "login".
public struct NotebookFilter: Sendable, Hashable {
    /// Words that must all appear (case-insensitive).
    public var words: [String] = []
    /// Allowed statuses (empty: any).
    public var statuses: Set<NotebookStatus> = []
    /// Tags that must all be present.
    public var tags: [String] = []
    /// Host substring.
    public var host: String?
    /// Only this kind.
    public var kind: NotebookItem.Kind?

    /// Everything.
    public init() {}

    /// Parse the search-box form.
    public init(_ text: String) {
        for token in text.split(whereSeparator: \.isWhitespace).map(String.init) {
            let parts = token.split(separator: ":", maxSplits: 1).map(String.init)
            guard parts.count == 2, !parts[1].isEmpty else {
                words.append(token.lowercased())
                continue
            }
            let value = parts[1].lowercased()
            switch parts[0].lowercased() {
            case "status":
                let match = NotebookStatus.allCases.first {
                    $0.rawValue == value
                        || $0.title.lowercased().replacingOccurrences(of: " ", with: "") == value
                }
                if let match { statuses.insert(match) } else { words.append(token.lowercased()) }
            case "tag": tags.append(value)
            case "host": host = value
            case "is": kind = NotebookItem.Kind(rawValue: value)
            default: words.append(token.lowercased())
            }
        }
    }

    /// Whether `item` passes.
    public func matches(_ item: NotebookItem) -> Bool {
        if !statuses.isEmpty, !statuses.contains(item.status) { return false }
        if let kind, item.kind != kind { return false }
        let itemTags = Set(item.tags.map { $0.lowercased() })
        if tags.contains(where: { !itemTags.contains($0) }) { return false }
        let location = item.location?.lowercased() ?? ""
        if let host, !(item.target?.host.lowercased().contains(host) ?? false) { return false }
        let haystack = [item.title, item.note, location, item.tags.joined(separator: " ")]
            .joined(separator: "\n").lowercased()
        return words.allSatisfy { haystack.contains($0) }
    }
}

/// How the Notebook list groups items (NB-004).
public enum NotebookGrouping: String, Sendable, CaseIterable {
    /// One group per status, in triage order.
    case status
    /// One group per host ("Notes" for free-form notes).
    case host
}

/// Where an item's stored request can go (NB-006).
public enum NotebookDestination: String, Sendable, CaseIterable {
    /// A new Repeater tab.
    case repeater
    /// The Comparer's list (the response, or the request if there is none).
    case comparer
    /// The Fuzzer's base request.
    case fuzzer
}

extension ProjectSession {
    /// Save an exchange to the Notebook (NB-001).
    @discardableResult
    public func addToNotebook(
        _ id: ExchangeID, title: String? = nil, note: String = "", status: NotebookStatus = .todo,
        tags: [String] = []
    ) async throws -> NotebookItem? {
        try await store.addNotebookItem(exchange: id, title: title, note: note, status: status, tags: tags)
    }

    /// A free-form note (NB-003).
    @discardableResult
    public func addNote(title: String, note: String = "", tags: [String] = []) async throws -> NotebookItem {
        try await store.addNotebookNote(title: title, note: note, tags: tags)
    }

    /// The items passing `filter`, in list order (NB-002/004).
    public func notebook(_ filter: NotebookFilter = NotebookFilter()) async throws -> [NotebookItem] {
        try await store.notebookItems().filter(filter.matches)
    }

    /// The items passing `filter`, grouped (NB-004); groups keep the list order inside.
    public func notebookGroups(_ grouping: NotebookGrouping, filter: NotebookFilter = NotebookFilter())
        async throws -> [(name: String, items: [NotebookItem])]
    {
        let items = try await notebook(filter)
        switch grouping {
        case .status:
            return NotebookStatus.allCases.compactMap { status in
                let members = items.filter { $0.status == status }
                return members.isEmpty ? nil : (status.title, members)
            }
        case .host:
            var order: [String] = []
            var groups: [String: [NotebookItem]] = [:]
            for item in items {
                let name = item.target?.host ?? "Notes"
                if groups[name] == nil { order.append(name) }
                groups[name, default: []].append(item)
            }
            return order.map { ($0, groups[$0] ?? []) }
        }
    }

    /// Send an item's stored request back to a tool (NB-006). False for notes (nothing stored).
    @discardableResult
    public func sendNotebookItem(_ id: Int64, to destination: NotebookDestination) async throws -> Bool {
        guard let item = try await store.notebookItem(id), let target = item.target,
            let request = item.request
        else { return false }
        switch destination {
        case .repeater:
            let tab = await repeater.openTab(
                request: RawRequest(Bytes(request)), target: target, title: String(item.title.prefix(40)))
            await events.publish(.repeaterTabOpened(tab.id))
        case .comparer:
            let bytes = item.response ?? request
            await inbox.addToComparer(
                ComparerItem(
                    label: "Notebook: \(item.title)" + (item.response == nil ? " (request)" : ""),
                    source: "notebook", bytes: bytes))
        case .fuzzer:
            await inbox.sendToFuzzer(FuzzerInput(request: request, target: target))
        }
        return true
    }
}
