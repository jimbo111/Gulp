// GulpFeatures — the History table (F05 HIS-001/002/004/005, doc 05 UI-001): an NSTableView that
// only materialises visible rows, pulled page by page from `HistoryModel`. Columns can be hidden
// (header menu), reordered, resized and sorted; NSTableView's autosave keeps those preferences.

#if canImport(AppKit)
import AppKit
import GulpCodec
import GulpCore
import GulpStore
import SwiftUI

/// One History column (HIS-001).
enum HistoryColumn: String, CaseIterable {
    case number, host, method, url, params, status, length, mime, title, tls, version, time, source, comment
    case highlight

    var title: String {
        switch self {
        case .number: "#"
        case .host: "Host"
        case .method: "Method"
        case .url: "URL"
        case .params: "Params"
        case .status: "Status"
        case .length: "Length"
        case .mime: "MIME"
        case .title: "Title"
        case .tls: "TLS"
        case .version: "Protocol"
        case .time: "Time"
        case .source: "Source"
        case .comment: "Comment"
        case .highlight: "Highlight"
        }
    }

    var width: CGFloat {
        switch self {
        case .url: 320
        case .host, .title, .comment: 160
        case .number, .method, .status, .params, .tls, .version: 56
        default: 80
        }
    }

    /// The store column this sorts by, if sortable.
    var sortColumn: HistorySortColumn? {
        switch self {
        case .number: .id
        case .host: .host
        case .method: .method
        case .url: .path
        case .status: .status
        case .length: .responseLength
        case .mime: .mime
        case .title: .title
        case .time: .createdAt
        default: nil
        }
    }

    func text(_ row: ExchangeSummary) -> String {
        switch self {
        case .number: String(row.id)
        case .host: row.host
        case .method: row.method ?? ""
        case .url: row.url
        case .params: row.paramCount > 0 ? "✓" : ""
        case .status where row.state == "pending":  // HIS-007: still streaming
            row.status.map { "\($0) ⋯" } ?? "⋯"
        case .status: row.status.map(String.init) ?? (row.error ?? "")
        case .length: row.responseLength.map(String.init) ?? ""
        case .mime: row.mime ?? ""
        case .title: row.title ?? ""
        case .tls: row.scheme == .https ? "✓" : ""
        case .version: row.httpVersion == .http2 ? "h2" : ""
        case .time where row.state == "pending":  // live duration (rows refresh as updates land)
            String(format: "%.1f s ⋯", Date().timeIntervalSince(row.createdAt))
        case .time: row.totalMs.map { String(format: "%.0f ms", $0) } ?? ""
        case .source: row.source.rawValue
        case .comment: row.comment ?? ""
        case .highlight: row.highlight?.rawValue ?? ""
        }
    }
}

extension Highlight {
    /// The row tint for this highlight (HIS-005).
    var color: NSColor {
        switch self {
        case .red: .systemRed
        case .orange: .systemOrange
        case .yellow: .systemYellow
        case .green: .systemGreen
        case .cyan: .systemCyan
        case .blue: .systemBlue
        case .purple: .systemPurple
        case .pink: .systemPink
        case .gray: .systemGray
        }
    }
}

/// The History table.
struct HistoryTableView: NSViewRepresentable {
    let model: HistoryModel

    func makeCoordinator() -> Coordinator { Coordinator(model: model) }

    func makeNSView(context: Context) -> NSScrollView {
        let table = NSTableView()
        table.allowsMultipleSelection = true
        table.allowsColumnReordering = true
        table.allowsColumnResizing = true
        table.usesAlternatingRowBackgroundColors = true
        table.style = .plain
        for column in HistoryColumn.allCases {
            let tableColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(column.rawValue))
            tableColumn.title = column.title
            tableColumn.width = column.width
            if let sort = column.sortColumn {
                let descriptor = NSSortDescriptor(key: sort.rawValue, ascending: true)
                tableColumn.sortDescriptorPrototype = descriptor
            }
            tableColumn.isHidden = column == .highlight || column == .source
            table.addTableColumn(tableColumn)
        }
        // Column preferences persist (HIS-001).
        table.autosaveName = "GulpHistoryTable"
        table.autosaveTableColumns = true
        table.dataSource = context.coordinator
        table.delegate = context.coordinator
        table.headerView?.menu = context.coordinator.columnMenu(for: table)
        table.menu = context.coordinator.rowMenu
        context.coordinator.table = table

        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        return scroll
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        // Reading these registers the observation that drives updates.
        context.coordinator.sync(revision: model.revision, rowCount: model.rowCount)
    }

    @MainActor
    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate {
        let model: HistoryModel
        weak var table: NSTableView?
        private var shownRevision = -1
        private var restoring = false
        let rowMenu = NSMenu()

        init(model: HistoryModel) {
            self.model = model
            super.init()
            rowMenu.delegate = self
        }

        func sync(revision: Int, rowCount: Int) {
            guard let table, revision != shownRevision else { return }
            shownRevision = revision
            // Rows move when traffic arrives or rows are deleted: keep the *exchanges* selected,
            // not the row positions (HIS-004).
            let keep = Set(model.selectedIDs)
            restoring = true
            table.reloadData()
            var indexes = IndexSet()
            if !keep.isEmpty {
                let visible = table.rows(in: table.visibleRect)
                let lower = max(0, visible.location - 200)
                let window = lower..<max(lower, min(rowCount, visible.location + visible.length + 200))
                for row in window where model.loadedRow(row).map({ keep.contains($0.id) }) == true {
                    indexes.insert(row)
                }
            }
            table.selectRowIndexes(indexes, byExtendingSelection: false)
            restoring = false
            if model.autoScroll, rowCount > 0, model.sort == .idAscending {
                table.scrollRowToVisible(rowCount - 1)
            }
        }

        // MARK: data source

        func numberOfRows(in tableView: NSTableView) -> Int { model.rowCount }

        func tableView(
            _ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int
        ) -> NSView? {
            let id = tableColumn?.identifier.rawValue ?? ""
            guard let column = HistoryColumn(rawValue: id) else { return nil }
            let identifier = NSUserInterfaceItemIdentifier("cell.\(column.rawValue)")
            let field: NSTextField
            if let reused = tableView.makeView(withIdentifier: identifier, owner: nil) as? NSTextField {
                field = reused
            } else {
                field = NSTextField(labelWithString: "")
                field.identifier = identifier
                field.lineBreakMode = .byTruncatingTail
            }
            field.stringValue = model.row(row).map(column.text) ?? "…"
            return field
        }

        func tableView(_ tableView: NSTableView, didAdd rowView: NSTableRowView, forRow row: Int) {
            // Row views are reused: always set the colour, or a highlight sticks to another row.
            rowView.backgroundColor =
                model.loadedRow(row)?.highlight.map { $0.color.withAlphaComponent(0.3) } ?? .clear
        }

        func tableView(
            _ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]
        ) {
            guard let descriptor = tableView.sortDescriptors.first,
                let column = descriptor.key.flatMap(HistorySortColumn.init(rawValue:))
            else { return }
            model.sort = HistorySort(column: column, ascending: descriptor.ascending)
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard !restoring, let table else { return }
            let rows = table.selectedRowIndexes
            let loaded = rows.compactMap { model.loadedRow($0)?.id }
            if loaded.count == rows.count {
                model.select(loaded)
            } else {
                let model = self.model
                Task { model.select(await model.ids(forRows: rows)) }
            }
        }

        /// Rows a menu action applies to: the clicked row if it is outside the selection, otherwise
        /// the whole selection (resolved through the store, so unloaded pages count too).
        func targetIDs() async -> [ExchangeID] {
            guard let table else { return [] }
            let clicked = table.clickedRow
            if clicked >= 0, !table.selectedRowIndexes.contains(clicked) {
                return await model.ids(forRows: IndexSet(integer: clicked))
            }
            return await model.ids(forRows: table.selectedRowIndexes)
        }

        // MARK: menus (HIS-004/005)

        func columnMenu(for table: NSTableView) -> NSMenu {
            let menu = NSMenu()
            for tableColumn in table.tableColumns {
                let item = NSMenuItem(
                    title: tableColumn.title, action: #selector(toggleColumn(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = tableColumn
                item.state = tableColumn.isHidden ? .off : .on
                menu.addItem(item)
            }
            return menu
        }

        @objc func toggleColumn(_ sender: NSMenuItem) {
            guard let column = sender.representedObject as? NSTableColumn else { return }
            column.isHidden.toggle()
            sender.state = column.isHidden ? .off : .on
        }

        func menuNeedsUpdate(_ menu: NSMenu) {
            menu.removeAllItems()
            let highlight = NSMenuItem(title: "Highlight", action: nil, keyEquivalent: "")
            let colors = NSMenu()
            for color in Highlight.allCases {
                let item = NSMenuItem(
                    title: color.rawValue.capitalized, action: #selector(setHighlight(_:)),
                    keyEquivalent: "")
                item.target = self
                item.representedObject = color.rawValue
                colors.addItem(item)
            }
            let none = NSMenuItem(title: "None", action: #selector(setHighlight(_:)), keyEquivalent: "")
            none.target = self
            colors.addItem(none)
            highlight.submenu = colors
            menu.addItem(highlight)
            addItem("Comment…", #selector(editComment), to: menu)
            addItem("Copy URLs", #selector(copyURLs), to: menu)
            let copyAs = NSMenuItem(title: "Copy as", action: nil, keyEquivalent: "")
            let formats = NSMenu()
            for format in RequestExportFormat.allCases {
                let item = NSMenuItem(
                    title: format.rawValue, action: #selector(copyAs(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = format.rawValue
                formats.addItem(item)
            }
            copyAs.submenu = formats
            menu.addItem(copyAs)
            menu.addItem(.separator())
            addItem("Delete", #selector(deleteRows), to: menu)
        }

        private func addItem(_ title: String, _ action: Selector, to menu: NSMenu) {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
            item.target = self
            menu.addItem(item)
        }

        @objc func setHighlight(_ sender: NSMenuItem) {
            let color = (sender.representedObject as? String).flatMap(Highlight.init(rawValue:))
            Task { model.highlight(await targetIDs(), color) }
        }

        @objc func editComment() {
            Task { await editComment(ids: await targetIDs()) }
        }

        private func editComment(ids: [ExchangeID]) async {
            guard !ids.isEmpty else { return }
            let alert = NSAlert()
            alert.messageText = ids.count == 1 ? "Comment" : "Comment \(ids.count) items"
            let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
            let existing = ids.count == 1 ? model.loadedRow(table?.clickedRow ?? -1)?.comment : nil
            field.stringValue = existing ?? ""
            alert.accessoryView = field
            alert.addButton(withTitle: "Save")
            alert.addButton(withTitle: "Cancel")
            if alert.runModal() == .alertFirstButtonReturn {
                model.comment(ids, field.stringValue.isEmpty ? nil : field.stringValue)
            }
        }

        @objc func copyURLs() {
            let model = self.model
            Task {
                let text = await model.urls(await targetIDs())
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            }
        }

        @objc func copyAs(_ sender: NSMenuItem) {
            guard let raw = sender.representedObject as? String,
                let format = RequestExportFormat(rawValue: raw)
            else { return }
            let model = self.model
            Task {
                let text = await model.copyAs(await targetIDs(), format: format)
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            }
        }

        @objc func deleteRows() {
            Task { model.delete(await targetIDs()) }
        }
    }
}
#endif
