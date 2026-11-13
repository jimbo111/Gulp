import Foundation

// The sidebar's tool list (docs/05-ui-ux.md §2). This is UI navigation metadata
// only; the actual tools live in the GulpFeatures package and are wired later.

/// A selectable tool in the sidebar.
enum Tool: String, Identifiable, CaseIterable, Hashable {
    case dashboard
    case proxy, target, logger
    case repeater, fuzzer, scanner, beacon, sequencer, decoder, comparer
    case authzMatrix, jwt, graphql, jsRecon, domProbe
    case notebook, extensions, assistant

    var id: String { rawValue }

    /// The human-readable name shown in the sidebar.
    var title: String {
        switch self {
        case .dashboard: "Dashboard"
        case .proxy: "Proxy"
        case .target: "Target"
        case .logger: "Logger"
        case .repeater: "Repeater"
        case .fuzzer: "Fuzzer"
        case .scanner: "Scanner"
        case .beacon: "Beacon"
        case .sequencer: "Sequencer"
        case .decoder: "Decoder"
        case .comparer: "Comparer"
        case .authzMatrix: "Authz Matrix"
        case .jwt: "JWT Workbench"
        case .graphql: "GraphQL"
        case .jsRecon: "JS Recon"
        case .domProbe: "DOM Probe"
        case .notebook: "Notebook"
        case .extensions: "Extensions"
        case .assistant: "Assistant"
        }
    }

    /// The SF Symbol used as the row icon.
    var symbol: String {
        switch self {
        case .dashboard: "square.grid.2x2"
        case .proxy: "arrow.left.arrow.right"
        case .target: "scope"
        case .logger: "list.bullet.rectangle"
        case .repeater: "arrow.triangle.2.circlepath"
        case .fuzzer: "dial.max"
        case .scanner: "ladybug"
        case .beacon: "antenna.radiowaves.left.and.right"
        case .sequencer: "waveform.path.ecg"
        case .decoder: "chevron.left.forwardslash.chevron.right"
        case .comparer: "rectangle.split.2x1"
        case .authzMatrix: "person.2.badge.key"
        case .jwt: "key"
        case .graphql: "point.3.connected.trianglepath.dotted"
        case .jsRecon: "doc.text.magnifyingglass"
        case .domProbe: "ladybug.fill"
        case .notebook: "note.text"
        case .extensions: "puzzlepiece.extension"
        case .assistant: "sparkles"
        }
    }
}

/// A labelled group of tools in the sidebar.
enum ToolSection: String, Identifiable, CaseIterable {
    case traffic, tools, workspace

    var id: String { rawValue }

    /// The section header text.
    var title: String {
        switch self {
        case .traffic: "Traffic"
        case .tools: "Tools"
        case .workspace: "Workspace"
        }
    }

    /// The tools shown under this section, in order.
    var tools: [Tool] {
        switch self {
        case .traffic: [.dashboard, .proxy, .target, .logger]
        case .tools:
            [
                .repeater, .fuzzer, .scanner, .beacon, .sequencer, .decoder,
                .comparer, .authzMatrix, .jwt, .graphql, .jsRecon, .domProbe,
            ]
        case .workspace: [.notebook, .extensions, .assistant]
        }
    }
}
