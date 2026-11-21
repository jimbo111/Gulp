// GulpExtensions — the extension manifest (F18 EXT-003) and permissions (EXT-004). An extension ships
// a `gulp-extension.json` declaring its identity, runtime, entry point, the minimum API version and
// the permissions it needs; Gulp approves the permissions at enable time and enforces them at the API
// boundary at runtime. This module is the out-of-process (JSON-RPC) runtime; the in-process JS runtime
// (JavaScriptCore) is macOS-only.

import Foundation

/// A capability an extension must declare and the user must approve (EXT-004).
public enum ExtensionPermission: String, Sendable, Codable, CaseIterable {
    case httpSend = "http-send"
    case interceptModify = "intercept-modify"
    case readTraffic = "read-traffic"
    case createIssues = "create-issues"
    case modifyScope = "modify-scope"
    case filesystem
    case networkDirect = "network-direct"
    case ui
    case oast
    case settingsRead = "settings-read"
}

/// Which runtime an extension uses.
public enum ExtensionRuntime: String, Sendable, Codable {
    /// In-process JavaScript (JavaScriptCore; macOS only).
    case js
    /// Out-of-process, any language, over JSON-RPC on stdio.
    case process
}

/// A parsed `gulp-extension.json` (EXT-003).
public struct ExtensionManifest: Sendable, Codable, Equatable {
    /// The extension's identifier.
    public var id: String
    /// The display name.
    public var name: String
    /// The extension's version string.
    public var version: String
    /// Who wrote it, if declared.
    public var author: String?
    /// Which runtime runs it.
    public var runtime: ExtensionRuntime
    /// The command to launch, for `runtime == .process` (argv; the first element is the executable).
    public var command: [String]?
    /// The entry file, for `runtime == .js`.
    public var entry: String?
    /// The minimum extension API version it needs.
    public var minAPIVersion: Int
    /// The permissions it asks for; the user approves them at enable time (EXT-004).
    public var permissions: [ExtensionPermission]
    /// Hooks the extension registers, e.g. `passive-check`, `on-request`, `context-menu`.
    public var hooks: [String]

    /// A manifest; `minAPIVersion` defaults to 1 and the lists to empty.
    public init(
        id: String, name: String, version: String, author: String? = nil, runtime: ExtensionRuntime,
        command: [String]? = nil, entry: String? = nil, minAPIVersion: Int = 1,
        permissions: [ExtensionPermission] = [], hooks: [String] = []
    ) {
        self.id = id
        self.name = name
        self.version = version
        self.author = author
        self.runtime = runtime
        self.command = command
        self.entry = entry
        self.minAPIVersion = minAPIVersion
        self.permissions = permissions
        self.hooks = hooks
    }

    /// Decode a manifest from `gulp-extension.json` bytes.
    public static func decode(_ data: Data) throws -> ExtensionManifest {
        try JSONDecoder().decode(ExtensionManifest.self, from: data)
    }

    /// Whether the extension declared `permission` (so the API boundary may allow it).
    public func allows(_ permission: ExtensionPermission) -> Bool { permissions.contains(permission) }
}

/// The Gulp side's view of a finding an extension reported (mapped to an `Issue` by the workspace).
public struct ExtensionFinding: Sendable, Codable, Equatable {
    /// The issue type id the finding is recorded under.
    public var typeID: String
    /// The issue name.
    public var name: String
    /// The severity, as the extension's string.
    public var severity: String
    /// The issue detail text.
    public var detail: String
    /// A substring of the response that proves the finding (for a marker), optional.
    public var marker: String?

    /// A finding.
    public init(
        typeID: String, name: String, severity: String, detail: String, marker: String? = nil
    ) {
        self.typeID = typeID
        self.name = name
        self.severity = severity
        self.detail = detail
        self.marker = marker
    }
}
