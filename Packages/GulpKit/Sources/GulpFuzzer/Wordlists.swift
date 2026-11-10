// GulpFuzzer — bundled wordlists (F07 FUZ-011): content discovery, parameters, usernames, passwords,
// injection probes (XSS, SQLi, traversal, SSTI, command metacharacters), user agents and weak JWT
// secrets. They ship as a package resource and are copied to the user's wordlists folder on first
// use, where the user can edit them and add their own.

import Foundation

/// The wordlists that ship with Gulp.
public enum BundledWordlists {
    /// File name → label.
    public static let labels: [(file: String, label: String)] = [
        ("content.txt", "Directories and files"), ("parameters.txt", "Parameter names"),
        ("usernames.txt", "Usernames"), ("passwords.txt", "Passwords"), ("fuzz-xss.txt", "XSS probes"),
        ("fuzz-sqli.txt", "SQL injection probes"), ("fuzz-traversal.txt", "Path traversal probes"),
        ("fuzz-ssti.txt", "Template injection probes"), ("fuzz-cmd.txt", "Command injection probes"),
        ("user-agents.txt", "User agents"), ("jwt-secrets.txt", "Weak JWT secrets"),
    ]

    /// The folder of bundled lists inside the package resources.
    public static var directory: URL? {
        Bundle.module.url(forResource: "Wordlists", withExtension: nil)
    }

    /// A bundled list's file.
    public static func url(_ file: String) -> URL? {
        directory?.appendingPathComponent(file)
    }

    /// Copy the bundled lists into `folder`, keeping any file the user already has there. Returns
    /// the files copied.
    @discardableResult
    public static func install(into folder: URL) throws -> [String] {
        guard let directory else { return [] }
        let manager = FileManager.default
        try manager.createDirectory(at: folder, withIntermediateDirectories: true)
        var copied: [String] = []
        for (file, _) in labels {
            let destination = folder.appendingPathComponent(file)
            guard !manager.fileExists(atPath: destination.path) else { continue }
            try manager.copyItem(at: directory.appendingPathComponent(file), to: destination)
            copied.append(file)
        }
        return copied
    }
}
