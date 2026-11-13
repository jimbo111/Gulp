// GulpScanner — JavaScript Recon studio core (F27 JSR-003/006/008, M19/M23). Turns "dead" client-side
// JavaScript into attack surface: it recovers original sources from a source map, mines candidate
// parameter/flag names to feed Parameter Discovery, and flags interesting literals (cloud-storage URLs,
// internal hostnames, API bases). All pure string/JSON work, so it is fully tested; the engine only
// fetches the assets. (Endpoint inventory is the `recon.endpoint` passive check.)

import Foundation

/// A file reconstructed from a source map's `sourcesContent`.
public struct ReconstructedSource: Sendable, Equatable {
    public let path: String
    public let content: String
}

/// An interesting literal found in JavaScript.
public struct ReconLiteral: Sendable, Equatable {
    /// `cloud-storage`, `internal-host`, `api-base`, `source-map`.
    public let kind: String
    public let value: String
}

/// JavaScript recon.
public enum JSRecon {
    /// JSR-003: the `sourceMappingURL` a script points at (`//# sourceMappingURL=app.js.map`), if any.
    public static func sourceMapURL(in js: String) -> String? {
        for match in matches(#"(?m)^[ \t]*//[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*(\S+)"#, js, group: 1) {
            return match
        }
        return nil
    }

    /// JSR-003: reconstruct the original file tree from a source map's `sources` + `sourcesContent`.
    public static func reconstruct(sourceMap data: Data) -> [ReconstructedSource] {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let sources = object["sources"] as? [String]
        else { return [] }
        let contents = object["sourcesContent"] as? [String] ?? []
        var out: [ReconstructedSource] = []
        for (index, source) in sources.enumerated() where index < contents.count {
            out.append(ReconstructedSource(path: normalize(source), content: contents[index]))
        }
        return out
    }

    /// Clean a source-map path (`webpack://app/./src/a.js` → `src/a.js`).
    static func normalize(_ path: String) -> String {
        var cleaned = path
        if let slashes = cleaned.range(of: "://") { cleaned = String(cleaned[slashes.upperBound...]) }
        while cleaned.hasPrefix("./") || cleaned.hasPrefix("../") {
            cleaned = String(cleaned.drop(while: { $0 == "." || $0 == "/" }))
            break
        }
        // Drop the first path component if it's the webpack project name (no extension, no slash after).
        return cleaned.replacingOccurrences(of: "/./", with: "/")
    }

    /// Reserved words and generic noise that aren't useful parameter candidates.
    static let noise: Set<String> = [
        "function", "return", "const", "var", "let", "true", "false", "null", "undefined", "this",
        "typeof", "default", "length", "prototype", "constructor", "new", "class", "extends", "import",
        "export", "from", "async", "await", "yield", "case", "break", "continue", "else", "catch",
        "http", "https", "ftp", "ws", "wss", "data", "blob", "void", "in", "of", "do", "if",
    ]

    /// JSR-006 / ADV-021: mine candidate parameter/flag/config names from JavaScript, to augment a
    /// Parameter-Discovery wordlist.
    public static func mineParameters(from js: String) -> [String] {
        var names = Set<String>()
        // Object/config keys: `name:` or `"name":`.
        for name in matches(#"["'`]?([a-zA-Z_][a-zA-Z0-9_]{1,40})["'`]?\s*:"#, js, group: 1) {
            names.insert(name)
        }
        // Query parameters: `?x=` / `&x=`.
        for name in matches(#"[?&]([a-zA-Z_][a-zA-Z0-9_]{0,40})="#, js, group: 1) { names.insert(name) }
        // URLSearchParams / Map access: `.get("x")`, `.set("x")`, `.has("x")`.
        for name in matches(
            #"\.(?:get|set|has|append)\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_]{0,40})["'`]"#, js, group: 1)
        {
            names.insert(name)
        }
        return names.subtracting(noise).filter { $0.count >= 2 }.sorted()
    }

    /// JSR-008: flag interesting literals.
    public static func mineLiterals(from js: String) -> [ReconLiteral] {
        var out: [ReconLiteral] = []
        func add(_ kind: String, _ pattern: String, group: Int) {
            for value in matches(pattern, js, group: group) {
                out.append(ReconLiteral(kind: kind, value: value))
            }
        }
        add(
            "cloud-storage",
            #"https?://[a-z0-9.\-]+\.(?:s3[.\-][a-z0-9.\-]*amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)[^\s"'`]*"#,
            group: 0)
        add(
            "internal-host",
            #"https?://(?:[a-z0-9.\-]+\.(?:internal|local|corp|intranet)|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s"'`]*"#,
            group: 0)
        add(
            "api-base", #"(?:baseURL|apiBase|API_URL|endpoint)\s*[:=]\s*["'`](https?://[^"'`]+)["'`]"#,
            group: 1)
        // Dedup by (kind, value).
        var seen = Set<String>()
        return out.filter { seen.insert("\($0.kind)|\($0.value)").inserted }
    }

    // MARK: regex helper

    static func matches(_ pattern: String, _ text: String, group: Int) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(text.startIndex..., in: text)
        return regex.matches(in: text, range: range).compactMap { match in
            guard group <= match.numberOfRanges - 1, let found = Range(match.range(at: group), in: text)
            else { return nil }
            return String(text[found])
        }
    }
}
