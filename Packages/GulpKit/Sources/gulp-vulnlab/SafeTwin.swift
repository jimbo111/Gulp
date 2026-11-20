// gulp-vulnlab — the one place a `/safe/` twin path is recognized. Every vulnerable route has a twin
// at `/safe<route>` that behaves correctly (doc 06 §3); labs split a path here instead of each
// re-deriving the prefix (a check without the trailing slash would also match, say, `/safelist`).

enum SafeTwin {
    static let prefix = "/safe/"

    /// `path` split into the vulnerable route and whether it is the safe twin:
    /// `/safe/sqli/error` → (`/sqli/error`, true); `/sqli/error` → (`/sqli/error`, false).
    static func split(_ path: String) -> (route: String, safe: Bool) {
        isSafe(path) ? (String(path.dropFirst(prefix.count - 1)), true) : (path, false)
    }

    /// Whether `path` is a safe-twin path.
    static func isSafe(_ path: String) -> Bool { path.hasPrefix(prefix) }
}
