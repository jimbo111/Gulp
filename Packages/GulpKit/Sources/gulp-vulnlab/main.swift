// gulp-vulnlab — intentionally vulnerable local test server (scaffolding).
// Binds 127.0.0.1 only. Real endpoints arrive in M1; see docs/06-testing-strategy.md §3.

print("gulp-vulnlab \(VulnLab.version) — scaffolding. Endpoints arrive in M1. Binds 127.0.0.1 only.")

/// Version marker for the VulnLab test server.
enum VulnLab {
    /// Semantic version of the test server.
    static let version = "0.0.0"
}
