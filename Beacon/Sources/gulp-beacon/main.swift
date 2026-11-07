// gulp-beacon — OAST interaction server (scaffolding).
// Real DNS/HTTP/SMTP listeners and the polling API arrive in M11; see
// docs/features/F10-beacon-oast.md. Privileged ports 53/443 need
// CAP_NET_BIND_SERVICE or a privilege drop (F10 implementation notes).

print("gulp-beacon \(Beacon.version) — scaffolding. Listeners arrive in M11.")

/// Version marker and namespace for the Beacon server.
enum Beacon {
    /// Semantic version of the Beacon server.
    static let version = "0.0.0"
}
