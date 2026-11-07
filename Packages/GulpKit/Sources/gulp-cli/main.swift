// gulp-cli — headless entry point for Gulp (scaffolding).
// Real subcommands (send, scan, proxy, project, …) arrive in M1/M17; see
// docs/features/F21-automation.md.

print("gulp \(GulpCLI.version) — scaffolding. Commands arrive in later milestones.")

/// Version marker for the Gulp command-line tool.
enum GulpCLI {
    /// Semantic version of the CLI; bumped as the tool gains commands.
    static let version = "0.0.0"
}
