// GulpFeatures — Feature screens and view models (macOS-only code).
// Every other file is `#if canImport(AppKit)`; this marker is the module's only declaration on
// Linux, so the package graph stays identical there (docs/07 ADR-010).

/// Module marker for `GulpFeatures`.
public enum GulpFeatures {
    /// The module's name.
    public static let moduleName = "GulpFeatures"
}
