// GulpQuery — GulpQL (F05 §2.2): lexer and parser (Parser.swift), the syntax tree (AST.swift), the
// field catalog (Fields.swift), in-memory evaluation (Evaluator.swift) and SQL push-down
// (SQLLowering.swift). Pure Swift over GulpCore; no storage types (GulpStore maps `SQLBinding`).

/// Namespace and module marker for the `GulpQuery` module.
public enum GulpQuery {
    /// The module's name, used in diagnostics.
    public static let moduleName = "GulpQuery"
}
