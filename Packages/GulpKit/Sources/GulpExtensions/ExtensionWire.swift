// GulpExtensions — the wire-shape decoding shared by both extension hosts. The out-of-process
// `ExtensionHost` (JSON-RPC over a child process, Linux + macOS) and the in-process JavaScriptCore
// host in GulpScript (macOS-only) speak the same contract: `initialize` returns a `passiveChecks`
// array, and `passiveCheck` returns a `findings` array (EXT-002/004). Both used to re-implement the
// same `[String: Any]` → model decoding; that logic now lives here, so it is written once and
// exercised on Linux (the JavaScriptCore host can only *call* this on macOS, but what it calls is the
// same code these Linux tests cover — the untested-on-Linux surface of that host shrinks to the raw
// `JSContext` bridge).

import Foundation

/// Pure decoding of the extension wire contract, shared by both hosts (EXT-002/004).
public enum ExtensionWire {
    /// The checks an extension registered, decoded from its `initialize` result object. A missing or
    /// malformed `passiveChecks` array yields no checks; entries without a string `id` and `name` are
    /// skipped (EXT-002).
    public static func checks(fromInitializeResult object: [String: Any]) -> [ExtensionCheck] {
        guard let checks = object["passiveChecks"] as? [[String: Any]] else { return [] }
        return checks.compactMap { entry in
            guard let id = entry["id"] as? String, let name = entry["name"] as? String else { return nil }
            return ExtensionCheck(id: id, name: name)
        }
    }

    /// The findings a `passiveCheck` returned, decoded from its result object. A missing or malformed
    /// `findings` value yields no findings (EXT-004). This does **not** apply the `create-issues`
    /// permission gate — the host does that (and records the denial) before calling this.
    public static func findings(fromCheckResult object: [String: Any]) -> [ExtensionFinding] {
        // `findings` must be a top-level JSON array/dictionary: a scalar (string/number) makes
        // `JSONSerialization.data(withJSONObject:)` *fatal-error* rather than throw, so a malformed or
        // hostile extension could crash the host. Gate on `isValidJSONObject` first (EXT-004 hardening).
        guard let raw = object["findings"], JSONSerialization.isValidJSONObject(raw),
            let data = try? JSONSerialization.data(withJSONObject: raw)
        else { return [] }
        return (try? JSONDecoder().decode([ExtensionFinding].self, from: data)) ?? []
    }
}
