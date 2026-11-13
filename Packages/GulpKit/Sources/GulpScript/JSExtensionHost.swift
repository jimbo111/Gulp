// GulpScript — the in-process JavaScript extension host (F18 EXT-002/004, the `js` runtime). This is the
// alternative to GulpExtensions' out-of-process `ExtensionHost`: instead of a child process over
// JSON-RPC, the extension's script runs in a JavaScriptCore `JSContext` and Gulp calls into it directly.
// It mirrors the process host's contract — `initialize` returns the passive checks the extension
// registers, `passiveCheck` returns findings (only honoured with the `create-issues` permission) — and
// the host API it exposes (`host.log`, `host.httpSend`) is gated by the same manifest permissions.
//
// JavaScriptCore is an Apple framework, so this whole file is macOS-only (GulpScript is the
// platform-capability module permitted to import it, per the architecture): on Linux `canImport` is
// false and it compiles to nothing. It is compiled and exercised only by the macOS CI leg; the
// cross-platform process host in GulpExtensions remains the default, Linux-tested runtime.

#if canImport(JavaScriptCore)
import Foundation
import GulpExtensions
import JavaScriptCore

/// Runs one extension's script in a `JSContext` and calls into it for checks.
///
/// `@unchecked Sendable`: a `JSContext` is not `Sendable`, but this host confines every context access
/// to the synchronous call that triggered it (there is no `await` between touching the context), and
/// never shares the context between concurrent tasks — each host owns its own context. Callers that
/// hold a host across tasks serialise their calls, as they already do for the process host.
public final class JSExtensionHost: @unchecked Sendable {
    /// The extension's manifest (identity, runtime, approved permissions).
    public let manifest: ExtensionManifest
    /// Lines the extension logged (EXT-005 console), newest last.
    public private(set) var log: [String] = []
    /// Permission violations and script errors that were denied/caught (for the manager/audit).
    public private(set) var denials: [String] = []

    private let context: JSContext
    private let httpSend: (@Sendable (String) -> String)?

    /// A host running `script` for `manifest`. `httpSend` handles an approved `host.httpSend` call
    /// (request params JSON → response JSON); nil denies it even when the permission is present.
    public init(
        manifest: ExtensionManifest, script: String,
        httpSend: (@Sendable (String) -> String)? = nil
    ) {
        self.manifest = manifest
        self.httpSend = httpSend
        context = JSContext()
        installHostAPI()
        context.exceptionHandler = { [weak self] _, value in
            self?.denials.append("script error: \(value?.toString() ?? "unknown")")
        }
        context.evaluateScript(script)
    }

    /// Expose `host.log` and `host.httpSend` to the extension, gated by the manifest's permissions.
    private func installHostAPI() {
        let logBlock: @convention(block) (String) -> Void = { [weak self] message in
            self?.log.append(message)
        }
        let httpBlock: @convention(block) (String) -> String = { [weak self] paramsJSON in
            guard let self else { return "{}" }
            guard self.manifest.allows(.httpSend) else {
                self.denials.append("host.httpSend denied: extension lacks the http-send permission")
                return "{}"
            }
            return self.httpSend?(paramsJSON) ?? "{}"
        }
        context.setObject(logBlock, forKeyedSubscript: "gulpLog" as NSString)
        context.setObject(httpBlock, forKeyedSubscript: "gulpHttpSend" as NSString)
        // Present a small, stable `host` facade (so extensions call host.httpSend(obj), not the raw
        // JSON bridge) and evaluate it before the extension script.
        context.evaluateScript(
            """
            var host = {
              log: function(m) { gulpLog(String(m)); },
              httpSend: function(p) { return JSON.parse(gulpHttpSend(JSON.stringify(p))); }
            };
            """)
    }

    /// Handshake: hand the extension our API version and read the passive checks it registers (EXT-002).
    @discardableResult
    public func initialize(apiVersion: Int = 1) -> [ExtensionCheck] {
        guard let fn = context.objectForKeyedSubscript("initialize"), !fn.isUndefined,
            let result = fn.call(withArguments: [apiVersion]),
            let object = result.toDictionary(),
            let checks = object["passiveChecks"] as? [[String: Any]]
        else { return [] }
        return checks.compactMap { (entry: [String: Any]) -> ExtensionCheck? in
            guard let id = entry["id"] as? String, let name = entry["name"] as? String else { return nil }
            return ExtensionCheck(id: id, name: name)
        }
    }

    /// Run the extension's passive check over one exchange and collect its findings. Findings are only
    /// returned if the extension declared `create-issues` (EXT-004).
    public func runPassiveCheck(requestText: String, responseText: String) -> [ExtensionFinding] {
        guard let fn = context.objectForKeyedSubscript("passiveCheck"), !fn.isUndefined,
            let result = fn.call(withArguments: [requestText, responseText])
        else { return [] }
        guard manifest.allows(.createIssues) else {
            denials.append("passiveCheck returned findings without the create-issues permission")
            return []
        }
        guard let object = result.toDictionary(), let raw = object["findings"],
            let data = try? JSONSerialization.data(withJSONObject: raw)
        else { return [] }
        return (try? JSONDecoder().decode([ExtensionFinding].self, from: data)) ?? []
    }
}
#endif
