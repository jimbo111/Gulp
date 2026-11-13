// GulpBrowser — the DOM Probe (F16 BRW-010…BRW-012, M13b). It injects an instrumentation script into
// every page (CDP `Page.addScriptToEvaluateOnNewDocument`) that reports tainted source -> sink flows
// through a CDP binding, drives a navigation, and collects the reports as findings. The instrumentation
// JavaScript is a single source of truth: embedded here and loaded verbatim by the real-Chromium DoD.

import Foundation
import GulpCore

/// One tainted source -> sink flow the instrumentation reported.
public struct DOMFinding: Sendable, Codable, Equatable {
    /// The sink the data reached, e.g. `Element.innerHTML`.
    public let sink: String
    /// The source the data came from, e.g. `location.hash`.
    public let source: String
    /// The source payload that reached the sink (truncated).
    public let sample: String
    /// The value passed to the sink (truncated).
    public let snippet: String
}

/// The DOM Probe.
public enum DOMProbe {
    /// The instrumentation script, embedded from `dom-probe.js` (the same bytes the DoD runs in a real
    /// browser), so what is tested in Chromium is exactly what ships.
    public static var instrumentation: String {
        String(decoding: PackageResources.dom_probe_js, as: UTF8.self)
    }

    /// The binding the instrumentation calls to report a flow.
    public static let bindingName = "__gulpReport"

    /// Parse a `__gulpReport` payload into a finding.
    public static func parse(_ json: String) -> DOMFinding? {
        try? JSONDecoder().decode(DOMFinding.self, from: Data(json.utf8))
    }

    /// Instrument a page session, navigate to `url`, and collect DOM-XSS findings for `settle` seconds.
    /// `sessionId` is the flattened CDP page session. Requires a live browser; the CDP command
    /// sequence is unit-tested against a mock transport, and the instrumentation against real Chromium.
    public static func run(
        on client: CDPClient, sessionId: String?, url: String, settle: Double = 1.5
    ) async throws -> [DOMFinding] {
        _ = try await client.send("Runtime.enable", sessionId: sessionId)
        _ = try await client.send(
            "Runtime.addBinding", params: json(["name": bindingName]), sessionId: sessionId)
        _ = try await client.send("Page.enable", sessionId: sessionId)
        _ = try await client.send(
            "Page.addScriptToEvaluateOnNewDocument", params: json(["source": instrumentation]),
            sessionId: sessionId)

        // Collect binding calls while the page loads and runs.
        let collector = Task { () -> [DOMFinding] in
            var findings: [DOMFinding] = []
            for await event in client.events {
                guard event.method == "Runtime.bindingCalled" else { continue }
                guard
                    let object = try? JSONSerialization.jsonObject(with: Data(event.params.utf8))
                        as? [String: Any],
                    object["name"] as? String == bindingName,
                    let payload = object["payload"] as? String,
                    let finding = parse(payload)
                else { continue }
                findings.append(finding)
            }
            return findings
        }
        _ = try await client.send("Page.navigate", params: json(["url": url]), sessionId: sessionId)
        try? await Task.sleep(for: .seconds(settle))
        collector.cancel()
        return await collector.value
    }

    /// A JSON object string from a `[String: String]` (the only shape the probe's commands need).
    static func json(_ object: [String: String]) -> String {
        (try? JSONSerialization.data(withJSONObject: object)).map { String(decoding: $0, as: UTF8.self) }
            ?? "{}"
    }
}
