// GulpExtensions — tests for the wire-shape decoding shared by both extension hosts (EXT-002/004).
// These run on Linux and cover exactly the `[String: Any]` → model decoding that the macOS-only
// JavaScriptCore host (GulpScript.JSExtensionHost) now calls instead of re-implementing, so that
// host's parsing contract is verified here even though its `JSContext` bridge can only run on macOS.

import Foundation
import Testing

@testable import GulpExtensions

@Suite("Extension wire decoding (F18 EXT-002/004, shared by both hosts)")
struct ExtensionWireTests {
    @Test("EXT-002: initialize result → the registered checks")
    func initializeChecks() {
        let object: [String: Any] = [
            "passiveChecks": [
                ["id": "ext.header", "name": "Missing header"],
                ["id": "ext.cookie", "name": "Insecure cookie"],
            ]
        ]
        let checks = ExtensionWire.checks(fromInitializeResult: object)
        #expect(
            checks == [
                ExtensionCheck(id: "ext.header", name: "Missing header"),
                ExtensionCheck(id: "ext.cookie", name: "Insecure cookie"),
            ])
    }

    @Test("EXT-002: entries missing id or name are skipped; a missing array yields none")
    func initializeChecksMalformed() {
        let partial: [String: Any] = [
            "passiveChecks": [
                ["id": "ext.ok", "name": "Fine"],
                ["id": "ext.noname"],  // no name → skipped
                ["name": "no id"],  // no id → skipped
                ["id": 7, "name": "wrong type"],  // id not a string → skipped
            ]
        ]
        #expect(
            ExtensionWire.checks(fromInitializeResult: partial) == [
                ExtensionCheck(id: "ext.ok", name: "Fine")
            ])
        #expect(ExtensionWire.checks(fromInitializeResult: [:]).isEmpty)
        #expect(ExtensionWire.checks(fromInitializeResult: ["passiveChecks": "not an array"]).isEmpty)
    }

    @Test("EXT-004: passiveCheck result → the decoded findings")
    func checkFindings() {
        let object: [String: Any] = [
            "findings": [
                [
                    "typeID": "ext.secret", "name": "Secret in body", "severity": "high",
                    "detail": "Found a token", "marker": "AKIA…",
                ]
            ]
        ]
        let findings = ExtensionWire.findings(fromCheckResult: object)
        #expect(
            findings == [
                ExtensionFinding(
                    typeID: "ext.secret", name: "Secret in body", severity: "high",
                    detail: "Found a token", marker: "AKIA…")
            ])
    }

    @Test("EXT-004: a missing or malformed findings value yields none")
    func checkFindingsMalformed() {
        #expect(ExtensionWire.findings(fromCheckResult: [:]).isEmpty)
        // `findings` present but not a serialisable findings array → none, no throw.
        #expect(ExtensionWire.findings(fromCheckResult: ["findings": "oops"]).isEmpty)
        #expect(ExtensionWire.findings(fromCheckResult: ["findings": [["typeID": "x"]]]).isEmpty)
    }
}
