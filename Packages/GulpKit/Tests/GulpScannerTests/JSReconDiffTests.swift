import Foundation
import Testing

@testable import GulpScanner

@Suite("JS Recon asset diff (F27 JSR-009)")
struct JSReconDiffTests {
    @Test("a redeploy that adds a param and an internal host shows them as added, nothing removed")
    func test_JSR009_addedSurface() {
        let old = JSRecon.inventory(
            js: "new URLSearchParams(location.search).get('trace');"
                + "const API_URL='http://api.internal/v1';")
        let new = JSRecon.inventory(
            js: "new URLSearchParams(location.search).get('trace');"
                + "new URLSearchParams(location.search).get('adminPanel');"
                + "const API_URL='http://api.internal/v1';fetch('http://secret.corp/ops');")
        let diff = JSRecon.diff(from: old, to: new)

        #expect(diff.addedParameters.contains("adminPanel"))
        #expect(!diff.addedParameters.contains("trace"))
        #expect(diff.removedParameters.isEmpty)
        #expect(diff.addedLiterals.contains { $0.value.contains("secret.corp") })
        #expect(diff.removedLiterals.isEmpty)
        #expect(!diff.isEmpty)
    }

    @Test("identical assets diff to nothing")
    func test_JSR009_noChange() {
        let js = "new URLSearchParams(location.search).get('q');const API_URL='http://api.internal/v1';"
        #expect(JSRecon.diff(from: JSRecon.inventory(js: js), to: JSRecon.inventory(js: js)).isEmpty)
    }

    @Test("a removed param and a new source map file are reported on the right side")
    func test_JSR009_removedAndSources() {
        let map = { (param: String) in
            Data(
                (#"{"version":3,"file":"app.js","sources":["webpack://app/./src/a.js"],"#
                    + #""sourcesContent":["new URLSearchParams().get('\#(param)');"]}"#).utf8)
        }
        let old = JSRecon.inventory(js: "new URLSearchParams().get('legacy');", sourceMap: map("oldOnly"))
        let new = JSRecon.inventory(js: "new URLSearchParams().get('kept');", sourceMap: map("oldOnly"))
        let diff = JSRecon.diff(from: old, to: new)

        #expect(diff.removedParameters.contains("legacy"))
        #expect(diff.addedParameters.contains("kept"))
        #expect(diff.addedSources.isEmpty)  // same map path in both
        #expect(diff.removedSources.isEmpty)
    }
}
