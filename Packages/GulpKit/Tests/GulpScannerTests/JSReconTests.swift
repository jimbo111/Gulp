import Foundation
import Testing

@testable import GulpScanner

@Suite("JavaScript Recon (F27 JSR-003/006/008)")
struct JSReconTests {
    @Test("JSR-003: detect sourceMappingURL and reconstruct original sources from a .map")
    func sourceMap() {
        let js = "console.log(1);\n//# sourceMappingURL=app.js.map\n"
        #expect(JSRecon.sourceMapURL(in: js) == "app.js.map")
        let map = Data(
            #"{"version":3,"sources":["webpack://app/./src/login.js","src/api.js"],"sourcesContent":["const x=1","fetch('/api')"]}"#
                .utf8)
        let files = JSRecon.reconstruct(sourceMap: map)
        #expect(files.count == 2)
        #expect(files.contains { $0.path.hasSuffix("src/login.js") && $0.content == "const x=1" })
    }

    @Test("JSR-006 / ADV-021: mine candidate parameter names, skipping JS keywords")
    func mineParams() {
        let js = #"const o={debug:true, userId:1}; fetch('/x?trace=1&admin=1'); params.get("token");"#
        let names = JSRecon.mineParameters(from: js)
        for expected in ["debug", "userId", "trace", "admin", "token"] {
            #expect(names.contains(expected), "missing \(expected) in \(names)")
        }
        #expect(!names.contains("true"))
        #expect(!names.contains("const"))
    }

    @Test("JSR-008: flag cloud-storage URLs, internal hosts and API bases")
    func literals() {
        let js = #"""
            var a="https://my-bucket.s3.amazonaws.com/k";
            var b="http://db.internal/x";
            const API_URL="https://api.corp.example/v1";
            """#
        let found = JSRecon.mineLiterals(from: js)
        #expect(found.contains { $0.kind == "cloud-storage" && $0.value.contains("s3.amazonaws.com") })
        #expect(found.contains { $0.kind == "internal-host" && $0.value.contains("db.internal") })
        #expect(found.contains { $0.kind == "api-base" && $0.value.contains("api.corp.example") })
    }
}
