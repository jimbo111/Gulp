// GulpScanner — every issue-type id the code names must have a definition. Ids are plain strings, and a
// missing definition traps in `IssueDefinitions.require` — at runtime, in the middle of a live scan. This
// suite scans `Sources/` for every literal id handed to `require(…)`, `PassiveChecks.d(…)` or a
// `…finding(…)` call (and every check whose `let id` is passed to `finding(id, …)`), so a typo or a
// forgotten definition fails `make test-core` instead. It also forbids building an id by interpolation,
// which this scan could not verify.

import Foundation
import Testing

@testable import GulpScanner

@Suite("Issue-type ids resolve (definitions cover every id the code emits)")
struct IssueIDCoverageTests {
    /// `Packages/GulpKit/Sources`, located from this file.
    static let sources = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Sources")

    /// Every Swift source file (vulnlab is a fixture server, not a producer of issues).
    static func swiftFiles() -> [(name: String, text: String)] {
        guard let walker = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil)
        else { return [] }
        return walker.compactMap { $0 as? URL }
            .filter { $0.pathExtension == "swift" && !$0.path.contains("/gulp-vulnlab/") }
            .compactMap { url in
                (try? String(contentsOf: url, encoding: .utf8)).map { (url.lastPathComponent, $0) }
            }
    }

    static func captures(_ pattern: String, in text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        return regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).compactMap {
            Range($0.range(at: 1), in: text).map { String(text[$0]) }
        }
    }

    @Test("the source scan sees the producers (guards against a vacuous pass)")
    func scanFindsProducers() {
        let files = Self.swiftFiles()
        #expect(files.count > 50, "found \(files.count) source files under \(Self.sources.path)")
        let literals = files.flatMap { Self.captures(#"[fF]inding\(\s*"([^"]+)""#, in: $0.text) }
        let ownIDs = files.flatMap { Self.captures(#"let id = "(active\.[^"]+)""#, in: $0.text) }
        // 18 literal sites and ~30 check ids today; far fewer means the scan is looking in the wrong place.
        #expect(
            literals.count >= 10 && ownIDs.count >= 20,
            "\(literals.count) literals, \(ownIDs.count) check ids")
    }

    @Test("every literal id passed to require / d / …finding has a definition")
    func literalIDsResolve() {
        let patterns = [
            #"[fF]inding\(\s*"([^"]+)""#,
            #"IssueDefinitions\.require\(\s*"([^"]+)""#,
            #"PassiveChecks\.d\(\s*"([^"]+)""#,
        ]
        for file in Self.swiftFiles() {
            for pattern in patterns {
                for id in Self.captures(pattern, in: file.text) {
                    #expect(IssueDefinitions.named(id) != nil, "\(file.name): no definition for '\(id)'")
                }
            }
        }
    }

    @Test("a check that reports under its own `let id` has a definition for it")
    func checkOwnIDsResolve() {
        for file in Self.swiftFiles() where file.text.contains("ActiveCheck") {
            // Split into `struct …` blocks so each `let id` is paired with its own `finding(id, …)`.
            for block in file.text.components(separatedBy: "\nstruct ").dropFirst() {
                guard block.range(of: #"finding\(\s*id\s*,"#, options: .regularExpression) != nil,
                    let id = Self.captures(#"let id = "([^"]+)""#, in: block).first
                else { continue }
                #expect(IssueDefinitions.named(id) != nil, "\(file.name): check id '\(id)' has no definition")
            }
        }
    }

    @Test("ids are literals, never interpolated (the scan above could not verify those)")
    func noInterpolatedIDs() {
        for file in Self.swiftFiles() {
            let interpolated = Self.captures(#"([fF]inding\(\s*"[^"]*\\\()"#, in: file.text)
            #expect(interpolated.isEmpty, "\(file.name): interpolated issue id \(interpolated)")
        }
    }
}
