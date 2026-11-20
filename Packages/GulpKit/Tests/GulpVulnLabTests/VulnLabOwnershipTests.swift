// VulnLab route ownership: every route is answered by exactly one lab, so the lab dispatch order in
// `VulnLab.labs` never decides who answers. Runs the labs in-process, with no server.

import Foundation
import GulpCore
import Testing

@testable import gulp_vulnlab

@Suite("VulnLab: each route belongs to exactly one lab")
struct VulnLabOwnershipTests {
    static let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()

    /// Every route the fixtures, the crawl list and the lab sources name, plus each one's other twin.
    static let corpus: [String] = {
        var paths: Set<String> = []
        let fixtures = packageRoot.appendingPathComponent("Tests/Fixtures")
        for name in ["vulnlab-active.json", "vulnlab-issues.json"] {
            let data = (try? Data(contentsOf: fixtures.appendingPathComponent(name))) ?? Data()
            let entries = (try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]) ?? []
            for entry in entries { if let path = entry["path"] as? String { paths.insert(path) } }
        }
        let crawl =
            (try? String(contentsOf: fixtures.appendingPathComponent("vulnlab-crawl.txt"), encoding: .utf8))
            ?? ""
        paths.formUnion(crawl.split(whereSeparator: \.isNewline).map(String.init))
        // `case "/route"` literals in the lab sources (covers labs no fixture lists).
        let sources = packageRoot.appendingPathComponent("Sources/gulp-vulnlab")
        let caseLiteral = try! NSRegularExpression(pattern: #"case\s+((?:"/[^"]*"\s*,?\s*)+):"#)
        let literal = try! NSRegularExpression(pattern: #""(/[^"]*)""#)
        for file in (try? FileManager.default.contentsOfDirectory(atPath: sources.path)) ?? [] {
            guard let text = try? String(contentsOf: sources.appendingPathComponent(file), encoding: .utf8)
            else {
                continue
            }
            let ns = text as NSString
            for match in caseLiteral.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                let list = ns.substring(with: match.range(at: 1)) as NSString
                for item in literal.matches(
                    in: list as String, range: NSRange(location: 0, length: list.length))
                {
                    paths.insert(list.substring(with: item.range(at: 1)))
                }
            }
        }
        let routes = paths.map { String($0.split(separator: "?", maxSplits: 1).first ?? "") }
            .filter { $0.hasPrefix("/") && !$0.hasPrefix("/lab/") }  // /lab/* mutate lab state
        return Set(routes.flatMap { [$0, "/safe" + SafeTwin.split($0).route] }).sorted()
    }()

    func request(_ method: String, _ path: String) -> RawRequest {
        RawRequest(Bytes("\(method) \(path) HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Length: 0\r\n\r\n"))
    }

    /// The labs that answer `method path`.
    func owners(_ method: String, _ path: String) -> [String] {
        VulnLab.labs.filter { $0.respond(request(method, path), path, [:]) != nil }.map(\.name)
    }

    @Test func corpusIsNotVacuous() {
        #expect(Self.corpus.count > 150)
        #expect(Self.corpus.contains("/safe/recon/app.js"))
    }

    @Test func noRouteIsClaimedByTwoLabs() {
        for method in ["GET", "POST"] {
            for path in Self.corpus {
                let claimed = owners(method, path)
                #expect(
                    claimed.count <= 1,
                    "\(method) \(path) is answered by \(claimed.joined(separator: " and "))")
            }
        }
    }

    // The regression that motivated the check: ScanLab's `/recon/*` bundles must not shadow ReconLab's
    // `/safe/recon/*` clean twins.
    @Test func safeReconBelongsToReconLab() {
        #expect(owners("GET", "/safe/recon/app.js") == ["ReconLab"])
        #expect(owners("GET", "/safe/recon/config") == ["ReconLab"])
    }

    @Test func safeTwinSplit() {
        #expect(SafeTwin.split("/safe/sqli/error") == ("/sqli/error", true))
        #expect(SafeTwin.split("/sqli/error") == ("/sqli/error", false))
        #expect(SafeTwin.split("/safelist") == ("/safelist", false))
    }
}
