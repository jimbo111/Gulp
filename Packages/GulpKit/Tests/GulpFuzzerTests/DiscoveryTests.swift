import Foundation
import GulpCore
import Testing

@testable import GulpFuzzer

// F07 ETL-003 (content discovery) and FUZ-011 (bundled wordlists).

func discover(
    _ config: DiscoveryConfig, _ engine: FakeEngine,
    inScope: (@Sendable (HTTPTarget, String) async -> Bool)? = nil
)
    async throws -> (found: [DiscoveredPath], sent: Int, outOfScope: Int)
{
    let discovery = try ContentDiscovery(config: config, engine: engine, inScope: inScope)
    var found: [DiscoveredPath] = []
    var sent = 0
    var skipped = 0
    for await event in await discovery.start() {
        switch event {
        case .found(let path): found.append(path)
        case .finished(let total, let outOfScope, _):
            sent = total
            skipped = outOfScope
        }
    }
    return (found, sent, skipped)
}

@Suite("GulpFuzzer — content discovery (ETL-003) and wordlists (FUZ-011)")
struct DiscoveryTests {
    static let site: [String: Int] = [
        "/admin": 403, "/index.html": 200, "/index.html.bak": 200, "/backup.zip": 200, "/.old/": 403,
        "/.old/config.php~": 200,
    ]

    @Test("F07 acceptance 6: hidden /admin, backups and a nested backup are found; the tree shows them")
    func test_ETL003_discover() async throws {
        let engine = FakeEngine { request, _ in
            let path = String(request.split(separator: " ")[1])
            return Self.site[path].map { ($0, "content of \(path)") } ?? (404, "not found\n")
        }
        let words = PayloadSource.list(["admin", "index", "backup", ".old", "config", "nothing"])
        let config = DiscoveryConfig(
            baseURL: "http://lab:8088/", words: words, extensions: ["html", "zip", "php"],
            backupSuffixes: ["~", ".bak"],
            maxDepth: 2, concurrency: 4)
        let (found, sent, _) = try await discover(config, engine)
        let paths = Set(found.map(\.path))
        #expect(paths == Set(Self.site.keys))
        #expect(found.first { $0.path == "/.old/" }?.isDirectory == true)
        let tree = discoveryTree(found)
        #expect(tree.contains(".old/\t403\t" + String(found.first { $0.path == "/.old/" }!.length)))
        #expect(tree.contains { $0.hasPrefix("  config.php~\t200") })
        // Two directories probed: / and /.old/ (2 fingerprints + 6 words × (2 + 3 × 3) candidates each).
        #expect(sent == 2 * (2 + 6 * 11))
    }

    @Test("Soft 404s (200 for everything, path echoed) are filtered; scope is honoured")
    func test_ETL003_soft404AndScope() async throws {
        let engine = FakeEngine { request, _ in
            let path = String(request.split(separator: " ")[1])
            return path == "/real"
                ? (200, String(repeating: "real content ", count: 20)) : (200, "Sorry, \(path) was not found")
        }
        let config = DiscoveryConfig(
            baseURL: "http://lab:8088/", words: .list(["real", "fake", "private"]), extensions: [],
            backupSuffixes: [],
            maxDepth: 0, concurrency: 2)
        let (found, _, skipped) = try await discover(
            config, engine, inScope: { _, path in !path.hasPrefix("/private") })
        #expect(found.map(\.path) == ["/real"])
        #expect(skipped == 2)  // /private and /private/
    }

    @Test("ETL-003 / CLAUDE.md scope safety: the soft-404 fingerprint probes are scope-checked too")
    func test_ETL003_fingerprintScope() async throws {
        let engine = FakeEngine { _, _ in (404, "not found") }
        let config = DiscoveryConfig(
            baseURL: "http://lab:8088/", words: .list(["real"]), extensions: [], backupSuffixes: [],
            maxDepth: 0, concurrency: 1)
        // Only the two word candidates are in scope; the random fingerprint paths are not.
        let (_, sent, skipped) = try await discover(
            config, engine, inScope: { _, path in path == "/real" || path == "/real/" })
        let lines = engine.sent.map { $0.split(separator: "\r\n").first.map(String.init) ?? "" }
        #expect(Set(lines) == ["GET /real HTTP/1.1", "GET /real/ HTTP/1.1"])
        #expect(sent == 2 && skipped == 2)
    }

    @Test("FUZ-011: the bundled wordlists ship and install without overwriting the user's edits")
    func test_FUZ011_wordlists() throws {
        let content = try #require(BundledWordlists.url("content.txt"))
        let words = try String(contentsOf: content, encoding: .utf8)
        #expect(words.contains("\nadmin\n") && words.contains("\n.old\n") && words.contains("\nbackup\n"))
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(
            "gulp-wl-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try "mine\n".write(
            to: folder.appendingPathComponent("usernames.txt"), atomically: true, encoding: .utf8)
        let copied = try BundledWordlists.install(into: folder)
        #expect(copied.count == BundledWordlists.labels.count - 1 && !copied.contains("usernames.txt"))
        #expect(
            try String(contentsOf: folder.appendingPathComponent("usernames.txt"), encoding: .utf8)
                == "mine\n")
        #expect(try BundledWordlists.install(into: folder).isEmpty)
    }
}
