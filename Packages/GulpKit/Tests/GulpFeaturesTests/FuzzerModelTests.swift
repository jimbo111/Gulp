#if canImport(AppKit)
import Foundation
import GulpFuzzer
import GulpWorkspace
import Testing

@testable import GulpFeatures

@MainActor
@Suite("Fuzzer model")
struct FuzzerModelTests {
    /// FUZ-010/FUZ-012: a wordlist file is read once, off the main thread, when its path is set; the
    /// planned count and preview the view renders come from that copy, not from disk.
    @Test func test_FUZ010_wordlistReadOnceOffMain() async throws {
        let session = try await openIsolatedSession()
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("words-\(UUID()).txt")
        try "alpha\nbeta\n# comment\ngamma\n".write(to: file, atomically: true, encoding: .utf8)
        let model = FuzzerModel(session: session)
        model.sets[0].kind = .file
        model.sets[0].filePath = file.path

        await model.loadWordlist(file.path)
        #expect(model.plannedCount == "3 requests")
        #expect(model.preview(model.sets[0]) == ["alpha", "beta", "gamma"])

        // Rendering never touches the file again.
        try FileManager.default.removeItem(at: file)
        #expect(model.plannedCount == "3 requests")
        #expect(model.preview(model.sets[0]) == ["alpha", "beta", "gamma"])
        try await session.close()
    }

    /// A path that was never loaded counts as loading, without reading the file on the main thread.
    @Test func test_FUZ010_unloadedWordlistIsNotReadWhileRendering() async throws {
        let session = try await openIsolatedSession()
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("words-\(UUID()).txt")
        try "alpha\nbeta\n".write(to: file, atomically: true, encoding: .utf8)
        let model = FuzzerModel(session: session)
        model.sets[0].kind = .file
        model.sets[0].filePath = file.path
        #expect(model.plannedCount == "Loading wordlist…")
        #expect(model.preview(model.sets[0]).isEmpty)
        try await session.close()
    }

    /// FUZ-004: results reach the table on a 100 ms tick even when no further result arrives.
    @Test func test_FUZ004_resultsFlushOnTick() async throws {
        let session = try await openIsolatedSession()
        let model = FuzzerModel(session: session)
        model.beginResults()
        model.buffer(
            FuzzResult(
                seq: 1, payloads: ["a"], exchangeID: 0, status: 200, length: 10, timeMs: 1, error: nil,
                findings: ResponseFindings(matches: [], extracts: [], reflection: .none)))
        #expect(model.results.isEmpty)
        #expect(await eventually { model.results.count == 1 })
        model.endResults()
        try await session.close()
    }
}
#endif
