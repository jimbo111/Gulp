import Foundation
import GulpCore
import GulpReport
import GulpStore
import Testing

@testable import GulpWorkspace

@Suite("End-to-end: capture → store → passive scan → report")
struct IntegrationTests {
    @Test("workspace module is linkable from integration tests")
    func workspaceLinkable() {
        #expect(GulpWorkspace.moduleName == "GulpWorkspace")
    }

    /// An isolated, throwaway workspace (no Keychain, fast CA key) for a self-contained project.
    private func isolatedEnvironment() -> WorkspaceEnvironment {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("gulp-it-\(UUID().uuidString)")
        var environment = WorkspaceEnvironment(
            supportDirectory: root.appendingPathComponent("support"),
            cachesDirectory: root.appendingPathComponent("caches"))
        environment.caKeyType = .p256
        return environment
    }

    /// The whole pipeline a user drives: traffic is captured into a project, the passive scanner turns
    /// it into issues, and a shareable report is rendered from those issues — across GulpStore,
    /// GulpScanner (via the workspace) and GulpReport in one flow.
    @Test("a vulnerable page is captured, scanned into issues, and rendered into HTML + Markdown reports")
    func captureScanReport() async throws {
        let session = try await ProjectSession.openTemporary(environment: isolatedEnvironment())

        // 1. Capture: a page with no security headers and a bare (non-HttpOnly) cookie — as the proxy
        //    would record it.
        let body = "<h1>Welcome</h1>"
        let response =
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nSet-Cookie: sid=secret\r\n"
            + "Content-Length: \(body.utf8.count)\r\n\r\n\(body)"
        let id = await session.store.writer.record(
            Exchange(
                source: .proxy, target: HTTPTarget(scheme: .http, host: "app.example"),
                request: RawRequest(Bytes("GET /dashboard HTTP/1.1\r\nHost: app.example\r\n\r\n")),
                response: RawResponse(Bytes(response)), state: .complete))
        #expect(id > 0)

        // 2. Scan: the live passive scanner turns the recorded exchange into issues.
        await session.passiveScan.drain()
        let issues = try await session.store.issues()
        let types = Set(issues.map(\.typeID))
        #expect(types.contains("passive.csp.missing"), "\(types)")
        #expect(types.contains("passive.cookie.no-httponly"), "\(types)")
        // The page-level CSP finding is attributed to the captured path (cookie findings are host-wide).
        #expect(issues.contains { $0.typeID == "passive.csp.missing" && $0.path == "/dashboard" })

        // 3. Report: both renderers produce a self-contained report naming the findings.
        let when = Date(timeIntervalSince1970: 1_700_000_000)
        let html = GulpReport.render(issues, title: "Engagement", format: .html, now: when)
        #expect(html.contains("<html") && html.contains("Engagement"))
        #expect(html.contains("Content Security Policy") || html.lowercased().contains("csp"))
        #expect(!html.contains("<script>alert"))  // issue text is escaped, not executed

        let markdown = GulpReport.render(issues, title: "Engagement", format: .markdown, now: when)
        #expect(markdown.contains("# ") && markdown.contains("Engagement"))
        // Every raised issue type appears in the Markdown body.
        for issue in issues { #expect(markdown.contains(issue.name), "missing \(issue.name)") }

        // 4. An empty project renders a clean report (no crash, no findings).
        let empty = GulpReport.render([], title: "Empty", format: .markdown, now: when)
        #expect(empty.contains("Empty"))

        try await session.close()
    }
}
