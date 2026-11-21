import Foundation
import GulpWorkspace

/// A temporary project in its own support folder (file CA and secret stores: no Keychain).
func openIsolatedSession() async throws -> ProjectSession {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "gulp-features-\(UUID().uuidString)")
    var environment = WorkspaceEnvironment(
        supportDirectory: root.appendingPathComponent("support"),
        cachesDirectory: root.appendingPathComponent("caches"))
    environment.caKeyType = .p256  // fast key generation in tests
    return try await ProjectSession.openTemporary(environment: environment)
}

/// Wait (on the main actor, yielding) until `condition` holds, or fail after `timeout`.
@MainActor
func eventually(
    timeout: Duration = .seconds(5), _ condition: @MainActor () async -> Bool
) async -> Bool {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return await condition()
}
