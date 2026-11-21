// GulpFeatures — the Authz Matrix screen (F23 §1, ADV-001…003). The matrix engine (replay each request
// as every identity, classify authorized / enforced / bypassed) lives in GulpWorkspace and is tested on
// Linux; this file drives it: it replays the requests queued with "Actively scan" as each configured identity
// and shows the verdict grid, so an access-control bypass (a privileged response under a lower identity)
// stands out. The main thread never waits on the network — the run is a cancellable task.

#if canImport(AppKit)
import AppKit
import GulpCore
import GulpWorkspace
import Observation
import SwiftUI

/// State behind the Authz Matrix.
@MainActor
@Observable
public final class AuthzMatrixModel {
    /// The last finished matrix.
    public private(set) var result: AuthzMatrixResult?
    /// A status line.
    public private(set) var status: String =
        "Select requests in HTTP History and choose Actively scan, then Run."

    @ObservationIgnored let session: ProjectSession
    @ObservationIgnored private var task: Task<Void, Never>?

    /// A model for `session`.
    public init(session: ProjectSession) { self.session = session }

    /// Replay the queued requests as every identity and classify each cell.
    public func run() {
        task?.cancel()
        task = Task {
            status = "Running…"
            let ids = await session.inbox.scanInput
            guard !ids.isEmpty else {
                status = "No requests queued. Select requests in HTTP History and choose Actively scan first."
                return
            }
            do {
                let requests = try await session.scanRequests(exchanges: ids)
                let matrix = try await session.runAuthzMatrix(requests)
                result = matrix
                status =
                    "\(matrix.requests.count) request(s) × \(matrix.columns.count) identity column(s); "
                    + "\(matrix.issuesRaised.count) bypass issue(s)"
            } catch {
                status = "Failed: \(error)"
            }
        }
    }

    /// A label for an identity column (the authorized one is first; nil is the unauthenticated column).
    func columnLabel(_ index: Int, _ identity: UUID?) -> String {
        if identity == nil { return "unauth" }
        return index == 0 ? "authorized" : "identity \(index)"
    }
}

/// The Authz Matrix: replay requests across identities and read the verdict grid.
public struct AuthzMatrixView: View {
    private let model: AuthzMatrixModel

    /// The Authz Matrix of the project whose tool models are `models`.
    public init(models: ToolModels) {
        model = models.authzMatrix
    }

    /// The screen.
    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button("Run") { model.run() }.keyboardShortcut(.return, modifiers: .command)
                Text(model.status).font(.callout).foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, 6)
            Divider()
            if let result = model.result {
                ScrollView([.horizontal, .vertical]) {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 8) {
                            Text("Request").frame(width: 260, alignment: .leading).bold()
                            ForEach(Array(result.columns.enumerated()), id: \.offset) { index, identity in
                                Text(model.columnLabel(index, identity)).frame(width: 90).bold()
                            }
                        }
                        ForEach(Array(result.requests.enumerated()), id: \.offset) { row, label in
                            HStack(spacing: 8) {
                                Text(label).frame(width: 260, alignment: .leading)
                                    .font(.system(.caption, design: .monospaced)).lineLimit(1)
                                ForEach(Array(result.columns.enumerated()), id: \.offset) { _, identity in
                                    verdictBadge(result.cell(request: row, identity: identity)?.verdict)
                                        .frame(width: 90)
                                }
                            }
                        }
                    }
                    .padding(6)
                }
            } else {
                ContentUnavailableView(
                    "No matrix yet", systemImage: "person.2.badge.key",
                    description: Text("Queue requests for analysis, then press Run (⌘↵)."))
            }
        }
        .navigationTitle("Authz Matrix")
    }

    @ViewBuilder
    private func verdictBadge(_ verdict: AuthzVerdict?) -> some View {
        switch verdict {
        case .bypassed:
            Text("bypassed").font(.caption).foregroundStyle(.red).bold()
        case .enforced:
            Text("enforced").font(.caption).foregroundStyle(.green)
        case .authorized:
            Text("authorized").font(.caption).foregroundStyle(.secondary)
        case .sameAsAuthorized:
            Text("same").font(.caption).foregroundStyle(.orange)
        case .needsReview:
            Text("review").font(.caption).foregroundStyle(.orange)
        case .none:
            Text("—").font(.caption).foregroundStyle(.secondary)
        }
    }
}
#endif
