// GulpWorkspace — running the Authorization Matrix (F23 ADV-001…005). Replays each request as each
// identity by stripping the original Cookie/Authorization and applying the identity's cookies and
// headers (reusing the F15 identities), sends through the engine as scanner traffic under ScopeGuard,
// computes the verdicts (AuthzAnalysis), and raises a broken-access-control issue for each Bypassed
// cell with both exchanges as evidence.

import Foundation
import GulpCore
import GulpHTTP
import GulpScanner
import GulpSession

extension RawRequest {
    /// The request with the caller's own auth removed and `identity`'s cookies/headers applied, so it
    /// is replayed "as" that identity (ADV-001). The unauthenticated identity simply strips auth.
    func authorized(as identity: Identity?, target: HTTPTarget, now: Date = Date()) -> RawRequest {
        var request = removingHeader("cookie").removingHeader("authorization")
        guard let identity else { return request }
        if let cookie = identity.cookies.header(
            host: target.host, path: bytes[parsed.target].string(), scheme: target.scheme, now: now)
        {
            request = request.settingHeader("Cookie", to: cookie)
        }
        for (name, value) in identity.headers.sorted(by: { $0.key < $1.key }) {
            request = request.settingHeader(name, to: VariableExpansion.expand(value, identity.allVariables))
        }
        return request
    }
}

extension ProjectSession {
    /// Run the Authz Matrix over `requests` with the project's identities (ADV-001…003). The
    /// authorized baseline is `authorizedIdentity` (default: the active identity). `includeUnauth`
    /// adds an unauthenticated column. Bypasses become issues.
    public func runAuthzMatrix(
        _ requests: [(request: RawRequest, target: HTTPTarget)], authorizedIdentity: UUID? = nil,
        includeUnauthenticated: Bool = true, threshold: Double = 0.95, allowOutOfScope: Bool = false
    ) async throws -> AuthzMatrixResult {
        let config = sessionSettings()
        let identities = config.identities
        let authorizedID = authorizedIdentity ?? config.activeIdentity ?? identities.first?.id
        guard let authorizedID else { throw AuthzError.noIdentities }

        // Columns: the authorized identity first, then the others, then (optionally) unauthenticated.
        var columns: [UUID?] = [authorizedID] + identities.map(\.id).filter { $0 != authorizedID }
        if includeUnauthenticated { columns.append(nil) }
        let byID = Dictionary(uniqueKeysWithValues: identities.map { ($0.id, $0) })
        let send = scanSender()
        let inScope = scanScope(allowOutOfScope: allowOutOfScope)

        var cells: [AuthzCell] = []
        var raised: [IssueID] = []
        var labels: [String] = []

        for (index, item) in requests.enumerated() {
            let derived = DerivedFields(target: item.target, request: item.request, response: nil)
            let path = (derived.path ?? "/") + (derived.query.map { "?" + $0 } ?? "")
            labels.append("\(derived.method ?? "GET") \(derived.path ?? "/")")
            guard await inScope(item.target, path) else { continue }

            // Send as each column, remembering the authorized and unauthenticated responses.
            var responses: [UUID?: AuthzResponse] = [:]
            for column in columns {
                let request = item.request.authorized(as: column.flatMap { byID[$0] }, target: item.target)
                let probe = await send(request, item.target)
                let body =
                    probe.response.map { String(decoding: $0.bytes.rawBytes[$0.parsed.body], as: UTF8.self) }
                    ?? ""
                responses[column] = AuthzResponse(
                    status: probe.status ?? 0, body: body, exchangeID: probe.exchangeID)
            }
            await store.writer.flush()
            guard let authorized = responses[authorizedID] else { continue }

            for column in columns {
                guard let response = responses[column] else { continue }
                let verdict = AuthzAnalysis.verdict(
                    candidate: response, authorized: authorized, isAuthorized: column == authorizedID,
                    isUnauthenticated: column == nil, threshold: threshold)
                cells.append(
                    AuthzCell(requestIndex: index, identity: column, response: response, verdict: verdict))
                if verdict == .bypassed {
                    let who = column.flatMap { byID[$0]?.name } ?? "an unauthenticated user"
                    let finding = authzFinding(
                        request: item.request, target: item.target, who: who, response: response,
                        authorized: authorized)
                    if let id = await persisting(
                        "an Authz Matrix issue", events: events, { try await store.record(finding) })?.id
                    {
                        raised.append(id)
                    }
                }
            }
        }
        await store.writer.flush()
        return AuthzMatrixResult(requests: labels, columns: columns, cells: cells, issuesRaised: raised)
    }

    private func authzFinding(
        request: RawRequest, target: HTTPTarget, who: String, response: AuthzResponse,
        authorized: AuthzResponse
    ) -> IssueFinding {
        let definition = IssueDefinitions.require("authz.broken-access-control")
        let derived = DerivedFields(target: target, request: request, response: nil)
        return IssueFinding(
            typeID: definition.id, name: definition.name, severity: definition.severity,
            confidence: definition.confidence, host: Issue.origin(target), path: derived.path ?? "/",
            insertionPoint: nil, variant: who,
            detail:
                "Replaying this request as **\(who)** returned the same response as the authorized user (status \(response.status)), so the server isn't checking authorization.",
            background: definition.background, remediation: definition.remediation,
            references: definition.references,
            evidence: IssueEvidence(exchangeID: response.exchangeID == 0 ? nil : response.exchangeID))
    }
}

/// Why the matrix couldn't run.
public enum AuthzError: Error, Sendable, CustomStringConvertible {
    /// No identities are configured.
    case noIdentities

    /// A human-readable reason.
    public var description: String {
        switch self {
        case .noIdentities: return "the Authz Matrix needs at least one identity (configure them in Sessions)"
        }
    }
}
