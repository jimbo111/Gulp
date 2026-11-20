// GulpWorkspace — the GraphQL Workbench's engine-backed actions (F23 §5 ADV-040…042, M13b):
// introspect an endpoint and parse its schema, send an operation, and run the security checks
// (introspection exposed, and a probe for broken object/field authorization) raising issues. The
// parsing/rendering is GulpCodec's `GraphQL`/`GraphQLSchema`; this layer adds the network and issues.

import Foundation
import GulpCodec
import GulpCore
import GulpHTTP
import GulpScanner

/// The result of introspecting an endpoint (ADV-040).
public struct GraphQLIntrospection: Sendable {
    /// The parsed schema, or nil when introspection is disabled.
    public var schema: GraphQLSchema?
    /// Whether the endpoint answered an introspection query at all.
    public var enabled: Bool
    /// The exchange id of the introspection request.
    public var exchangeID: ExchangeID
}

extension ProjectSession {
    /// Build a GraphQL POST request to `path` on `target`.
    nonisolated func graphQLRequest(_ gql: GraphQLRequest, path: String, host: String) -> RawRequest {
        let body = GraphQL.body(gql)
        let head = [
            "POST \(path) HTTP/1.1", "Host: \(host)", "Content-Type: application/json",
            "Accept: application/json",
            "Content-Length: \(body.count)",
        ].joined(separator: "\r\n")
        return RawRequest(Bytes(Array((head + "\r\n\r\n").utf8) + body))
    }

    nonisolated func hostHeader(_ target: HTTPTarget) -> String {
        target.port == (target.scheme == .https ? 443 : 80) ? target.host : "\(target.host):\(target.port)"
    }

    /// Introspect a GraphQL endpoint and parse its schema (ADV-040).
    public func introspectGraphQL(path: String, target: HTTPTarget) async -> GraphQLIntrospection {
        let request = graphQLRequest(
            GraphQLRequest(query: GraphQL.introspectionQuery), path: path, host: hostHeader(target))
        var options = SendOptions(recordAs: .scanner)
        options.timeouts.total = .seconds(30)
        let result = await http.send(request, to: target, options: options)
        guard let response = result.exchange.response else {
            return GraphQLIntrospection(schema: nil, enabled: false, exchangeID: result.exchange.id)
        }
        let body = Data(response.bytes.rawBytes[response.parsed.body])
        let schema = GraphQLSchema.parse(introspection: body)
        return GraphQLIntrospection(schema: schema, enabled: schema != nil, exchangeID: result.exchange.id)
    }

    /// Send a GraphQL operation and return the response text (ADV-041).
    public func sendGraphQL(_ gql: GraphQLRequest, path: String, target: HTTPTarget) async -> (
        status: Int, body: String, exchangeID: ExchangeID
    ) {
        let request = graphQLRequest(gql, path: path, host: hostHeader(target))
        var options = SendOptions(recordAs: .repeater)
        options.timeouts.total = .seconds(30)
        let result = await http.send(request, to: target, options: options)
        let response = result.exchange.response
        let body = response.map { String(decoding: $0.bytes.rawBytes[$0.parsed.body], as: UTF8.self) } ?? ""
        return (response?.parsed.statusCode ?? 0, body, result.exchange.id)
    }

    /// Run the GraphQL security checks against `path` and raise issues (ADV-042). `authzProbe`, when
    /// given, is a query that should be denied to an unauthenticated caller but whose `sensitiveMarker`
    /// appearing in the unauthenticated response proves broken object/field authorization.
    public func scanGraphQL(
        path: String, target: HTTPTarget, authzProbe: GraphQLRequest? = nil, sensitiveMarker: String? = nil
    ) async throws -> [IssueID] {
        var raised: [IssueID] = []
        let introspection = await introspectGraphQL(path: path, target: target)
        let origin = Issue.origin(target)

        if introspection.enabled {
            await store.writer.flush()  // commit the evidence exchange before the issue references it
            let finding = graphQLFinding(
                "graphql.introspection-enabled", origin: origin, path: path,
                exchangeID: introspection.exchangeID,
                detail:
                    "The endpoint answered a full introspection query, exposing \(introspection.schema?.queries.count ?? 0) queries and \(introspection.schema?.mutations.count ?? 0) mutations."
            )
            if let id = try? await store.record(finding).id { raised.append(id) }
        }

        if let authzProbe, let sensitiveMarker {
            // Send the probe with no credentials; if the sensitive marker comes back, authz is missing.
            let result = await sendGraphQL(authzProbe, path: path, target: target)
            if result.body.contains(sensitiveMarker) {
                await store.writer.flush()
                let finding = graphQLFinding(
                    "graphql.broken-object-authz", origin: origin, path: path, exchangeID: result.exchangeID,
                    detail:
                        "An unauthenticated GraphQL query returned another object's sensitive field (`\(sensitiveMarker)` in the response), so object/field-level authorization isn't enforced in the resolver."
                )
                if let id = try? await store.record(finding).id { raised.append(id) }
            }
        }
        await store.writer.flush()
        return raised
    }

    private func graphQLFinding(
        _ typeID: String, origin: String, path: String, exchangeID: ExchangeID, detail: String
    ) -> IssueFinding {
        let definition = IssueDefinitions.require(typeID)
        return IssueFinding(
            typeID: definition.id, name: definition.name, severity: definition.severity,
            confidence: definition.confidence, host: origin, path: path, insertionPoint: nil, variant: "",
            detail: detail, background: definition.background, remediation: definition.remediation,
            references: definition.references,
            evidence: IssueEvidence(exchangeID: exchangeID == 0 ? nil : exchangeID))
    }
}
