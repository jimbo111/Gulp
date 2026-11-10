// GulpProxy — GulpQL for proxy rules (F05 HIS-027): intercept rules written as an expression
// (PRX-015) and Match & Replace conditions (PRX-025) evaluate the same expression type as History
// and the Logger, over the message as it passes.

import GulpCore
import GulpHTTP
import GulpQuery

/// Builds what a GulpQL rule evaluates in the proxy.
public enum ProxyQuery {
    /// Bodies are decoded (gzip, deflate…) up to the GulpQL body limit.
    public static func context(scope: ScopeService?) -> GulpQLContext {
        GulpQLContext(
            scope: scope,
            decodeBody: { body, encoding in
                try? ContentDecoding.decode(Bytes(body), contentEncoding: encoding, limit: 2 * 1024 * 1024)
                    .rawBytes
            })
    }

    /// The message as an exchange (no id yet; `resp.*` fields are missing until there is a response).
    public static func exchange(
        _ request: RawRequest, target: HTTPTarget, response: RawResponse? = nil, source: ToolSource = .proxy
    ) -> Exchange {
        Exchange(source: source, target: target, request: request, response: response, state: .pending)
    }

    /// Whether `predicate` holds for the message.
    public static func holds(
        _ predicate: GulpQLPredicate, request: RawRequest, target: HTTPTarget, response: RawResponse? = nil,
        source: ToolSource = .proxy, scope: ScopeService?
    ) -> Bool {
        predicate.evaluate(
            exchange(request, target: target, response: response, source: source),
            context: context(scope: scope))
    }
}
