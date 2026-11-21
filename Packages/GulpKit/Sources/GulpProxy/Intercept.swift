// GulpProxy — Intercept (F01 PRX-010…PRX-014, PRX-018): hold matching requests (and, separately,
// responses) in a queue until the user forwards them — possibly edited — or drops them.
//
// Concept: the proxy's connection task simply *awaits* the user's decision (a checked continuation
// per held item), so a held request blocks only its own exchange; other connections and other
// HTTP/2 streams keep flowing (PRX-017). Cancelling that task (its client went away) drops the item.

import Foundation
import GulpCore
import GulpHTTP
import GulpQuery

/// What an intercept condition looks at (PRX-013 requests, PRX-014 responses).
public enum InterceptField: String, Sendable, Codable, CaseIterable {
    case domain, ipAddress, scheme, method, url, fileExtension, hasParams, header, body, inScope
    case status, mime, requestWasIntercepted
}

/// How a condition combines with the result of the conditions before it.
public enum InterceptJoin: String, Sendable, Codable, CaseIterable {
    case and, or
}

/// One rule condition: `field` matches (or doesn't match) the regex `pattern`.
public struct InterceptCondition: Sendable, Codable, Hashable, Identifiable {
    /// Stable identity.
    public var id: UUID
    /// Disabled conditions are skipped.
    public var enabled: Bool
    /// AND/OR with the conditions before it (ignored for the first).
    public var join: InterceptJoin
    /// What is matched.
    public var field: InterceptField
    /// Regex (case-insensitive); empty matches anything.
    public var pattern: String
    /// "Doesn't match".
    public var negate: Bool

    /// A condition.
    public init(
        id: UUID = UUID(), enabled: Bool = true, join: InterceptJoin = .and, field: InterceptField,
        pattern: String, negate: Bool = false
    ) {
        self.id = id
        self.enabled = enabled
        self.join = join
        self.field = field
        self.pattern = pattern
        self.negate = negate
    }

    /// PRX-013 defaults: don't intercept static assets, and "only in scope" — present but off, so a
    /// project without a scope yet still intercepts (an empty scope has nothing in it).
    public static let defaultRequestRules = [
        InterceptCondition(
            field: .fileExtension, pattern: "^(gif|jpe?g|png|css|js|ico|svg|woff2?|ttf|webp|map)$",
            negate: true),
        InterceptCondition(enabled: false, field: .inScope, pattern: "^true$"),
    ]
}

/// One held message (PRX-011).
public struct InterceptItem: Sendable, Identifiable, Equatable {
    /// Held request or held response.
    public enum Kind: Sendable, Equatable {
        case request
        case response
        /// A WebSocket message going this way (PRX-033); `request` is the upgrade request.
        case webSocket(WSDirection)
    }

    /// Queue id.
    public let id: InterceptItemID
    /// What is held.
    public let kind: Kind
    /// Where the request goes.
    public let target: HTTPTarget
    /// The request (the one being held, or the one the held response answers).
    public let request: RawRequest
    /// The held response, for `.response` items.
    public let response: RawResponse?
    /// When it was queued (the UI shows time waiting).
    public let queuedAt: ContinuousClock.Instant
    /// The held WebSocket message's payload and opcode, for `.webSocket` items.
    public var webSocketPayload: [UInt8]? = nil
    /// Opcode of the held WebSocket message (1 text, 2 binary).
    public var webSocketOpcode: UInt8? = nil

    /// Whether this is a WebSocket message.
    public var isWebSocket: Bool {
        if case .webSocket = kind { return true }
        return false
    }
}

/// The user's decision for a held item.
public enum InterceptDecision: Sendable {
    /// Send it on, optionally with edited bytes.
    case forward(Bytes?)
    /// Discard it.
    case drop
}

/// The intercept queue for one proxy (PRX-010…PRX-014).
public actor InterceptQueue {
    /// Whether requests matching `requestRules` are held (PRX-010).
    public private(set) var interceptRequests = false
    /// Whether responses matching `responseRules` are held (PRX-014).
    public private(set) var interceptResponses = false
    /// Request rule conditions (PRX-013).
    public private(set) var requestRules = InterceptCondition.defaultRequestRules
    /// Response rule conditions (PRX-014).
    public private(set) var responseRules: [InterceptCondition] = []
    /// Whether WebSocket messages are held (PRX-033, a separate toggle).
    public private(set) var interceptWebSockets = false
    /// Conditions on the upgrade request that pick which connections' messages are held.
    public private(set) var webSocketRules: [InterceptCondition] = []
    /// A GulpQL request rule (PRX-015); when set it replaces `requestRules`.
    public private(set) var requestQuery: GulpQLPredicate?
    /// A GulpQL response rule (PRX-015); when set it replaces `responseRules`.
    public private(set) var responseQuery: GulpQLPredicate?
    /// The project scope: the `inScope` rule field and GulpQL rules (`in_scope`, `matches_scope`)
    /// evaluate against it; without one, nothing is in scope.
    public private(set) var scope: ScopeService?

    private struct Waiter {
        let item: InterceptItem
        let decide: CheckedContinuation<InterceptDecision, Never>
    }

    private var held: [InterceptItemID: Waiter] = [:]
    private var order: [InterceptItemID] = []
    private var nextID: InterceptItemID = 1
    private let events: EventBus?

    /// A queue that announces held and decided items on `events` (`interceptQueued`,
    /// `interceptDecided`).
    public init(events: EventBus? = nil) {
        self.events = events
    }

    /// The held items, oldest first.
    public var items: [InterceptItem] { order.compactMap { held[$0]?.item } }

    /// Turn interception on or off. Turning a kind off forwards everything of that kind unchanged.
    public func setIntercepting(requests: Bool? = nil, responses: Bool? = nil) {
        if let requests {
            interceptRequests = requests
            if !requests { releaseAll(.request) }
        }
        if let responses {
            interceptResponses = responses
            if !responses { releaseAll(.response) }
        }
    }

    /// Turn WebSocket message interception on or off (off forwards held messages unchanged).
    public func setInterceptingWebSockets(_ on: Bool) {
        interceptWebSockets = on
        if !on {
            for id in order where held[id]?.item.isWebSocket == true { decide(id, .forward(nil)) }
        }
    }

    /// Replace the rule sets.
    public func setRules(
        requests: [InterceptCondition]? = nil, responses: [InterceptCondition]? = nil,
        webSockets: [InterceptCondition]? = nil
    ) {
        if let requests { requestRules = requests }
        if let responses { responseRules = responses }
        if let webSockets { webSocketRules = webSockets }
    }

    /// Use GulpQL expressions instead of the rule builder (nil returns to the builder's rules).
    public func setQueries(request: GulpQLPredicate?, response: GulpQLPredicate?) {
        requestQuery = request
        responseQuery = response
    }

    /// The scope rules evaluate `inScope` / `in_scope` against.
    public func setScope(_ scope: ScopeService?) { self.scope = scope }

    /// Whether messages of the connection opened by `upgrade` are currently held.
    public func interceptsWebSockets(upgrade: RawRequest, target: HTTPTarget) -> Bool {
        interceptWebSockets
            && InterceptRules.matches(webSocketRules, request: upgrade, target: target, scope: scope)
    }

    /// Hold a WebSocket data message if WebSocket interception is on and the connection matches;
    /// an edited payload comes back in `.forward(bytes)`.
    public func holdWebSocketMessage(
        _ payload: [UInt8], opcode: UInt8, direction: WSDirection, upgrade: RawRequest, target: HTTPTarget
    ) async -> (InterceptDecision, held: Bool) {
        guard interceptsWebSockets(upgrade: upgrade, target: target) else { return (.forward(nil), false) }
        var item = InterceptItem(
            id: nextID, kind: .webSocket(direction), target: target, request: upgrade, response: nil,
            queuedAt: .now)
        item.webSocketPayload = payload
        item.webSocketOpcode = opcode
        return (await hold(item), true)
    }

    /// Decide a held item (Forward / Drop, PRX-011); announces `interceptDecided`.
    public func decide(_ id: InterceptItemID, _ decision: InterceptDecision) {
        guard let entry = held.removeValue(forKey: id) else { return }
        order.removeAll { $0 == id }
        entry.decide.resume(returning: decision)
        if let events { Task { await events.publish(.interceptDecided(id)) } }
    }

    /// Forward all (or drop all) held items.
    public func decideAll(_ decision: InterceptDecision) {
        for id in order { decide(id, decision) }
    }

    private func releaseAll(_ kind: InterceptItem.Kind) {
        for id in order where held[id]?.item.kind == kind { decide(id, .forward(nil)) }
    }

    /// Hold `request` if requests are intercepted and it matches the rules; returns the decision
    /// (an unheld request is forwarded unchanged) and whether it was held.
    public func holdRequest(
        _ request: RawRequest, target: HTTPTarget
    ) async -> (InterceptDecision, held: Bool) {
        guard interceptRequests else { return (.forward(nil), false) }
        let matches =
            requestQuery.map { ProxyQuery.holds($0, request: request, target: target, scope: scope) }
            ?? InterceptRules.matches(requestRules, request: request, target: target, scope: scope)
        guard matches else { return (.forward(nil), false) }
        return (await hold(.request, request: request, response: nil, target: target), true)
    }

    /// Hold `response` if responses are intercepted and it matches the rules.
    public func holdResponse(
        _ response: RawResponse, for request: RawRequest, target: HTTPTarget, requestWasHeld: Bool
    ) async -> (InterceptDecision, held: Bool) {
        guard interceptResponses else { return (.forward(nil), false) }
        let matches =
            responseQuery.map {
                ProxyQuery.holds($0, request: request, target: target, response: response, scope: scope)
            }
            ?? InterceptRules.matches(
                responseRules, request: request, target: target, response: response,
                requestWasHeld: requestWasHeld, scope: scope)
        guard matches else { return (.forward(nil), false) }
        return (await hold(.response, request: request, response: response, target: target), true)
    }

    private func hold(
        _ kind: InterceptItem.Kind, request: RawRequest, response: RawResponse?, target: HTTPTarget
    ) async -> InterceptDecision {
        let item = InterceptItem(
            id: nextID, kind: kind, target: target, request: request, response: response, queuedAt: .now)
        return await hold(item)
    }

    /// Queue `item` until it is decided, or dropped when the waiting task is cancelled (the client
    /// went away). The cancel handler's `decide` runs on the actor after the item is queued, so a
    /// task cancelled before it got here still has its item dropped.
    private func hold(_ item: InterceptItem) async -> InterceptDecision {
        let id = item.id
        nextID += 1
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                held[id] = Waiter(item: item, decide: continuation)
                order.append(id)
                if let events { Task { await events.publish(.interceptQueued(id)) } }
            }
        } onCancel: {
            Task { await self.decide(id, .drop) }
        }
    }
}

/// Rule evaluation (PRX-013/PRX-014).
public enum InterceptRules {
    /// Whether the message satisfies `conditions` (left to right, AND/OR; no enabled conditions
    /// matches everything). `inScope` is decided by `scope` (without one, nothing is in scope).
    public static func matches(
        _ conditions: [InterceptCondition], request: RawRequest, target: HTTPTarget,
        response: RawResponse? = nil, requestWasHeld: Bool = false, scope: ScopeService? = nil
    ) -> Bool {
        var result: Bool?
        for condition in conditions where condition.enabled {
            let value = subject(
                condition.field, request: request, target: target, response: response,
                requestWasHeld: requestWasHeld, scope: scope)
            var hit = matchesPattern(condition.pattern, value)
            if condition.negate { hit.toggle() }
            switch (result, condition.join) {
            case (nil, _): result = hit
            case (let previous?, .and): result = previous && hit
            case (let previous?, .or): result = previous || hit
            }
        }
        return result ?? true
    }

    static func subject(
        _ field: InterceptField, request: RawRequest, target: HTTPTarget, response: RawResponse?,
        requestWasHeld: Bool, scope: ScopeService?
    ) -> String {
        let bytes = request.bytes
        let requestTarget = bytes[request.parsed.target].string()
        let path = String(requestTarget.split(separator: "?", maxSplits: 1).first ?? "")
        switch field {
        case .domain: return target.host
        case .ipAddress: return target.ipOverride ?? target.host
        case .scheme: return target.scheme.rawValue
        case .method: return bytes[request.parsed.method].string()
        case .url: return requestTarget
        case .fileExtension:
            let last = path.split(separator: "/").last ?? ""
            guard let dot = last.lastIndex(of: ".") else { return "" }
            return String(last[last.index(after: dot)...]).lowercased()
        case .hasParams:
            let type = request.headerValue("content-type")?.string() ?? ""
            let form = type.contains("x-www-form-urlencoded")
            return requestTarget.contains("?") || form ? "true" : "false"
        case .header: return headerText(request.bytes, request.parsed.headers)
        case .body:
            if let response { return Latin1.string(response.bytes[response.parsed.body].rawBytes) }
            return Latin1.string(bytes[request.parsed.body].rawBytes)
        case .inScope:
            let pathAndQuery =
                requestTarget.contains("://") ? ScopeService.requestPath(ofURL: requestTarget) : requestTarget
            return scope?.isInScope(target, path: pathAndQuery) == true ? "true" : "false"
        case .status: return response.map { String($0.parsed.statusCode) } ?? ""
        case .mime: return response?.headerValue("content-type")?.string() ?? ""
        case .requestWasIntercepted: return requestWasHeld ? "true" : "false"
        }
    }

    static func headerText(_ bytes: Bytes, _ fields: [HeaderField]) -> String {
        fields.map { "\(bytes[$0.name].string()): \(bytes[$0.value].string())" }.joined(separator: "\n")
    }

    static func matchesPattern(_ pattern: String, _ value: String) -> Bool {
        guard !pattern.isEmpty else { return true }
        // Case-insensitive; ^ and $ match at line boundaries (header conditions see one line per header).
        guard let regex = try? Regex(pattern).ignoresCase().anchorsMatchLineEndings() else { return false }
        return value.contains(regex)
    }
}
