// GulpSession — macros (F15 SES-020…SES-023): an ordered list of requests replayed to establish or
// refresh session state. Each step can capture values from its response (a cookie, a regex group, a
// JSON path) into variables that later steps, session rules and Transform Tags read; cookies are
// carried forward automatically through the jar. The runner is engine-agnostic (it takes a sender),
// so it is tested on Linux and reused by Repeater, the Crawler and the Scanner for re-auth.

import Foundation
import GulpCore
import GulpHTTP

/// Where a macro step reads a captured value from (SES-020).
public enum MacroCapture: Sendable, Hashable, Codable {
    /// A cookie's value by name.
    case cookie(String)
    /// The first capture group of a regex over the response body.
    case regex(String)
    /// A response header's value.
    case header(String)
    /// A JSON value by dotted path (`token`, `data.access_token`).
    case jsonPath(String)
}

/// One captured variable: where to read it and the variable name to store it under.
public struct MacroExtraction: Sendable, Hashable, Codable {
    /// Variable name to store under.
    public var variable: String
    /// Where to read the value.
    public var from: MacroCapture

    /// An extraction.
    public init(variable: String, from: MacroCapture) {
        self.variable = variable
        self.from = from
    }
}

/// One macro step (SES-020/021).
public struct MacroStep: Sendable, Hashable, Codable {
    /// The request bytes. `${var}` references are expanded before sending (SES-021).
    public var request: [UInt8]
    /// Where it goes.
    public var target: HTTPTarget
    /// Values to capture from the response for later steps and rules.
    public var extractions: [MacroExtraction]

    /// A step.
    public init(request: [UInt8], target: HTTPTarget, extractions: [MacroExtraction] = []) {
        self.request = request
        self.target = target
        self.extractions = extractions
    }
}

/// A macro (SES-020).
public struct Macro: Sendable, Hashable, Codable, Identifiable {
    /// Stable id.
    public var id: UUID
    /// Display name.
    public var name: String
    /// Ordered steps.
    public var steps: [MacroStep]

    /// A macro.
    public init(id: UUID = UUID(), name: String, steps: [MacroStep] = []) {
        self.id = id
        self.name = name
        self.steps = steps
    }
}

/// What a macro run produced (SES-022).
public struct MacroResult: Sendable {
    /// Variables captured across the run (and the identity's starting variables).
    public var variables: [String: String]
    /// The cookie jar after the run.
    public var cookies: CookieJar
    /// One line per step, for the tester and the Logger (SES-015/022).
    public var log: [String]
    /// The exchange ids the steps produced (for history linking), in order.
    public var exchangeIDs: [ExchangeID]
    /// A step that failed (network error or a required capture missing), if any.
    public var failure: String?
}

/// Sends a macro's request and returns the response plus the recorded exchange id.
public typealias MacroSender = @Sendable (RawRequest, HTTPTarget) async -> (
    response: RawResponse?, exchangeID: ExchangeID, error: String?
)

/// Replays a macro to refresh session state (SES-020).
public struct MacroRunner: Sendable {
    let send: MacroSender

    /// A runner that sends through `send`.
    public init(send: @escaping MacroSender) { self.send = send }

    /// Run `macro` starting from `variables` and `cookies`; each step expands `${var}`, carries
    /// cookies forward, sends, stores Set-Cookie, and captures its extractions (SES-021).
    public func run(
        _ macro: Macro, variables: [String: String] = [:], cookies: CookieJar = CookieJar(),
        now: Date = Date()
    ) async -> MacroResult {
        var variables = variables
        var jar = cookies
        var log: [String] = []
        var exchangeIDs: [ExchangeID] = []
        for (index, step) in macro.steps.enumerated() {
            let expanded = VariableExpansion.expand(String(decoding: step.request, as: UTF8.self), variables)
            var request = RawRequest(Bytes(Array(expanded.utf8)))
            let path = request.bytes[request.parsed.target].string()
            if let cookie = jar.header(
                host: step.target.host, path: path, scheme: step.target.scheme, now: now)
            {
                request = request.settingHeader("Cookie", to: cookie)
            }
            request = request.updatingContentLength()
            let (response, exchangeID, error) = await send(request, step.target)
            exchangeIDs.append(exchangeID)
            if let error {
                log.append("step \(index + 1): \(step.target.host) — error: \(error)")
                return MacroResult(
                    variables: variables, cookies: jar, log: log, exchangeIDs: exchangeIDs,
                    failure: "step \(index + 1): \(error)")
            }
            guard let response else {
                log.append("step \(index + 1): no response")
                return MacroResult(
                    variables: variables, cookies: jar, log: log, exchangeIDs: exchangeIDs,
                    failure: "step \(index + 1): no response")
            }
            let setCookies = response.headerValues("set-cookie").map { $0.string() }
            jar.store(setCookies: setCookies, from: step.target.host, now: now)
            var captured: [String] = []
            for extraction in step.extractions {
                if let value = Self.capture(
                    extraction.from, response: response, cookies: jar, host: step.target.host)
                {
                    variables[extraction.variable] = value
                    captured.append("\(extraction.variable)=\(value.prefix(16))…")
                } else {
                    log.append("step \(index + 1): couldn't capture \(extraction.variable)")
                    return MacroResult(
                        variables: variables, cookies: jar, log: log, exchangeIDs: exchangeIDs,
                        failure: "step \(index + 1): capture \(extraction.variable) failed")
                }
            }
            log.append(
                "step \(index + 1): \(step.target.host) \(response.parsed.statusCode)"
                    + (captured.isEmpty ? "" : " [\(captured.joined(separator: ", "))]"))
        }
        return MacroResult(
            variables: variables, cookies: jar, log: log, exchangeIDs: exchangeIDs, failure: nil)
    }

    /// Read a capture from a response.
    static func capture(_ capture: MacroCapture, response: RawResponse, cookies: CookieJar, host: String)
        -> String?
    {
        switch capture {
        case .cookie(let name):
            return cookies.cookies.first {
                $0.name == name && CookieJar.domainMatches(host: host.lowercased(), cookie: $0)
            }?
            .value
        case .header(let name):
            return response.headerValue(name)?.string()
        case .regex(let pattern):
            let body = String(decoding: response.bytes.rawBytes[response.parsed.body], as: UTF8.self)
            guard let regex = try? NSRegularExpression(pattern: pattern),
                let match = regex.firstMatch(in: body, range: NSRange(body.startIndex..., in: body))
            else { return nil }
            let groupIndex = match.numberOfRanges > 1 ? 1 : 0
            return Range(match.range(at: groupIndex), in: body).map { String(body[$0]) }
        case .jsonPath(let path):
            let body = Data(response.bytes.rawBytes[response.parsed.body])
            guard let root = try? JSONSerialization.jsonObject(with: body) else { return nil }
            var current: Any? = root
            for key in path.split(separator: ".") {
                current = (current as? [String: Any])?[String(key)]
            }
            switch current {
            case let string as String: return string
            case let number as NSNumber: return number.stringValue
            default: return nil
            }
        }
    }
}
