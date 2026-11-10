// gulp-vulnlab — the M1 protocol fixtures (doc 06 §3 "Basics"). Each route is a pure function from
// the exact request to the exact reply bytes, so F03's framing tests know precisely what is on the
// wire. App-level vulnerable endpoints (auth, XSS, SQLi, …) arrive with their milestones.

import Foundation
import GulpCore
import NIOConcurrencyHelpers

/// The bytes to write back, optionally after a delay.
struct VulnReply: Sendable {
    var bytes: [UInt8]
    var delayMilliseconds = 0
    /// Runs when the reply is written (after the delay): the "act" of a check-then-act route.
    var onSend: (@Sendable () -> Void)? = nil
}

/// `/race/*` (doc 06 §3, M5): a coupon that can be redeemed once — checked on arrival, marked
/// redeemed only when the 200 goes out 50 ms later. Requests that arrive inside that window all
/// pass the check: the race the single-packet group send (F03 HTTP-033/034) is built to expose.
enum Race {
    static let window = 50
    private struct State {
        var redeemed: Set<String> = []
        var successes: [String: Int] = [:]
    }
    private static let state = NIOLockedValueBox(State())

    static func redeem(_ code: String) -> VulnReply {
        let already = state.withLockedValue { $0.redeemed.contains(code) }
        guard !already else {
            let body = Array("coupon \(code) already redeemed\n".utf8)
            return VulnReply(bytes: VulnLab.response(409, body: body))
        }
        let body = Array("coupon \(code) redeemed: 10% off\n".utf8)
        return VulnReply(bytes: VulnLab.response(200, body: body), delayMilliseconds: window) {
            state.withLockedValue { state in
                state.redeemed.insert(code)
                state.successes[code, default: 0] += 1
            }
        }
    }

    static func status(_ code: String) -> VulnReply {
        let count = state.withLockedValue { $0.successes[code] ?? 0 }
        let body = Array("coupon \(code) redemptions=\(count)\n".utf8)
        return VulnReply(bytes: VulnLab.response(200, body: body))
    }

    static func reset(_ code: String) -> VulnReply {
        state.withLockedValue { state in
            state.redeemed.remove(code)
            state.successes[code] = nil
        }
        return VulnReply(bytes: VulnLab.response(200, body: Array("coupon \(code) reset\n".utf8)))
    }
}

enum VulnLab {
    /// Semantic version of the test server.
    static let version = "0.1.0"

    /// "Hello from Gulp VulnLab (gzip)\n", gzip-compressed with mtime 0 (deterministic bytes).
    static let gzipBody: [UInt8] = [
        0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xF3, 0x48, 0xCD, 0xC9, 0xC9, 0x57, 0x48,
        0x2B, 0xCA, 0xCF, 0x55, 0x70, 0x2F, 0xCD, 0x29, 0x50, 0x08, 0x2B, 0xCD, 0xC9, 0xF3, 0x49, 0x4C, 0x52,
        0xD0, 0x48, 0xAF, 0xCA, 0x2C, 0xD0, 0xE4, 0x02, 0x00, 0x03, 0x30, 0xE4, 0xED, 0x1F, 0x00, 0x00, 0x00,
    ]

    /// A JSON response.
    static func json(_ code: Int, _ text: String) -> VulnReply {
        VulnReply(bytes: response(code, body: Array(text.utf8), type: "application/json"))
    }

    /// `/openapi.json`: the `/api/*` routes (F23 ADV-050, the M6b DoD).
    static let openAPI = """
        {
          "openapi": "3.0.3",
          "info": {"title": "Gulp VulnLab API", "version": "1.0.0"},
          "servers": [{"url": "/"}],
          "components": {
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
            "schemas": {
              "NewOrder": {
                "type": "object", "required": ["item", "quantity"],
                "properties": {
                  "item": {"type": "string", "example": "coffee"},
                  "quantity": {"type": "integer", "minimum": 1},
                  "note": {"type": "string"},
                  "deliverAt": {"type": "string", "format": "date-time"},
                  "express": {"type": "boolean"}
                }
              }
            }
          },
          "paths": {
            "/api/items": {
              "get": {
                "operationId": "listItems", "summary": "List items",
                "parameters": [
                  {"name": "q", "in": "query", "schema": {"type": "string"}},
                  {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "default": 3}}
                ],
                "responses": {"200": {"description": "items"}}
              }
            },
            "/api/orders": {
              "post": {
                "operationId": "createOrder", "summary": "Create an order",
                "requestBody": {
                  "required": true,
                  "content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewOrder"}}}
                },
                "responses": {"201": {"description": "created"}}
              }
            },
            "/api/orders/{id}": {
              "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer", "example": 1}}],
              "get": {"operationId": "getOrder", "summary": "Get an order", "responses": {"200": {"description": "order"}}}
            },
            "/api/me": {
              "get": {
                "operationId": "me", "summary": "The current user", "security": [{"bearer": []}],
                "responses": {"200": {"description": "user"}, "401": {"description": "no token"}}
              }
            }
          }
        }

        """

    /// The `/` page.
    static let homePage = """
        <!doctype html>
        <html><head><title>Gulp VulnLab</title><script src="/static/app.js"></script></head>
        <body><h1>Gulp VulnLab</h1><p>A deliberately vulnerable app. Local use only.</p>
        <ul>
        <li><a href="/echo">Echo</a></li>
        <li><a href="/redirect?to=/echo">Redirect</a></li>
        <li><a href="/login">Login</a></li>
        <li><a href="/api/orders/1">Order 1</a> <a href="/api/orders/2">Order 2</a></li>
        <li><a href="/xss/html?q=hello">Reflected XSS</a></li>
        <li><a href="/file?name=readme.txt">Files</a></li>
        <li><a href="/go?next=/">Go</a></li>
        <li><a href="/race/status?code=GULP10">Coupon status</a></li>
        </ul>
        <form action="/guestbook" method="post"><input name="message"></form>
        </body></html>

        """

    /// Route one request.
    static func respond(to request: RawRequest) -> VulnReply {
        let requestTarget = request.bytes[request.parsed.target].string()
        let path = String(requestTarget.split(separator: "?", maxSplits: 1).first ?? "")
        let query = queryItems(requestTarget)
        switch path {
        case "/":
            // The home page: links to the labs, so a proxied visit gives the site map inferred nodes
            // (F04 TGT-003). `/admin` is deliberately not linked (content discovery finds it, M8).
            return VulnReply(
                bytes: response(200, body: Array(homePage.utf8), type: "text/html; charset=utf-8"))
        case "/echo":
            // Reflects the exact request bytes as a readable response.
            return VulnReply(bytes: response(200, body: request.bytes.rawBytes))
        case "/redirect":
            let location = query["to"] ?? "/echo"
            return VulnReply(bytes: response(302, body: [], headers: ["Location: \(location)"]))
        case "/chunked":
            let body = "7\r\nchunked\r\n1\r\n \r\n8\r\nresponse\r\n0\r\nX-Trailer: done\r\n\r\n"
            let head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
            return VulnReply(bytes: Array((head + body).utf8))
        case "/gzip":
            let headers = ["Content-Encoding: gzip"]
            return VulnReply(bytes: response(200, body: gzipBody, type: "text/plain", headers: headers))
        case "/race/redeem": return Race.redeem(query["code"] ?? "GULP10")
        case "/race/status": return Race.status(query["code"] ?? "GULP10")
        case "/race/reset": return Race.reset(query["code"] ?? "GULP10")
        case "/slow":
            let delay = min(max(Int(query["ms"] ?? "") ?? 1_000, 0), 60_000)
            let body = Array("slow \(delay) ms\n".utf8)
            return VulnReply(bytes: response(200, body: body), delayMilliseconds: delay)
        case "/large":
            let megabytes = min(max(Int(query["mb"] ?? "") ?? 1, 1), 100)
            let block = Array("0123456789abcdef".utf8)
            let body = [UInt8]((0..<(megabytes * 65_536)).flatMap { _ in block })
            return VulnReply(bytes: response(200, body: body, type: "application/octet-stream"))
        case "/openapi.json":
            return VulnReply(bytes: response(200, body: Array(openAPI.utf8), type: "application/json"))
        case "/api/items":
            let limit = min(max(Int(query["limit"] ?? "") ?? 3, 0), 20)
            let q = query["q"] ?? ""
            let items = (1...max(limit, 1)).prefix(limit).map {
                #"{"id":\#($0),"name":"item \#($0)\#(q.isEmpty ? "" : " " + q)"}"#
            }
            return json(200, "[" + items.joined(separator: ",") + "]")
        case "/api/orders":
            // POST creates an order (echoes the body back with an id).
            let method = request.bytes[request.parsed.method].string()
            guard method == "POST" else { return json(405, #"{"error":"use POST"}"#) }
            let body = request.bytes[request.parsed.body].string()
            return json(201, #"{"id":3,"order":\#(body.isEmpty ? "null" : body)}"#)
        case "/login": return AuthLab.login(request)
        case "/account": return AuthLab.account(request)
        case "/admin", "/admin/": return AuthLab.admin(request)
        case "/api/me", "/safe/api/me":
            return JWTLab.me(request.headerValue("authorization")?.string(), safe: path.hasPrefix("/safe"))
        case "/api/login":
            return JWTLab.login(user: query["user"] ?? "alice", alg: (query["alg"] ?? "RS256").uppercased())
        case "/api/key.pem":
            return VulnReply(
                bytes: response(200, body: Array(JWTLab.publicPEM.utf8), type: "application/x-pem-file"))
        case "/.well-known/jwks.json":
            return JWTLab.jwks()
        case "/continue":
            let interim = Array("HTTP/1.1 100 Continue\r\n\r\n".utf8)
            return VulnReply(bytes: interim + response(200, body: Array("continued\n".utf8)))
        default:
            if let found = AuthLab.discovery(path) { return found }
            if let planted = PassiveLab.respond(path, query, request) { return planted }
            if path.hasPrefix("/xss/") || path.hasPrefix("/safe/xss/"), let page = XSSLab.respond(path, query)
            {
                return page
            }
            if path.hasPrefix("/api/orders/"), let id = Int(path.dropFirst("/api/orders/".count)) {
                // IDOR (doc 06 §3): any order by id, no owner check.
                guard (1...2).contains(id) else { return json(404, #"{"error":"no such order"}"#) }
                return json(
                    200, #"{"id":\#(id),"owner":"\#(id == 1 ? "alice" : "bob")","total":\#(id * 10)}"#)
            }
            if path.hasPrefix("/status/") {
                return status(Int(path.dropFirst("/status/".count)))
            }
            return VulnReply(bytes: response(404, body: Array("not found\n".utf8)))
        }
    }

    /// `/status/{code}`: that status; 1xx is followed by a final 200; 204/304 carry no body.
    static func status(_ code: Int?) -> VulnReply {
        guard let code, (100...599).contains(code) else {
            return VulnReply(bytes: response(400, body: Array("bad status\n".utf8)))
        }
        if code < 200 {
            let interim = Array("HTTP/1.1 \(code) \(reason(code))\r\n\r\n".utf8)
            return VulnReply(bytes: interim + response(200, body: Array("after \(code)\n".utf8)))
        }
        if code == 204 || code == 304 {
            return VulnReply(bytes: Array("HTTP/1.1 \(code) \(reason(code))\r\n\r\n".utf8))
        }
        return VulnReply(bytes: response(code, body: Array("status \(code)\n".utf8)))
    }

    /// The security baseline every response carries (doc 06 §3, "determinism prerequisites"), so a
    /// passive issue fires only where a route deliberately leaves something out (`omit`).
    static let baseline = [
        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; "
            + "frame-ancestors 'self'",
        "X-Content-Type-Options: nosniff", "X-Frame-Options: SAMEORIGIN",
        "Referrer-Policy: strict-origin-when-cross-origin",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "Strict-Transport-Security: max-age=31536000", "Cache-Control: no-store",
    ]

    /// A complete response with a correct Content-Length and the security baseline. `headers` with
    /// the same name as a baseline header replace it; `omit` drops baseline headers (lowercased names,
    /// or `content-type`).
    static func response(
        _ code: Int, body: [UInt8], type: String = "text/plain; charset=utf-8", headers: [String] = [],
        omit: Set<String> = []
    ) -> [UInt8] {
        // No version in the banner: a version is a planted issue (`/headers/version`), not the default.
        var head = "HTTP/1.1 \(code) \(reason(code))\r\n"
        func name(_ header: String) -> String {
            header.split(separator: ":").first.map { $0.lowercased() } ?? ""
        }
        let given = Set(headers.map(name))
        if !given.contains("server") { head += "Server: gulp-vulnlab\r\n" }
        for header in baseline where !omit.contains(name(header)) && !given.contains(name(header)) {
            head += "\(header)\r\n"
        }
        if !body.isEmpty, !omit.contains("content-type"), !given.contains("content-type") {
            head += "Content-Type: \(type)\r\n"
        }
        for header in headers { head += "\(header)\r\n" }
        head += "Content-Length: \(body.count)\r\n\r\n"
        return Array(head.utf8) + body
    }

    static func reason(_ code: Int) -> String {
        switch code {
        case 100: "Continue"
        case 103: "Early Hints"
        case 200: "OK"
        case 204: "No Content"
        case 302: "Found"
        case 403: "Forbidden"
        case 304: "Not Modified"
        case 400: "Bad Request"
        case 404: "Not Found"
        case 500: "Internal Server Error"
        default: "Status"
        }
    }

    /// Decoded query parameters (last value wins).
    static func queryItems(_ requestTarget: String) -> [String: String] {
        guard let q = requestTarget.split(separator: "?", maxSplits: 1).dropFirst().first else { return [:] }
        var items: [String: String] = [:]
        for pair in q.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            let key = parts[0].removingPercentEncoding ?? parts[0]
            let value = parts.count > 1 ? (parts[1].removingPercentEncoding ?? parts[1]) : ""
            items[key] = value
        }
        return items
    }
}
