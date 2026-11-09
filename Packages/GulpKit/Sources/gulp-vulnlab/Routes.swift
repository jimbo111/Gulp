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

    /// Route one request.
    static func respond(to request: RawRequest) -> VulnReply {
        let requestTarget = request.bytes[request.parsed.target].string()
        let path = String(requestTarget.split(separator: "?", maxSplits: 1).first ?? "")
        let query = queryItems(requestTarget)
        switch path {
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
        case "/continue":
            let interim = Array("HTTP/1.1 100 Continue\r\n\r\n".utf8)
            return VulnReply(bytes: interim + response(200, body: Array("continued\n".utf8)))
        default:
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

    /// A complete response with a correct Content-Length.
    static func response(
        _ code: Int, body: [UInt8], type: String = "text/plain; charset=utf-8", headers: [String] = []
    ) -> [UInt8] {
        var head = "HTTP/1.1 \(code) \(reason(code))\r\nServer: gulp-vulnlab/\(version)\r\n"
        if !body.isEmpty { head += "Content-Type: \(type)\r\n" }
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
