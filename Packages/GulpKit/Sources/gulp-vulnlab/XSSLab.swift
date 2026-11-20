// gulp-vulnlab — reflected XSS (doc 06 §3): `q` is reflected into four contexts — HTML body, a
// quoted attribute, a JavaScript string and an href — unencoded under `/xss/…`, and encoded for its
// context under `/safe/xss/…`. GulpQL's `reflected("q")` (F05 acceptance 2) and the Scanner's
// reflection checks (M11) use them.

import Foundation

enum XSSLab {
    /// The page for `path` (`/xss/html`, `/safe/xss/attr`…), or nil if it isn't an XSS lab path.
    static func respond(_ path: String, _ query: [String: String]) -> VulnReply? {
        let safe = SafeTwin.isSafe(path)
        let context = path.split(separator: "/").last.map(String.init) ?? ""
        let q = query["q"] ?? ""
        let body: String
        switch context {
        case "html":
            body = "<p>You searched for: \(safe ? html(q) : q)</p>"
        case "attr":
            body = "<input name=\"q\" value=\"\(safe ? html(q) : q)\">"
        case "js":
            body = "<script>var search = '\(safe ? js(q) : q)';</script>"
        case "url":
            let href = safe ? (q.hasPrefix("http://") || q.hasPrefix("https://") ? html(q) : "#") : q
            body = "<a href=\"\(href)\">Continue</a>"
        default:
            return nil
        }
        let page = "<!doctype html><html><head><title>Search</title></head><body>\(body)</body></html>"
        return VulnReply(
            bytes: VulnLab.response(200, body: Array(page.utf8), type: "text/html; charset=utf-8"))
    }

    /// HTML text/attribute encoding.
    static func html(_ text: String) -> String {
        var out = ""
        for c in text {
            switch c {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&#39;"
            default: out.append(c)
            }
        }
        return out
    }

    /// JavaScript string encoding (also safe inside a <script> block).
    static func js(_ text: String) -> String {
        text.unicodeScalars.map { scalar in
            let value = scalar.value
            let isPlain =
                (value >= 0x30 && value <= 0x39) || (value >= 0x41 && value <= 0x5A)
                || (value >= 0x61 && value <= 0x7A) || scalar == " " || scalar == "." || scalar == "-"
            return isPlain ? String(scalar) : String(format: "\\u%04x", value & 0xFFFF)
        }.joined()
    }
}
