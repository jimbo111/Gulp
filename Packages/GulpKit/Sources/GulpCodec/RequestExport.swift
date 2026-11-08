// GulpCodec — "Copy as" (F17 ETL-008, moved to M4a; doc 05 UI-040): one serializer that turns any
// request into a runnable snippet. Every table and editor uses it through the Send-to menu.
//
// Fidelity notes: cURL and Python get the body as exact bytes (ANSI-C `$'…'` quoting / a `b"…"`
// literal), so binary and CRLF survive; fetch, PowerShell and Go get it as a string, which is exact
// for UTF-8 text. Headers the client library computes (Content-Length, Host when it matches the URL,
// Connection) are left out so the snippet doesn't fight the library.

import GulpCore

/// A "Copy as" target language.
public enum RequestExportFormat: String, Sendable, CaseIterable, Codable {
    /// `curl` command line (bash/zsh).
    case curl = "cURL"
    /// PowerShell `Invoke-WebRequest`.
    case powershell = "PowerShell"
    /// JavaScript `fetch`.
    case fetch = "fetch"
    /// Python `requests`.
    case python = "Python requests"
    /// Go `net/http`.
    case go = "Go"
}

/// Serializes requests as runnable code.
public enum RequestExport {
    /// The request as a `format` snippet that reproduces it against `target`.
    public static func export(
        _ request: RawRequest, target: HTTPTarget, as format: RequestExportFormat
    ) -> String {
        let parts = Parts(request, target: target)
        switch format {
        case .curl: return curl(parts)
        case .powershell: return powershell(parts)
        case .fetch: return fetch(parts)
        case .python: return python(parts)
        case .go: return go(parts)
        }
    }

    struct Parts {
        let method: String
        let url: String
        let headers: [(name: String, value: String)]
        let body: [UInt8]
        let http2: Bool

        init(_ request: RawRequest, target: HTTPTarget) {
            let bytes = request.bytes
            let parsed = request.parsed
            method = bytes[parsed.method].string()
            http2 = bytes[parsed.version].string() == "HTTP/2"
            var path = bytes[parsed.target].string()
            if path.hasPrefix("http://") || path.hasPrefix("https://") {
                url = path  // absolute-form already names the target
            } else {
                if !path.hasPrefix("/") && path != "*" { path = "/" + path }
                let defaultPort = target.scheme == .https ? 443 : 80
                let port = target.port == defaultPort ? "" : ":\(target.port)"
                url = "\(target.scheme.rawValue)://\(target.host)\(port)\(path)"
            }
            let standardPort = target.port == (target.scheme == .https ? 443 : 80)
            let authority = standardPort ? target.host : "\(target.host):\(target.port)"
            let skipped: Set<String> = ["content-length", "connection", "transfer-encoding", "keep-alive"]
            var headers: [(String, String)] = []
            for field in parsed.headers {
                let name = bytes[field.name].string()
                let value = bytes[field.value].string()
                let lower = name.lowercased()
                if skipped.contains(lower) { continue }
                if lower == "host", value.lowercased() == authority.lowercased() { continue }
                headers.append((name, value))
            }
            self.headers = headers
            let all = bytes.rawBytes
            body = parsed.headerBlockEnd < all.count ? Array(all[parsed.headerBlockEnd...]) : []
        }
    }

    // MARK: formats

    static func curl(_ p: Parts) -> String {
        var lines = ["curl --path-as-is" + (p.http2 ? " --http2" : "")]
        if p.method == "HEAD" {
            lines.append("  --head")
        } else if p.method != "GET" || !p.body.isEmpty {
            lines.append("  -X \(shellQuote(p.method))")
        }
        lines.append("  \(shellQuote(p.url))")
        for header in p.headers { lines.append("  -H \(shellQuote("\(header.name): \(header.value)"))") }
        if !p.body.isEmpty { lines.append("  --data-binary \(ansiCQuote(p.body))") }
        return lines.joined(separator: " \\\n")
    }

    static func powershell(_ p: Parts) -> String {
        var out = "$headers = @{\n"
        var contentType: String?
        for header in p.headers {
            if header.name.lowercased() == "content-type" {
                contentType = header.value
                continue
            }
            out += "    \(psQuote(header.name)) = \(psQuote(header.value))\n"
        }
        out += "}\n"
        out += "Invoke-WebRequest -Uri \(psQuote(p.url)) -Method \(psQuote(p.method)) -Headers $headers"
        if let contentType { out += " -ContentType \(psQuote(contentType))" }
        if !p.body.isEmpty {
            out += " -Body \(psQuote(String(decoding: p.body, as: UTF8.self)))"
        }
        return out
    }

    static func fetch(_ p: Parts) -> String {
        var options = ["  method: \(jsonQuote(p.method))"]
        if !p.headers.isEmpty {
            let fields = p.headers.map { "    \(jsonQuote($0.name)): \(jsonQuote($0.value))" }
            options.append("  headers: {\n" + fields.joined(separator: ",\n") + "\n  }")
        }
        if !p.body.isEmpty {
            options.append("  body: \(jsonQuote(String(decoding: p.body, as: UTF8.self)))")
        }
        return "await fetch(\(jsonQuote(p.url)), {\n" + options.joined(separator: ",\n") + "\n});"
    }

    static func python(_ p: Parts) -> String {
        var out = "import requests\n\n"
        out += "headers = {\n"
        for header in p.headers { out += "    \(pyQuote(header.name)): \(pyQuote(header.value)),\n" }
        out += "}\n"
        out += "response = requests.request(\n"
        out += "    \(pyQuote(p.method)), \(pyQuote(p.url)), headers=headers"
        if !p.body.isEmpty { out += ", data=\(pyBytes(p.body))" }
        out += ",\n)\nprint(response.status_code)\nprint(response.text)"
        return out
    }

    static func go(_ p: Parts) -> String {
        var out = "package main\n\nimport (\n"
        out += "\t\"fmt\"\n\t\"io\"\n\t\"net/http\"\n\t\"strings\"\n)\n\n"
        out += "func main() {\n"
        let text = jsonQuote(String(decoding: p.body, as: UTF8.self))
        let body = p.body.isEmpty ? "nil" : "strings.NewReader(\(text))"
        out += "\treq, err := http.NewRequest(\(jsonQuote(p.method)), \(jsonQuote(p.url)), \(body))\n"
        out += "\tif err != nil {\n\t\tpanic(err)\n\t}\n"
        for header in p.headers {
            if header.name.lowercased() == "host" {
                out += "\treq.Host = \(jsonQuote(header.value))\n"
            } else {
                out += "\treq.Header.Set(\(jsonQuote(header.name)), \(jsonQuote(header.value)))\n"
            }
        }
        out += "\tresp, err := http.DefaultClient.Do(req)\n\tif err != nil {\n\t\tpanic(err)\n\t}\n"
        out += "\tdefer resp.Body.Close()\n\tdata, _ := io.ReadAll(resp.Body)\n"
        out += "\tfmt.Println(resp.Status)\n\tfmt.Println(string(data))\n}"
        return out
    }

    // MARK: quoting

    /// A single-quoted shell word (`'` becomes `'\''`).
    static func shellQuote(_ text: String) -> String {
        "'" + text.replacingAll("'", with: "'\\''") + "'"
    }

    /// A bash/zsh ANSI-C quoted string `$'…'` holding exactly `bytes`.
    static func ansiCQuote(_ bytes: [UInt8]) -> String {
        var out = "$'"
        for byte in bytes {
            switch byte {
            case 0x5C: out += "\\\\"
            case 0x27: out += "\\'"
            case 0x0A: out += "\\n"
            case 0x0D: out += "\\r"
            case 0x09: out += "\\t"
            case 0x20...0x7E: out.append(Character(UnicodeScalar(byte)))
            default: out += "\\x" + hex(byte)
            }
        }
        return out + "'"
    }

    /// A JavaScript/Go/JSON double-quoted string.
    static func jsonQuote(_ text: String) -> String {
        var out = "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    out += "\\u00" + hex(UInt8(scalar.value))
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }

    /// A Python string literal.
    static func pyQuote(_ text: String) -> String { jsonQuote(text) }

    /// A Python bytes literal holding exactly `bytes`.
    static func pyBytes(_ bytes: [UInt8]) -> String {
        var out = "b\""
        for byte in bytes {
            switch byte {
            case 0x5C: out += "\\\\"
            case 0x22: out += "\\\""
            case 0x0A: out += "\\n"
            case 0x0D: out += "\\r"
            case 0x09: out += "\\t"
            case 0x20...0x7E: out.append(Character(UnicodeScalar(byte)))
            default: out += "\\x" + hex(byte)
            }
        }
        return out + "\""
    }

    /// A PowerShell single-quoted string (`'` doubled).
    static func psQuote(_ text: String) -> String {
        "'" + text.replacingAll("'", with: "''") + "'"
    }

    static func hex(_ byte: UInt8) -> String {
        let digits = Array("0123456789abcdef")
        return String([digits[Int(byte >> 4)], digits[Int(byte & 0xF)]])
    }
}

extension String {
    /// Replace every occurrence of `target` (no Foundation).
    func replacingAll(_ target: String, with replacement: String) -> String {
        guard !target.isEmpty else { return self }
        var result = ""
        var rest = self[...]
        while let range = rest.firstRange(of: target) {
            result += rest[..<range.lowerBound]
            result += replacement
            rest = rest[range.upperBound...]
        }
        return result + rest
    }
}
