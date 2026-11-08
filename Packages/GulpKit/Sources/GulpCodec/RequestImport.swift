// GulpCodec — "Paste to request" (F06 REP-017): turn a cURL command line, a `fetch(url, {...})`
// call (a browser's "Copy as fetch" or Node), or a raw HTTP request into raw request bytes and a
// target. The inverse of `RequestExport`. Anything that could not be mapped is reported, not dropped
// silently.
//
// The request is built in the order given (headers as written, then the body); `Host` comes first
// unless the paste sets it. cURL's own defaults (User-Agent: curl/…, Accept: */*) are not added.

import GulpCore

/// A pasted request, parsed.
public struct ImportedRequest: Sendable, Equatable {
    /// The request bytes (HTTP/1.1 form).
    public var request: RawRequest
    /// Where to send it.
    public var target: HTTPTarget
    /// The paste asked for HTTP/2 (`--http2`, `--http2-prior-knowledge`).
    public var prefersHTTP2: Bool
    /// The paste turned certificate checks off (`-k`).
    public var insecure: Bool
    /// The paste asked to follow redirects (`-L`).
    public var followRedirects: Bool
    /// What the paste said that has no equivalent here (flags, options), for the user to review.
    public var ignored: [String]
}

/// Why a paste could not be turned into a request.
public enum RequestImportError: Error, Sendable, Equatable {
    /// Unbalanced quotes or a dangling escape.
    case unterminatedQuote
    /// No URL was found.
    case missingURL
    /// The URL is not an absolute http(s) URL.
    case invalidURL(String)
    /// Neither cURL, fetch nor a raw HTTP request.
    case unrecognized
}

/// Parses pasted requests (REP-017).
public enum RequestImport {
    /// Parse `text`, detecting the format: `curl …`, `fetch(…)`, or a raw HTTP request. For a raw
    /// request, `target` overrides the one derived from its `Host` header.
    public static func parse(_ text: String, target: HTTPTarget? = nil) throws -> ImportedRequest {
        let trimmed = text.drop { $0.isWhitespace }
        if trimmed.hasPrefix("curl ") || trimmed.hasPrefix("curl\t") || trimmed.hasPrefix("curl.exe ") {
            return try curl(String(trimmed))
        }
        if trimmed.hasPrefix("fetch(") || trimmed.hasPrefix("await fetch(") {
            return try fetch(String(trimmed))
        }
        if let raw = raw(String(trimmed), target: target) { return raw }
        throw RequestImportError.unrecognized
    }

    // MARK: cURL

    /// Flags that take a value and are mapped elsewhere or deliberately ignored.
    static let valueFlags: Set<String> = [
        "-o", "--output", "-m", "--max-time", "--connect-timeout", "-x", "--proxy", "-w", "--write-out",
        "--retry", "--cacert", "--cert", "--key", "-E", "--resolve", "--interface", "-T", "--upload-file",
        "-F", "--form", "--limit-rate", "--max-redirs", "-c", "--cookie-jar", "-D", "--dump-header",
        "--proxy-user", "-U", "--ciphers", "--tls-max",
    ]
    /// Short flags that take a value (so `-XPOST` means `-X POST`).
    static let shortValueFlags: Set<Character> = [
        "X", "H", "d", "b", "u", "A", "e", "o", "m", "x", "w", "F", "T", "c", "D", "E", "U",
    ]

    /// Parse a cURL command line (bash quoting; Chrome's and Firefox's "Copy as cURL").
    public static func curl(_ text: String) throws -> ImportedRequest {
        var words = try ShellWords.split(text)
        guard !words.isEmpty else { throw RequestImportError.missingURL }
        words.removeFirst()  // curl
        var method: String?
        var url: String?
        var headers: [(String, String)] = []
        var data: [String] = []
        var dataIsForm = false
        var get = false
        var head = false
        var http2 = false
        var insecure = false
        var follow = false
        var compressed = false
        var ignored: [String] = []

        var index = 0
        func value(_ flag: String) -> String? {
            index += 1
            guard index < words.count else {
                ignored.append(flag)
                return nil
            }
            return words[index]
        }
        while index < words.count {
            var word = words[index]
            var inline: String?
            if word.hasPrefix("--"), let equals = word.firstIndex(of: "=") {
                inline = String(word[word.index(after: equals)...])
                word = String(word[..<equals])
            } else if word.hasPrefix("-"), !word.hasPrefix("--"), word.count > 2 {
                let letters = Array(word.dropFirst())
                if shortValueFlags.contains(letters[0]) {
                    inline = String(letters.dropFirst())
                    word = "-" + String(letters[0])
                } else {
                    // Bundled boolean flags such as -sSLk: expand them in place.
                    words.replaceSubrange(index...index, with: letters.map { "-" + String($0) })
                    continue
                }
            }
            func take() -> String? { inline ?? value(word) }
            switch word {
            case "-X", "--request": method = take()
            case "-H", "--header":
                if let header = take() {
                    if let colon = header.firstIndex(of: ":") {
                        let name = String(header[..<colon])
                        let rest = header[header.index(after: colon)...].drop { $0 == " " || $0 == "\t" }
                        // `-H 'Name:'` is curl's way to remove a default header: nothing to add.
                        if !rest.isEmpty { headers.append((name, String(rest))) }
                    } else {
                        ignored.append("-H \(header)")
                    }
                }
            case "-d", "--data", "--data-raw", "--data-ascii", "--data-binary":
                if let piece = take() {
                    if piece.hasPrefix("@"), word != "--data-raw" {
                        ignored.append("\(word) \(piece) (file contents are not read)")
                    } else {
                        let exact = word == "--data-binary" || word == "--data-raw"
                        data.append(exact ? piece : stripNewlines(piece))
                        dataIsForm = true
                    }
                }
            case "--data-urlencode":
                if let piece = take() {
                    data.append(urlencodeDataPiece(piece))
                    dataIsForm = true
                }
            case "-b", "--cookie":
                if let cookie = take() {
                    if cookie.contains("=") {
                        headers.append(("Cookie", cookie))
                    } else {
                        ignored.append("\(word) \(cookie) (cookie files are not read)")
                    }
                }
            case "-u", "--user":
                if let user = take() {
                    headers.append(("Authorization", "Basic " + base64(Array(user.utf8))))
                }
            case "-A", "--user-agent": if let agent = take() { headers.append(("User-Agent", agent)) }
            case "-e", "--referer": if let referer = take() { headers.append(("Referer", referer)) }
            case "--url": url = take()
            case "-G", "--get": get = true
            case "-I", "--head": head = true
            case "--http2", "--http2-prior-knowledge": http2 = true
            case "--http1.1", "--http1.0", "-0": break
            case "-k", "--insecure": insecure = true
            case "-L", "--location": follow = true
            case "--compressed": compressed = true
            case "-s", "--silent", "-S", "--show-error", "-v", "--verbose", "-i", "--include", "-N",
                "--no-buffer", "-#", "--progress-bar", "-f", "--fail", "--path-as-is":
                break  // output options (and --path-as-is: Gulp always sends the path as given)
            default:
                if word.hasPrefix("-") && word.count > 1 {
                    if valueFlags.contains(word) {
                        let given = take().map { " \($0)" } ?? ""
                        ignored.append(word + given)
                    } else {
                        ignored.append(word + (inline.map { "=\($0)" } ?? ""))
                    }
                } else if url == nil {
                    url = word
                } else {
                    ignored.append(word)
                }
            }
            index += 1
        }
        guard var url else { throw RequestImportError.missingURL }
        var body: [UInt8] = []
        if !data.isEmpty {
            let joined = data.joined(separator: "&")
            if get {
                url += (url.contains("?") ? "&" : "?") + joined
            } else {
                body = Array(joined.utf8)
                if dataIsForm, !headers.contains(where: { $0.0.lowercased() == "content-type" }) {
                    headers.append(("Content-Type", "application/x-www-form-urlencoded"))
                }
            }
        }
        if compressed, !headers.contains(where: { $0.0.lowercased() == "accept-encoding" }) {
            headers.append(("Accept-Encoding", "gzip, deflate, br"))
        }
        let resolvedMethod = method ?? (head ? "HEAD" : (body.isEmpty ? "GET" : "POST"))
        var imported = try build(method: resolvedMethod, url: url, headers: headers, body: body)
        imported.prefersHTTP2 = http2
        imported.insecure = insecure
        imported.followRedirects = follow
        imported.ignored = ignored
        return imported
    }

    /// curl's `-d`/`--data` (not `--data-binary`) drops CR and LF from the value.
    static func stripNewlines(_ text: String) -> String {
        String(text.unicodeScalars.filter { $0 != "\r" && $0 != "\n" }.map(Character.init))
    }

    /// `--data-urlencode name=value` encodes the value (or the whole piece without `=`).
    static func urlencodeDataPiece(_ piece: String) -> String {
        if let equals = piece.firstIndex(of: "=") {
            let name = piece[..<equals]
            return name + "=" + percentEncode(String(piece[piece.index(after: equals)...]))
        }
        return percentEncode(piece)
    }

    static func percentEncode(_ text: String) -> String {
        var out = ""
        for byte in text.utf8 {
            switch byte {
            case 0x30...0x39, 0x41...0x5A, 0x61...0x7A, 0x2D, 0x2E, 0x5F, 0x7E:
                out.append(Character(Unicode.Scalar(byte)))
            default:
                out += "%" + String(byte, radix: 16, uppercase: true).leftPadded(to: 2)
            }
        }
        return out
    }

    // MARK: fetch

    /// Parse `fetch(url, { method, headers, body, … })` (a browser's "Copy as fetch", Node).
    public static func fetch(_ text: String) throws -> ImportedRequest {
        guard let open = text.firstIndex(of: "(") else { throw RequestImportError.unrecognized }
        var reader = JSLiteralReader(String(text[text.index(after: open)...]))
        guard case .string(let url)? = try reader.value() else { throw RequestImportError.missingURL }
        var options: [(String, JSValue)] = []
        if reader.consume(","), case .object(let object)? = try reader.value() { options = object }
        var method = "GET"
        var headers: [(String, String)] = []
        var body: [UInt8] = []
        var ignored: [String] = []
        for (key, value) in options {
            switch (key, value) {
            case ("method", .string(let m)): method = m.uppercased()
            case ("headers", .object(let fields)):
                for (name, field) in fields {
                    if case .string(let text) = field { headers.append((name, text)) }
                }
            case ("body", .string(let text)): body = Array(text.utf8)
            case ("body", .null): break
            case ("referrer", .string(let referrer)):
                if !headers.contains(where: { $0.0.lowercased() == "referer" }) {
                    headers.append(("Referer", referrer))
                }
            case ("mode", _), ("credentials", _), ("referrerPolicy", _):
                break  // browser fetch semantics; cookies come from the headers when present
            default:
                ignored.append(key)
            }
        }
        var imported = try build(method: method, url: url, headers: headers, body: body)
        imported.ignored = ignored
        return imported
    }

    // MARK: raw

    /// A raw HTTP request, taken as is. The target comes from an absolute-form request line or the
    /// `Host` header (port 443 → https), unless `target` is given.
    static func raw(_ text: String, target: HTTPTarget?) -> ImportedRequest? {
        let request = RawRequest(Bytes(Array(text.utf8)))
        let method = request.bytes[request.parsed.method].string()
        let version = request.bytes[request.parsed.version].string()
        guard !method.isEmpty, method.allSatisfy({ $0.isLetter }), version.hasPrefix("HTTP/") else {
            return nil
        }
        if let target {
            return ImportedRequest(
                request: request, target: target, prefersHTTP2: false, insecure: false,
                followRedirects: false, ignored: [])
        }
        let requestTarget = request.bytes[request.parsed.target].string()
        var resolved = HTTPTarget(url: requestTarget)
        if resolved == nil, let host = request.headerValue("host")?.string() {
            let port = host.split(separator: ":").last.flatMap { Int($0) }
            resolved = HTTPTarget(url: (port == 443 ? "https://" : "http://") + host)
        }
        guard let resolved else { return nil }
        return ImportedRequest(
            request: request, target: resolved, prefersHTTP2: version == "HTTP/2", insecure: false,
            followRedirects: false, ignored: [])
    }

    // MARK: building

    static func build(
        method: String, url: String, headers: [(String, String)], body: [UInt8]
    ) throws -> ImportedRequest {
        guard let target = HTTPTarget(url: url) else { throw RequestImportError.invalidURL(url) }
        var path = "/"
        if let schemeEnd = url.range(of: "://") {
            let rest = url[schemeEnd.upperBound...]
            if let start = rest.firstIndex(where: { $0 == "/" || $0 == "?" }) {
                path = String(rest[start...])
                if path.hasPrefix("?") { path = "/" + path }
            }
        }
        if let hash = path.firstIndex(of: "#") { path = String(path[..<hash]) }  // fragments aren't sent
        var head = "\(method) \(path) HTTP/1.1\r\n"
        if !headers.contains(where: { $0.0.lowercased() == "host" }) {
            let standard = target.port == (target.scheme == .https ? 443 : 80)
            head += "Host: \(standard ? target.host : "\(target.host):\(target.port)")\r\n"
        }
        for (name, value) in headers where name.lowercased() != "content-length" {
            head += "\(name): \(value)\r\n"
        }
        if !body.isEmpty || ["POST", "PUT", "PATCH"].contains(method) {
            head += "Content-Length: \(body.count)\r\n"
        }
        head += "\r\n"
        return ImportedRequest(
            request: RawRequest(Bytes(Array(head.utf8) + body)), target: target, prefersHTTP2: false,
            insecure: false, followRedirects: false, ignored: [])
    }

    static func base64(_ bytes: [UInt8]) -> String {
        let table = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        var out = ""
        var index = 0
        while index < bytes.count {
            let b0 = Int(bytes[index])
            let b1 = index + 1 < bytes.count ? Int(bytes[index + 1]) : 0
            let b2 = index + 2 < bytes.count ? Int(bytes[index + 2]) : 0
            out.append(table[b0 >> 2])
            out.append(table[((b0 & 3) << 4) | (b1 >> 4)])
            out.append(index + 1 < bytes.count ? table[((b1 & 15) << 2) | (b2 >> 6)] : "=")
            out.append(index + 2 < bytes.count ? table[b2 & 63] : "=")
            index += 3
        }
        return out
    }
}

extension String {
    fileprivate func leftPadded(to width: Int) -> String {
        count >= width ? self : String(repeating: "0", count: width - count) + self
    }
}

// MARK: - Shell words

/// Splits a command line like bash does for the quoting forms copy-as-cURL produces: '…', "…",
/// $'…' (ANSI-C escapes), backslash escapes and backslash-newline continuations. Windows `^`
/// continuations (cmd) are accepted at line ends.
enum ShellWords {
    static func split(_ text: String) throws -> [String] {
        var words: [String] = []
        var current = ""
        var inWord = false
        var chars = Array(text)
        // cmd.exe "Copy as cURL (cmd)" ends lines with ^.
        chars = chars.enumerated().compactMap { offset, c in
            c == "^" && (offset + 1 == chars.count || chars[offset + 1] == "\n" || chars[offset + 1] == "\r")
                ? nil : c
        }
        var i = 0
        func finish() {
            if inWord { words.append(current) }
            current = ""
            inWord = false
        }
        while i < chars.count {
            let c = chars[i]
            switch c {
            case " ", "\t", "\n", "\r":
                finish()
                i += 1
            case "\\":
                if i + 1 < chars.count, chars[i + 1] == "\n" {
                    i += 2  // line continuation
                } else if i + 2 < chars.count, chars[i + 1] == "\r", chars[i + 2] == "\n" {
                    i += 3
                } else if i + 1 < chars.count {
                    current.append(chars[i + 1])
                    inWord = true
                    i += 2
                } else {
                    throw RequestImportError.unterminatedQuote
                }
            case "'":
                inWord = true
                guard let end = chars[(i + 1)...].firstIndex(of: "'") else {
                    throw RequestImportError.unterminatedQuote
                }
                current += String(chars[(i + 1)..<end])
                i = end + 1
            case "\"":
                inWord = true
                i += 1
                var closed = false
                while i < chars.count {
                    let d = chars[i]
                    if d == "\"" {
                        closed = true
                        i += 1
                        break
                    }
                    if d == "\\", i + 1 < chars.count, "\"\\$`\n".contains(chars[i + 1]) {
                        if chars[i + 1] != "\n" { current.append(chars[i + 1]) }
                        i += 2
                        continue
                    }
                    current.append(d)
                    i += 1
                }
                if !closed { throw RequestImportError.unterminatedQuote }
            case "$" where i + 1 < chars.count && chars[i + 1] == "'":
                inWord = true
                i += 2
                var closed = false
                var bytes: [UInt8] = []
                func flush() {
                    current += String(decoding: bytes, as: UTF8.self)
                    bytes = []
                }
                while i < chars.count {
                    let d = chars[i]
                    if d == "'" {
                        closed = true
                        i += 1
                        break
                    }
                    if d == "\\", i + 1 < chars.count {
                        let e = chars[i + 1]
                        i += 2
                        switch e {
                        case "n": bytes.append(0x0A)
                        case "r": bytes.append(0x0D)
                        case "t": bytes.append(0x09)
                        case "0": bytes.append(0)
                        case "e", "E": bytes.append(0x1B)
                        case "x":
                            var hex = ""
                            while hex.count < 2, i < chars.count, chars[i].isHexDigit {
                                hex.append(chars[i])
                                i += 1
                            }
                            bytes.append(UInt8(hex, radix: 16) ?? 0)
                        case "u":
                            var hex = ""
                            while hex.count < 4, i < chars.count, chars[i].isHexDigit {
                                hex.append(chars[i])
                                i += 1
                            }
                            if let scalar = UInt32(hex, radix: 16).flatMap(Unicode.Scalar.init) {
                                bytes += Array(String(Character(scalar)).utf8)
                            }
                        default: bytes += Array(String(e).utf8)  // \\ \' \" and anything else
                        }
                        continue
                    }
                    bytes += Array(String(d).utf8)
                    i += 1
                }
                flush()
                if !closed { throw RequestImportError.unterminatedQuote }
            default:
                current.append(c)
                inWord = true
                i += 1
            }
        }
        finish()
        return words
    }
}

// MARK: - JS literals

/// A JavaScript literal value as found in a `fetch` call.
enum JSValue: Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case null
    case object([(String, JSValue)])
    case array([JSValue])
    /// An expression this reader doesn't evaluate (a variable, a call).
    case other(String)

    static func == (lhs: JSValue, rhs: JSValue) -> Bool {
        switch (lhs, rhs) {
        case (.string(let a), .string(let b)): a == b
        case (.number(let a), .number(let b)): a == b
        case (.bool(let a), .bool(let b)): a == b
        case (.null, .null): true
        case (.object(let a), .object(let b)): a.map(\.0) == b.map(\.0) && a.map(\.1) == b.map(\.1)
        case (.array(let a), .array(let b)): a == b
        case (.other(let a), .other(let b)): a == b
        default: false
        }
    }
}

/// Reads JS object/array/string/number literals (the JSON-like subset copy-as-fetch produces, plus
/// single/backtick quotes, bare keys and trailing commas).
struct JSLiteralReader {
    private let chars: [Character]
    private var i = 0

    init(_ text: String) {
        chars = Array(text)
    }

    private mutating func skipSpace() {
        while i < chars.count {
            if chars[i].isWhitespace {
                i += 1
            } else if chars[i] == "/", i + 1 < chars.count, chars[i + 1] == "/" {
                while i < chars.count, chars[i] != "\n" { i += 1 }
            } else {
                return
            }
        }
    }

    mutating func consume(_ c: Character) -> Bool {
        skipSpace()
        guard i < chars.count, chars[i] == c else { return false }
        i += 1
        return true
    }

    mutating func value() throws -> JSValue? {
        skipSpace()
        guard i < chars.count else { return nil }
        let c = chars[i]
        switch c {
        case "\"", "'", "`": return .string(try string())
        case "{": return try object()
        case "[":
            i += 1
            var items: [JSValue] = []
            while !consume("]") {
                guard let item = try value() else { throw RequestImportError.unrecognized }
                items.append(item)
                _ = consume(",")
            }
            return .array(items)
        default:
            let start = i
            while i < chars.count, !",}])".contains(chars[i]), !chars[i].isWhitespace { i += 1 }
            let word = String(chars[start..<i])
            switch word {
            case "null", "undefined": return .null
            case "true": return .bool(true)
            case "false": return .bool(false)
            default: return Double(word).map(JSValue.number) ?? .other(word)
            }
        }
    }

    private mutating func object() throws -> JSValue {
        i += 1  // {
        var fields: [(String, JSValue)] = []
        while !consume("}") {
            skipSpace()
            guard i < chars.count else { throw RequestImportError.unterminatedQuote }
            let key: String
            if "\"'`".contains(chars[i]) {
                key = try string()
            } else {
                let start = i
                while i < chars.count, chars[i] != ":", !chars[i].isWhitespace { i += 1 }
                key = String(chars[start..<i])
            }
            guard consume(":"), let item = try value() else { throw RequestImportError.unrecognized }
            fields.append((key, item))
            _ = consume(",")
        }
        return .object(fields)
    }

    private static func scalar(_ hex: String) -> Unicode.Scalar? {
        UInt32(hex, radix: 16).flatMap(Unicode.Scalar.init)
    }

    private mutating func string() throws -> String {
        let quote = chars[i]
        i += 1
        var out = ""
        while i < chars.count {
            let c = chars[i]
            i += 1
            if c == quote { return out }
            guard c == "\\", i < chars.count else {
                out.append(c)
                continue
            }
            let e = chars[i]
            i += 1
            switch e {
            case "n": out.append("\n")
            case "r": out.append("\r")
            case "t": out.append("\t")
            case "0": out.append("\0")
            case "u":
                var hex = ""
                if i < chars.count, chars[i] == "{" {
                    i += 1
                    while i < chars.count, chars[i] != "}" {
                        hex.append(chars[i])
                        i += 1
                    }
                    i += 1
                } else {
                    while hex.count < 4, i < chars.count {
                        hex.append(chars[i])
                        i += 1
                    }
                }
                if let scalar = Self.scalar(hex) { out.append(Character(scalar)) }
            case "x":
                let hex = String(chars[i..<min(i + 2, chars.count)])
                i += 2
                if let scalar = Self.scalar(hex) { out.append(Character(scalar)) }
            case "\n": break  // line continuation
            default: out.append(e)
            }
        }
        throw RequestImportError.unterminatedQuote
    }
}
