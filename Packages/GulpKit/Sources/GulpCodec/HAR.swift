// GulpCodec — HAR 1.2 in and out (F20 PRJ-012, F05 HIS-044), Postman v2.1 collections (F23
// ADV-051) and CSV export.
//
// Gulp's HAR export is standard HAR (any tool reads it) plus a `_gulp` object per entry holding the
// exact request and response bytes (base64), the source tool and the highlight. HAR's own fields
// are parsed views (headers split, bodies decoded), so they can't reproduce bytes; `_gulp` makes
// export → import byte-for-byte (F20 acceptance 6). Other tools' HARs (browsers, mitmproxy, Caido)
// are rebuilt from the parsed fields.

import Foundation
import GulpCore

/// HAR import and export.
public enum HAR {
    /// HAR for `exchanges` (Gulp's export: standard fields plus `_gulp` raw bytes).
    public static func export(_ exchanges: [Exchange], creatorVersion: String = "1") throws -> Data {
        let entries = exchanges.map(entry)
        let log: [String: Any] = [
            "log": [
                "version": "1.2", "creator": ["name": "Gulp", "version": creatorVersion], "entries": entries,
            ] as [String: Any]
        ]
        return try JSONSerialization.data(
            withJSONObject: log, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }

    static func entry(_ exchange: Exchange) -> [String: Any] {
        let request = exchange.request
        let url = Wire.url(exchange.target, request: request)
        let version = exchange.httpVersion.rawValue
        var requestObject: [String: Any] = [
            "method": exchange.derived.method ?? "GET", "url": url, "httpVersion": version,
            "cookies": [Any](),
            "headers": headers(request.parsed.headers, in: request.bytes),
            "queryString": (exchange.derived.query ?? "").split(separator: "&").map {
                pair -> [String: String] in
                let parts = pair.split(separator: "=", maxSplits: 1)
                return ["name": String(parts.first ?? ""), "value": parts.count > 1 ? String(parts[1]) : ""]
            },
            "headersSize": request.parsed.headerBlockEnd, "bodySize": request.parsed.body.count,
        ]
        let requestBody = request.bytes[request.parsed.body].rawBytes
        if !requestBody.isEmpty {
            requestObject["postData"] = [
                "mimeType": request.headerValue("content-type")?.string() ?? "",
                "text": String(decoding: requestBody, as: UTF8.self),
            ]
        }
        var responseObject: [String: Any] = [
            "status": 0, "statusText": "", "httpVersion": version, "cookies": [Any](), "headers": [Any](),
            "content": ["size": 0, "mimeType": ""], "redirectURL": "", "headersSize": -1, "bodySize": -1,
        ]
        var gulp: [String: Any] = [
            "request": Data(request.bytes.rawBytes).base64EncodedString(), "source": exchange.source.rawValue,
            "scheme": exchange.target.scheme.rawValue, "host": exchange.target.host,
            "port": exchange.target.port,
        ]
        if let response = exchange.response {
            let body =
                response.parsed.dechunkedBody?.rawBytes ?? response.bytes[response.parsed.body].rawBytes
            var content: [String: Any] = [
                "size": body.count, "mimeType": response.headerValue("content-type")?.string() ?? "",
            ]
            if let text = String(validatingUTF8CString: body) {
                content["text"] = text
            } else {
                content["text"] = Data(body).base64EncodedString()
                content["encoding"] = "base64"
            }
            responseObject = [
                "status": response.parsed.statusCode,
                "statusText": response.bytes[response.parsed.reasonPhrase].string(), "httpVersion": version,
                "cookies": [Any](), "headers": headers(response.parsed.headers, in: response.bytes),
                "content": content, "redirectURL": response.headerValue("location")?.string() ?? "",
                "headersSize": response.parsed.headerBlockEnd, "bodySize": response.parsed.body.count,
            ]
            gulp["response"] = Data(response.wireBytes.rawBytes).base64EncodedString()
        }
        if let highlight = exchange.annotation.highlight { gulp["highlight"] = highlight.rawValue }
        let total = exchange.timing.totalMs ?? 0
        var entry: [String: Any] = [
            "startedDateTime": Wire.isoString(exchange.timing.start), "time": total, "request": requestObject,
            "response": responseObject, "cache": [String: Any](),
            "timings": ["send": 0, "wait": total, "receive": 0], "_gulp": gulp,
        ]
        if let comment = exchange.annotation.comment, !comment.isEmpty { entry["comment"] = comment }
        return entry
    }

    static func headers(_ fields: [HeaderField], in bytes: Bytes) -> [[String: String]] {
        fields.map { ["name": bytes[$0.name].string(), "value": bytes[$0.value].string()] }
    }

    /// Read a HAR file.
    public static func read(_ data: Data) throws -> ImportBatch {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let log = root["log"] as? [String: Any], let entries = log["entries"] as? [[String: Any]]
        else { throw TrafficImportError("Not a HAR file: expected {\"log\": {\"entries\": [...]}}.") }
        var batch = ImportBatch(format: .har)
        for (index, entry) in entries.enumerated() {
            let label = "entry \(index + 1)"
            do {
                batch.exchanges.append(try exchange(entry))
            } catch let error as TrafficImportError {
                batch.skipped.append(ImportSkip(item: label, reason: error.message))
            } catch {
                batch.skipped.append(ImportSkip(item: label, reason: "\(error)"))
            }
        }
        return batch
    }

    static func exchange(_ entry: [String: Any]) throws -> ImportedExchange {
        guard let requestObject = entry["request"] as? [String: Any] else {
            throw TrafficImportError("no request")
        }
        let url = requestObject["url"] as? String ?? ""
        let version = httpVersion(requestObject["httpVersion"] as? String)
        let gulp = entry["_gulp"] as? [String: Any]
        let comment = (entry["comment"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        let highlight = ((gulp?["highlight"] ?? entry["_highlight"]) as? String).flatMap(Wire.highlight)
        let started = Wire.date(entry["startedDateTime"])
        let duration = (entry["time"] as? NSNumber)?.doubleValue
        // Gulp's own export: the exact bytes.
        if let gulp, let raw = (gulp["request"] as? String).flatMap({ Data(base64Encoded: $0) }) {
            let request = RawRequest(Bytes([UInt8](raw)))
            let scheme: Scheme = (gulp["scheme"] as? String) == "https" ? .https : .http
            let target: HTTPTarget
            if let host = gulp["host"] as? String, !host.isEmpty {
                target = HTTPTarget(scheme: scheme, host: host, port: (gulp["port"] as? NSNumber)?.intValue)
            } else if let fromURL = HTTPTarget(url: url) {
                target = fromURL
            } else {
                throw TrafficImportError("no target")
            }
            let response = (gulp["response"] as? String).flatMap { Data(base64Encoded: $0) }.map {
                RawResponse(wire: Bytes([UInt8]($0)))
            }
            return ImportedExchange(
                target: target, request: request, response: response, httpVersion: version,
                startedAt: started,
                durationMs: duration, comment: comment, highlight: highlight,
                source: (gulp["source"] as? String).flatMap(ToolSource.init(rawValue:)))
        }
        // Anyone else's HAR: rebuild from the parsed fields.
        guard let target = HTTPTarget(url: url) else {
            throw TrafficImportError("not an http(s) URL: \(url)")
        }
        let method = requestObject["method"] as? String ?? "GET"
        var requestHeaders = pairs(requestObject["headers"])
        if !requestHeaders.contains(where: { $0.0.lowercased() == "host" }),
            let authority = requestHeaders.first(where: { $0.0.lowercased() == ":authority" })?.1
        {
            requestHeaders.insert(("Host", authority), at: 0)
        }
        var body: [UInt8] = []
        if let post = requestObject["postData"] as? [String: Any] {
            if let text = post["text"] as? String, !text.isEmpty {
                body =
                    (post["encoding"] as? String) == "base64"
                    ? [UInt8](Data(base64Encoded: text) ?? Data()) : Array(text.utf8)
            } else {
                let params = pairs(post["params"])
                body = Array(params.map { "\($0.0)=\($0.1)" }.joined(separator: "&").utf8)
            }
        }
        let token = version == .http2 ? "HTTP/2" : (version == .http1_0 ? "HTTP/1.0" : "HTTP/1.1")
        let request = Wire.build(
            method: method, url: url, target: target, headers: requestHeaders, body: body, version: token)
        var response: RawResponse?
        if let responseObject = entry["response"] as? [String: Any],
            let status = (responseObject["status"] as? NSNumber)?.intValue, status > 0
        {
            var responseBody: [UInt8] = []
            if let content = responseObject["content"] as? [String: Any],
                let text = content["text"] as? String
            {
                responseBody =
                    (content["encoding"] as? String) == "base64"
                    ? [UInt8](Data(base64Encoded: text, options: .ignoreUnknownCharacters) ?? Data())
                    : Array(text.utf8)
            }
            response = Wire.response(
                status: status, reason: responseObject["statusText"] as? String ?? "",
                headers: pairs(responseObject["headers"]), body: responseBody, version: token)
        }
        return ImportedExchange(
            target: target, request: request, response: response, httpVersion: version, startedAt: started,
            durationMs: duration, comment: comment, highlight: highlight)
    }

    /// `[{"name": …, "value": …}]` (or Postman's `key`) as ordered pairs; disabled entries dropped.
    static func pairs(_ value: Any?) -> [(String, String)] {
        (value as? [[String: Any]] ?? []).compactMap { item in
            if item["disabled"] as? Bool == true { return nil }
            guard let name = (item["name"] ?? item["key"]) as? String, !name.isEmpty else { return nil }
            return (name, item["value"].map { ($0 as? String) ?? "\($0)" } ?? "")
        }
    }

    static func httpVersion(_ text: String?) -> HTTPVersion {
        let lower = (text ?? "").lowercased()
        if lower.contains("2") && !lower.contains("1.") { return .http2 }
        if lower.contains("1.0") { return .http1_0 }
        return .http1_1
    }

    /// CSV of exchanges for spreadsheets (HIS-044): id, time, method, URL, status, length, MIME,
    /// highlight, comment. RFC 4180 quoting.
    public static func csv(_ exchanges: [Exchange]) -> Data {
        var lines = ["id,time,method,url,status,length,mime,highlight,comment"]
        for exchange in exchanges {
            let derived = exchange.derived
            let fields: [String] = [
                String(exchange.id), Wire.isoString(exchange.timing.start), derived.method ?? "",
                Wire.url(exchange.target, request: exchange.request), derived.status.map(String.init) ?? "",
                derived.responseLength.map(String.init) ?? "", derived.mime ?? "",
                exchange.annotation.highlight?.rawValue ?? "", exchange.annotation.comment ?? "",
            ]
            lines.append(fields.map(quote).joined(separator: ","))
        }
        return Data((lines.joined(separator: "\r\n") + "\r\n").utf8)
    }

    static func quote(_ field: String) -> String {
        guard field.contains(where: { $0 == "," || $0 == "\"" || $0.isNewline }) else {
            return field
        }
        return "\"" + field.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }
}

extension String {
    /// `bytes` as a String if they are valid UTF-8 without NUL bytes (so text bodies stay text in
    /// HAR, and binary ones are base64).
    init?(validatingUTF8CString bytes: [UInt8]) {
        guard !bytes.contains(0), let text = String(bytes: bytes, encoding: .utf8) else { return nil }
        self = text
    }
}

/// Postman collection v2.1 (ADV-051): every request in every folder, `{{variables}}` resolved from
/// the collection's variables (unresolved ones are left as written and reported).
public enum Postman {
    /// Read a collection.
    public static func read(_ data: Data) throws -> ImportBatch {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let items = root["item"] as? [[String: Any]]
        else {
            throw TrafficImportError("Not a Postman collection: expected {\"info\": …, \"item\": [...]}.")
        }
        var variables: [String: String] = [:]
        for (name, value) in HAR.pairs(root["variable"]) { variables[name] = value }
        var batch = ImportBatch(format: .postman)
        walk(items, path: [], variables: variables, into: &batch)
        return batch
    }

    static func walk(
        _ items: [[String: Any]], path: [String], variables: [String: String], into batch: inout ImportBatch
    ) {
        for item in items {
            let name = item["name"] as? String ?? "request"
            let label = (path + [name]).joined(separator: " / ")
            if let children = item["item"] as? [[String: Any]] {
                walk(children, path: path + [name], variables: variables, into: &batch)
                continue
            }
            guard let request = item["request"] else {
                batch.skipped.append(ImportSkip(item: label, reason: "no request"))
                continue
            }
            do {
                var imported = try build(request, variables: variables)
                imported.comment = label
                batch.exchanges.append(imported)
            } catch let error as TrafficImportError {
                batch.skipped.append(ImportSkip(item: label, reason: error.message))
            } catch {
                batch.skipped.append(ImportSkip(item: label, reason: "\(error)"))
            }
        }
    }

    static func build(_ request: Any, variables: [String: String]) throws -> ImportedExchange {
        func resolve(_ text: String) -> String {
            var result = text
            for (name, value) in variables {
                result = result.replacingOccurrences(of: "{{\(name)}}", with: value)
            }
            return result
        }
        // A bare string request is a GET of that URL.
        let object = request as? [String: Any] ?? ["url": request, "method": "GET"]
        var urlText = ""
        if let url = object["url"] as? String {
            urlText = url
        } else if let url = object["url"] as? [String: Any] {
            urlText = url["raw"] as? String ?? ""
        }
        urlText = resolve(urlText)
        if urlText.range(of: #"\{\{[^}]+\}\}"#, options: .regularExpression) != nil {
            throw TrafficImportError("unresolved variable in URL \(urlText)")
        }
        if !urlText.lowercased().hasPrefix("http") { urlText = "https://" + urlText }
        guard let target = HTTPTarget(url: urlText) else {
            throw TrafficImportError("not an http(s) URL: \(urlText)")
        }
        let method = (object["method"] as? String ?? "GET").uppercased()
        var headers = HAR.pairs(object["header"]).map { ($0.0, resolve($0.1)) }
        var body: [UInt8] = []
        if let bodyObject = object["body"] as? [String: Any], (bodyObject["disabled"] as? Bool) != true {
            switch bodyObject["mode"] as? String {
            case "raw":
                body = Array(resolve(bodyObject["raw"] as? String ?? "").utf8)
                let language = ((bodyObject["options"] as? [String: Any])?["raw"] as? [String: Any])?[
                    "language"]
                if language as? String == "json",
                    !headers.contains(where: { $0.0.lowercased() == "content-type" })
                {
                    headers.append(("Content-Type", "application/json"))
                }
            case "urlencoded":
                body = Array(
                    HAR.pairs(bodyObject["urlencoded"]).map { "\($0.0)=\(resolve($0.1))" }.joined(
                        separator: "&"
                    ).utf8)
                if !headers.contains(where: { $0.0.lowercased() == "content-type" }) {
                    headers.append(("Content-Type", "application/x-www-form-urlencoded"))
                }
            case "graphql":
                if let graphql = bodyObject["graphql"] as? [String: Any],
                    let json = try? JSONSerialization.data(withJSONObject: graphql, options: [.sortedKeys])
                {
                    body = [UInt8](json)
                    headers.append(("Content-Type", "application/json"))
                }
            default: break
            }
        }
        return ImportedExchange(
            target: target,
            request: Wire.build(method: method, url: urlText, target: target, headers: headers, body: body))
    }
}
