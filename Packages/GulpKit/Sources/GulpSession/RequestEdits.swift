// GulpSession — small raw-request edits the session layer needs beyond GulpHTTP's `settingHeader`:
// removing a header and setting a query parameter. Both work on the raw bytes (no URLComponents
// round-trip) so they obey the "raw bytes are the truth" rule; Content-Length is left to the engine.

import Foundation
import GulpCore
import GulpHTTP

extension RawRequest {
    /// The request with every header named `name` (case-insensitive) removed.
    public func removingHeader(_ name: String) -> RawRequest {
        let lower = name.lowercased()
        let fields = parsed.headers.filter { bytes[$0.name].string().lowercased() == lower }
        guard !fields.isEmpty else { return self }
        var result = self
        for field in fields.reversed() {
            var end = field.line.upperBound
            let all = result.bytes.rawBytes
            if end < all.count, all[end] == 0x0D { end += 1 }
            if end < all.count, all[end] == 0x0A { end += 1 }
            result = result.replacing(field.line.lowerBound..<end, with: Bytes())
        }
        return result
    }

    /// The request with query parameter `name` set to `value` (URL-encoded): the first occurrence is
    /// replaced, or the parameter is appended to the query string. The path and everything after the
    /// request target are untouched.
    public func settingQueryParameter(_ name: String, to value: String) -> RawRequest {
        let targetRange = parsed.target
        let targetBytes = Array(bytes.rawBytes[targetRange])
        let target = String(decoding: targetBytes, as: UTF8.self)
        let encodedName = Self.encodeComponent(name)
        let encodedValue = Self.encodeComponent(value)
        let (pathPart, queryPart) = Self.splitQuery(target)
        var pairs =
            queryPart.isEmpty
            ? [] : queryPart.split(separator: "&", omittingEmptySubsequences: false).map(String.init)
        var replaced = false
        for index in pairs.indices {
            let key = pairs[index].split(separator: "=", maxSplits: 1).first.map(String.init) ?? pairs[index]
            if key == encodedName || key == name {
                pairs[index] = "\(encodedName)=\(encodedValue)"
                replaced = true
                break
            }
        }
        if !replaced { pairs.append("\(encodedName)=\(encodedValue)") }
        let newTarget = pathPart + "?" + pairs.joined(separator: "&")
        return replacing(targetRange, with: Bytes(Array(newTarget.utf8)))
    }

    static func splitQuery(_ target: String) -> (path: String, query: String) {
        guard let mark = target.firstIndex(of: "?") else { return (target, "") }
        return (String(target[..<mark]), String(target[target.index(after: mark)...]))
    }

    static func encodeComponent(_ text: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return text.addingPercentEncoding(withAllowedCharacters: allowed) ?? text
    }
}
