// GulpSequencer — pulling a token out of a response (SEQ-001). The extraction is pure (it reads a
// response's headers/body), so the capture loop — repeatedly sending the base request and collecting
// tokens — lives in whatever drives the engine (the CLI, the workspace), keeping this module
// engine-free and Linux-testable.

import Foundation

/// Where the token lives in a response.
public enum TokenLocation: Sendable {
    /// A `Set-Cookie` value by cookie name.
    case cookie(String)
    /// The first capture group of a regular expression over the response text.
    case regex(String)

    /// Extract the token from a response's raw bytes, or nil if it isn't present.
    public func extract(fromResponse bytes: [UInt8]) -> String? {
        let text = String(decoding: bytes, as: UTF8.self)
        switch self {
        case .cookie(let name):
            return TokenLocation.cookie(named: name, in: text)
        case .regex(let pattern):
            guard let regex = try? NSRegularExpression(pattern: pattern),
                let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
                match.numberOfRanges > 1, let range = Range(match.range(at: 1), in: text)
            else { return nil }
            return String(text[range])
        }
    }

    /// Read the value of the named cookie from the `Set-Cookie` headers in a raw response.
    static func cookie(named name: String, in response: String) -> String? {
        let headerBlock = response.components(separatedBy: "\r\n\r\n").first ?? response
        for line in headerBlock.components(separatedBy: "\r\n") {
            guard line.lowercased().hasPrefix("set-cookie:") else { continue }
            let value = line.dropFirst("set-cookie:".count).trimmingCharacters(in: .whitespaces)
            // The cookie is `name=value; attrs…`; take the first pair and match the name.
            guard let pair = value.split(separator: ";", maxSplits: 1).first,
                let eq = pair.firstIndex(of: "=")
            else { continue }
            let cookieName = pair[..<eq].trimmingCharacters(in: .whitespaces)
            if cookieName.caseInsensitiveCompare(name) == .orderedSame {
                return String(pair[pair.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }
}
