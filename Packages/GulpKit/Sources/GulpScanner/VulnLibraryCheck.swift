// GulpScanner — passive detection of known-vulnerable JavaScript libraries (F08 §3.2, "Vulnerable JS
// libraries"). It fingerprints a library's name and version from script src filenames, banner
// comments and `VERSION` strings in HTML/JS responses, then flags the version against a small,
// bundled dataset of fixed-in versions with the relevant advisory. No network calls at scan time —
// the dataset ships with Gulp (Burp does this only via an extension / its Pro scanner).

import Foundation
import GulpCore

/// One library in the bundled vulnerability dataset.
struct VulnLibrary: Sendable {
    /// Library name as it appears to users.
    let name: String
    /// Versions strictly below this are vulnerable (the first fixed version).
    let fixedIn: [Int]
    /// A short note naming the class of issue / advisory.
    let advisory: String
    /// Regexes that capture the version (group 1) from a filename, banner or VERSION string.
    let patterns: [String]
}

/// Passive vulnerable-library detection.
public enum VulnLibraryCheck {
    /// The bundled dataset (small and curated; the macOS build can refresh it).
    static let libraries: [VulnLibrary] = [
        VulnLibrary(
            name: "jQuery", fixedIn: [3, 5, 0], advisory: "XSS via htmlPrefilter (CVE-2020-11022/11023)",
            patterns: [
                #"jquery[.-]v?(\d+\.\d+\.\d+)"#, #"jQuery v(\d+\.\d+\.\d+)"#,
                #"jQuery JavaScript Library v(\d+\.\d+\.\d+)"#,
            ]),
        VulnLibrary(
            name: "lodash", fixedIn: [4, 17, 21],
            advisory: "prototype pollution / command injection (CVE-2021-23337)",
            patterns: [#"lodash[.-](\d+\.\d+\.\d+)"#, #"lodash.*VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]"#]),
        VulnLibrary(
            name: "Bootstrap", fixedIn: [4, 3, 1], advisory: "XSS in data-target/tooltip (CVE-2019-8331)",
            patterns: [#"bootstrap[.-]v?(\d+\.\d+\.\d+)"#, #"Bootstrap v(\d+\.\d+\.\d+)"#]),
        VulnLibrary(
            name: "Moment.js", fixedIn: [2, 29, 4], advisory: "path traversal / ReDoS (CVE-2022-31129)",
            patterns: [#"moment[.-](\d+\.\d+\.\d+)"#, #"//! moment.js.*version : (\d+\.\d+\.\d+)"#]),
        VulnLibrary(
            name: "Handlebars", fixedIn: [4, 7, 7], advisory: "prototype pollution / RCE (CVE-2019-20920)",
            patterns: [#"handlebars[.-](\d+\.\d+\.\d+)"#]),
        VulnLibrary(
            name: "AngularJS", fixedIn: [999, 0, 0],
            advisory: "end-of-life, unpatched (no supported version)",
            patterns: [#"angular[.-](\d+\.\d+\.\d+)"#, #"angular\.version.*full['"]:\s*['"](\d+\.\d+\.\d+)"#]),
        VulnLibrary(
            name: "DOMPurify", fixedIn: [2, 0, 17], advisory: "mXSS bypass (CVE-2020-26870)",
            patterns: [
                #"purify[.-](\d+\.\d+\.\d+)"#, #"DOMPurify.*version['"]?\s*[:=]\s*['"](\d+\.\d+\.\d+)"#,
            ]),
    ]

    /// Parse a dotted version into components (missing parts are 0).
    static func version(_ text: String) -> [Int] {
        let parts = text.split(separator: ".").map { Int($0) ?? 0 }
        return parts + Array(repeating: 0, count: max(0, 3 - parts.count))
    }

    /// `a < b` by component.
    static func less(_ a: [Int], _ b: [Int]) -> Bool {
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x < y }
        }
        return false
    }

    /// Scan an HTML or JavaScript response for vulnerable library versions.
    static func scan(_ message: PassiveMessage) -> [IssueFinding] {
        guard message.isHTML || message.mime.contains("javascript") || message.path.hasSuffix(".js") else {
            return []
        }
        let body = message.body
        guard body.count < 3_000_000 else { return [] }
        var findings: [IssueFinding] = []
        var seen: Set<String> = []
        for library in libraries {
            for pattern in library.patterns {
                guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
                else { continue }
                guard let match = regex.firstMatch(in: body, range: NSRange(body.startIndex..., in: body)),
                    match.numberOfRanges > 1, let versionRange = Range(match.range(at: 1), in: body)
                else { continue }
                let versionText = String(body[versionRange])
                guard less(version(versionText), library.fixedIn), seen.insert(library.name).inserted else {
                    continue
                }
                let fixed =
                    library.fixedIn == [999, 0, 0]
                    ? "no supported release" : library.fixedIn.map(String.init).joined(separator: ".")
                findings.append(
                    message.finding(
                        PassiveChecks.d("passive.vuln-js-library"), variant: library.name,
                        detail:
                            "The page loads **\(library.name) \(versionText)**, which is vulnerable: \(library.advisory). Fixed in \(fixed).",
                        responseMarkers: message.bodyMarker(versionText).map { [$0] } ?? []))
                break
            }
        }
        return findings
    }
}
