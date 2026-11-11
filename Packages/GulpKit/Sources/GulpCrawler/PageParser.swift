// GulpCrawler — static link and form extraction (F09 CRL-002, CRL-004 discovery). A tolerant tag
// scanner (no well-formedness required) reads `a`, `link`, `area`, `script`, `img`, `iframe`,
// `frame`, `form`, `base` and meta refresh; CSS `url(...)` comes from `<style>` blocks, `style`
// attributes and stylesheets; the `Location` and `Refresh` headers count too. URL-looking strings
// in scripts and JSON are a low-priority heuristic. Relative references resolve against `<base>`
// or the page URL (GulpCore's `LinkExtractor.resolve`, shared with the site map's inferred nodes).

import Foundation
import GulpCore

/// Where a link was found.
public enum LinkSource: String, Sendable, Codable, Hashable {
    case anchor, link, script, image, frame, form, location, refresh, css, sitemap, robots, heuristic
}

/// A discovered URL.
public struct DiscoveredLink: Sendable, Hashable {
    /// Absolute URL.
    public var url: String
    /// Where it came from.
    public var source: LinkSource

    /// Heuristic URL strings (in scripts/JSON) are crawled after everything else (CRL-002).
    public var isLowPriority: Bool { source == .heuristic }
}

/// A form field.
public struct FormField: Sendable, Hashable, Codable {
    /// `name`.
    public var name: String
    /// `type` (lowercased; `text` when absent), or `select`/`textarea`.
    public var type: String
    /// The page's value (`value`, a select's first or selected option, a textarea's text).
    public var value: String
    /// A checkbox/radio's `checked`.
    public var checked: Bool
}

/// A form found on a page.
public struct HTMLForm: Sendable, Hashable, Codable {
    /// The absolute action URL (the page itself when the action is empty).
    public var action: String
    /// `GET` or `POST` (uppercased).
    public var method: String
    /// `enctype` (lowercased).
    public var enctype: String
    /// Fields in document order (submit buttons included, with `type` `submit`).
    public var fields: [FormField]
    /// The page it was found on.
    public var page: String
}

/// What a response yields.
public struct ParsedPage: Sendable {
    /// Links, in document order, unique.
    public var links: [DiscoveredLink]
    /// Forms.
    public var forms: [HTMLForm]
    /// A structure fingerprint of the HTML (tag sequence), for duplicate-page detection (CRL-007).
    public var structureHash: Int?
}

/// The static extractor.
public enum PageParser {
    /// Upper bound on links taken from one response.
    public static let maxLinks = 2_000
    /// Bodies longer than this are only partly read.
    public static let maxBody = 4_000_000

    /// Parse `response` to a request for `pageURL`.
    public static func parse(_ response: RawResponse, pageURL: String) -> ParsedPage {
        var raw: [(String, LinkSource)] = []
        if let location = response.headerValue("location")?.string() { raw.append((location, .location)) }
        if let refresh = response.headerValue("refresh")?.string(), let url = refreshURL(refresh) {
            raw.append((url, .refresh))
        }
        let type = response.headerValue("content-type")?.string().lowercased() ?? ""
        var forms: [HTMLForm] = []
        var structure: Int?
        var base = pageURL
        if let body = (try? response.decodedBody(limit: maxBody)) ?? nil {
            let text = String(decoding: body.rawBytes.prefix(maxBody), as: UTF8.self)
            if type.contains("html")
                || (type.isEmpty && text.range(of: "<html", options: .caseInsensitive) != nil)
            {
                let html = parseHTML(text, pageURL: pageURL)
                raw += html.links
                forms = html.forms
                structure = html.structureHash
                base = html.base ?? pageURL
            } else if type.contains("css") {
                raw += cssURLs(text).map { ($0, .css) }
            } else if type.contains("javascript") || type.contains("json") || type.contains("ecmascript") {
                raw += heuristicURLs(text).map { ($0, .heuristic) }
            } else if type.contains("xml") {
                raw += sitemapURLs(text).map { ($0, .sitemap) }
            }
        }
        var seen: Set<String> = []
        var links: [DiscoveredLink] = []
        for (reference, source) in raw {
            let against = source == .location || source == .refresh ? pageURL : base
            guard let resolved = LinkExtractor.resolve(decodeEntities(reference), against: against),
                seen.insert(resolved).inserted
            else { continue }
            links.append(DiscoveredLink(url: resolved, source: source))
            if links.count == maxLinks { break }
        }
        return ParsedPage(links: links, forms: forms, structureHash: structure)
    }

    // MARK: HTML

    struct HTMLResult {
        var links: [(String, LinkSource)] = []
        var forms: [HTMLForm] = []
        var base: String?
        var structureHash: Int?
    }

    /// One tag: lowercased name, attributes (lowercased names), whether it closes.
    struct Tag {
        var name: String
        var attributes: [String: String]
        var closing: Bool
        var end: String.Index
    }

    static func parseHTML(_ text: String, pageURL: String) -> HTMLResult {
        var result = HTMLResult()
        var hasher = Hasher()
        var tagCount = 0
        var form: HTMLForm?
        var selectField: FormField?
        var textareaName: String?
        var index = text.startIndex
        func add(_ value: String?, _ source: LinkSource) {
            if let value, !value.isEmpty { result.links.append((value, source)) }
        }
        while let open = text[index...].firstIndex(of: "<") {
            if text[open...].hasPrefix("<!--") {
                index = text[open...].range(of: "-->")?.upperBound ?? text.endIndex
                continue
            }
            guard let tag = scanTag(text, from: open) else {
                index = text.index(after: open)
                continue
            }
            index = tag.end
            if tagCount < 5_000 {
                hasher.combine(tag.closing ? "/" + tag.name : tag.name)
                tagCount += 1
            }
            let attributes = tag.attributes
            if tag.closing {
                switch tag.name {
                case "form":
                    if let done = form { result.forms.append(done) }
                    form = nil
                case "select":
                    if let field = selectField { form?.fields.append(field) }
                    selectField = nil
                default: break
                }
                continue
            }
            switch tag.name {
            case "a", "area": add(attributes["href"], .anchor)
            case "link": add(attributes["href"], .link)
            case "base":
                if result.base == nil, let href = attributes["href"] {
                    result.base = LinkExtractor.resolve(decodeEntities(href), against: pageURL)
                }
            case "script":
                add(attributes["src"], .script)
                // Inline script: heuristic URL strings, then skip to </script>.
                let close = text[index...].range(of: "</script", options: .caseInsensitive)
                let body = text[index..<(close?.lowerBound ?? text.endIndex)]
                if attributes["src"] == nil {
                    result.links += heuristicURLs(String(body)).map { ($0, .heuristic) }
                }
                index = close?.lowerBound ?? text.endIndex
            case "style":
                let close = text[index...].range(of: "</style", options: .caseInsensitive)
                result.links += cssURLs(String(text[index..<(close?.lowerBound ?? text.endIndex)])).map {
                    ($0, .css)
                }
                index = close?.lowerBound ?? text.endIndex
            case "img", "input", "embed", "source", "audio", "video", "track":
                add(attributes["src"], .image)
                if let srcset = attributes["srcset"] {
                    for candidate in srcset.split(separator: ",") {
                        add(candidate.split(separator: " ").first.map(String.init), .image)
                    }
                }
            case "iframe", "frame": add(attributes["src"], .frame)
            case "object": add(attributes["data"], .frame)
            case "meta":
                if attributes["http-equiv"]?.lowercased() == "refresh", let content = attributes["content"] {
                    add(refreshURL(content), .refresh)
                }
            case "form":
                if let done = form { result.forms.append(done) }  // unclosed previous form
                let action = attributes["action"].flatMap { $0.isEmpty ? nil : $0 }
                let resolvedAction =
                    action.flatMap {
                        LinkExtractor.resolve(decodeEntities($0), against: result.base ?? pageURL)
                    }
                    ?? pageURL
                if action != nil { add(action, .form) }
                form = HTMLForm(
                    action: resolvedAction, method: (attributes["method"] ?? "get").uppercased(),
                    enctype: (attributes["enctype"] ?? "application/x-www-form-urlencoded").lowercased(),
                    fields: [], page: pageURL)
            default: break
            }
            if let style = attributes["style"] { result.links += cssURLs(style).map { ($0, .css) } }
            // Form fields.
            guard form != nil else { continue }
            switch tag.name {
            case "input", "button":
                guard let name = attributes["name"] else { continue }
                let type = (attributes["type"] ?? (tag.name == "button" ? "submit" : "text")).lowercased()
                form?.fields.append(
                    FormField(
                        name: decodeEntities(name), type: type,
                        value: decodeEntities(attributes["value"] ?? ""),
                        checked: attributes["checked"] != nil))
            case "select":
                if let name = attributes["name"] {
                    selectField = FormField(
                        name: decodeEntities(name), type: "select", value: "", checked: false)
                }
            case "option":
                if var field = selectField {
                    let value = decodeEntities(attributes["value"] ?? "")
                    if field.value.isEmpty || attributes["selected"] != nil { field.value = value }
                    selectField = field
                }
            case "textarea":
                textareaName = attributes["name"].map(decodeEntities)
                let close = text[index...].range(of: "</textarea", options: .caseInsensitive)
                if let name = textareaName {
                    let content = text[index..<(close?.lowerBound ?? text.endIndex)]
                    form?.fields.append(
                        FormField(
                            name: name, type: "textarea", value: decodeEntities(String(content)),
                            checked: false))
                }
                textareaName = nil
                index = close?.lowerBound ?? text.endIndex
            default: break
            }
        }
        if let open = form { result.forms.append(open) }
        result.structureHash = tagCount > 0 ? hasher.finalize() : nil
        return result
    }

    /// Scan a tag starting at `<`; nil when it isn't one (`<` in text, `<!doctype>` etc. count as
    /// tags without a known name and are skipped by the caller).
    static func scanTag(_ text: String, from open: String.Index) -> Tag? {
        var index = text.index(after: open)
        guard index < text.endIndex else { return nil }
        var closing = false
        if text[index] == "/" {
            closing = true
            index = text.index(after: index)
        }
        let nameStart = index
        while index < text.endIndex,
            text[index].isLetter || text[index].isNumber || text[index] == "-"
                || text[index] == "!" || text[index] == "?"
        {
            index = text.index(after: index)
        }
        guard index > nameStart else { return nil }
        let name = text[nameStart..<index].lowercased()
        var attributes: [String: String] = [:]
        while index < text.endIndex {
            // Skip whitespace and stray slashes.
            while index < text.endIndex, text[index].isWhitespace || text[index] == "/" {
                index = text.index(after: index)
            }
            guard index < text.endIndex else { break }
            if text[index] == ">" {
                index = text.index(after: index)
                return Tag(name: name, attributes: attributes, closing: closing, end: index)
            }
            let attrStart = index
            while index < text.endIndex, !text[index].isWhitespace, text[index] != "=", text[index] != ">",
                text[index] != "/" || attrStart == index
            {
                index = text.index(after: index)
            }
            let attrName = text[attrStart..<index].lowercased()
            while index < text.endIndex, text[index].isWhitespace { index = text.index(after: index) }
            var value = ""
            if index < text.endIndex, text[index] == "=" {
                index = text.index(after: index)
                while index < text.endIndex, text[index].isWhitespace { index = text.index(after: index) }
                if index < text.endIndex, text[index] == "\"" || text[index] == "'" {
                    let quote = text[index]
                    let start = text.index(after: index)
                    let end = text[start...].firstIndex(of: quote) ?? text.endIndex
                    value = String(text[start..<end])
                    index = end < text.endIndex ? text.index(after: end) : end
                } else {
                    let start = index
                    while index < text.endIndex, !text[index].isWhitespace, text[index] != ">" {
                        index = text.index(after: index)
                    }
                    value = String(text[start..<index])
                }
            }
            if !attrName.isEmpty, attributes[attrName] == nil { attributes[attrName] = value }
            if attrStart == index { index = text.index(after: index) }  // no progress: skip a char
        }
        return Tag(name: name, attributes: attributes, closing: closing, end: text.endIndex)
    }

    // MARK: other sources

    /// The URL in a refresh value (`5; url=/next`).
    static func refreshURL(_ content: String) -> String? {
        guard let range = content.range(of: "url=", options: .caseInsensitive) else { return nil }
        let url = content[range.upperBound...].trimmingCharacters(in: CharacterSet(charactersIn: " '\""))
        return url.isEmpty ? nil : url
    }

    private static let cssURL = try? NSRegularExpression(
        pattern: #"url\(\s*['"]?([^'")\s]+)['"]?\s*\)|@import\s+['"]([^'"]+)['"]"#,
        options: [.caseInsensitive])
    private static let heuristic = try? NSRegularExpression(
        pattern:
            #"["'`]((?:https?://[A-Za-z0-9.\-]+(?::\d+)?)?/[A-Za-z0-9_\-./~%]*(?:\?[A-Za-z0-9_\-.=&%+]*)?)["'`]"#
    )
    private static let loc = try? NSRegularExpression(
        pattern: #"<loc>\s*([^<\s]+)\s*</loc>"#, options: [.caseInsensitive])

    static func cssURLs(_ text: String) -> [String] {
        matches(cssURL, in: text).filter { !$0.hasPrefix("data:") }
    }

    /// URL-looking strings in script or JSON text: quoted absolute http(s) URLs and root-relative
    /// paths (`"/api/items"`); `//` comments and single `/` are left out.
    static func heuristicURLs(_ text: String) -> [String] {
        matches(heuristic, in: text).filter { $0.count > 1 && !$0.hasPrefix("//") }
    }

    static func sitemapURLs(_ text: String) -> [String] { matches(loc, in: text) }

    static func matches(_ regex: NSRegularExpression?, in text: String) -> [String] {
        guard let regex else { return [] }
        let range = NSRange(text.startIndex..., in: text)
        return regex.matches(in: text, range: range).compactMap { match in
            for group in 1..<match.numberOfRanges {
                if let r = Range(match.range(at: group), in: text) { return String(text[r]) }
            }
            return nil
        }
    }

    /// The common HTML entities in attribute values (`&amp;` above all, so `?a=1&amp;b=2` works).
    static func decodeEntities(_ text: String) -> String {
        guard text.contains("&") else { return text }
        var out = text
        for (entity, char) in [
            ("&amp;", "&"), ("&quot;", "\""), ("&#39;", "'"), ("&apos;", "'"), ("&lt;", "<"), ("&gt;", ">"),
            ("&#x2F;", "/"), ("&#47;", "/"),
        ] {
            out = out.replacingOccurrences(of: entity, with: char, options: .caseInsensitive)
        }
        return out
    }
}
