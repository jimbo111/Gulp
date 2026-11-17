// GulpScanner — SSO Workbench core tests (F25 SSO-001…005). OAuth flow reconstruction, redirect_uri /
// state / PKCE analysis, and SAML decode + signature-scope + assertion mutations — all pure, so fully
// covered on Linux. The live accept/reject against VulnLab's SSO fixtures is the DoD (Scripts/sso-dod.sh).

import Foundation
import Testing

@testable import GulpCodec
@testable import GulpScanner

@Suite("SSO Workbench — OAuth/OIDC (F25 SSO-001/003/004)")
struct SSOOAuthTests {
    @Test("SSO-001: reconstruct an auth-code + PKCE flow and its fields")
    func reconstructAuthCodePKCE() {
        let url =
            "https://idp.example/authorize?response_type=code&client_id=app1"
            + "&redirect_uri=https://app.example/callback&scope=openid%20profile&state=xyz123"
            + "&nonce=n0&code_challenge=abc&code_challenge_method=S256"
        let flow = SSOWorkbench.reconstructOAuth(
            authorizeURL: url, tokenEndpoint: "https://idp.example/token")
        #expect(flow.grantType == .authorizationCodePKCE)
        #expect(flow.clientID == "app1")
        #expect(flow.redirectURI == "https://app.example/callback")
        #expect(flow.scope == "openid profile")
        #expect(flow.state == "xyz123")
        #expect(flow.codeChallengeMethod == "S256")
        #expect(flow.authorizeEndpoint == "https://idp.example/authorize")
        #expect(flow.tokenEndpoint == "https://idp.example/token")
    }

    @Test("SSO-001: grant-type classification")
    func grantTypes() {
        #expect(SSOWorkbench.grantType(responseType: "code", hasPKCE: false) == .authorizationCode)
        #expect(SSOWorkbench.grantType(responseType: "code", hasPKCE: true) == .authorizationCodePKCE)
        #expect(SSOWorkbench.grantType(responseType: "token", hasPKCE: false) == .implicit)
        #expect(SSOWorkbench.grantType(responseType: "id_token token", hasPKCE: false) == .implicit)
        #expect(SSOWorkbench.grantType(responseType: "code id_token", hasPKCE: false) == .hybrid)
        #expect(SSOWorkbench.grantType(responseType: nil, hasPKCE: false) == .unknown)
    }

    @Test("SSO-003: redirect_uri probes cover the classic bypass classes")
    func redirectProbes() {
        let probes = SSOWorkbench.redirectProbes(for: "https://app.example/callback")
        let kinds = Set(probes.map(\.kind))
        #expect(kinds.contains(.pathSuffix))
        #expect(kinds.contains(.subdomain))
        #expect(kinds.contains(.atConfusion))
        #expect(kinds.contains(.openRedirectChain))
        #expect(kinds.contains(.schemeDowngrade))  // https → http
        #expect(probes.contains { $0.value == "https://app.example/callback/../evil" })
    }

    @Test("SSO-003: an over-accepted redirect_uri variant is reported")
    func overAccepted() {
        let registered = "https://app.example/callback"
        let accepted = ["https://app.example/callback/../evil"]  // the AS accepted the traversal
        let over = SSOWorkbench.overAcceptedRedirects(registered: registered, accepted: accepted)
        #expect(over.count == 1)
        #expect(over.first?.kind == .pathSuffix)
    }

    @Test("SSO-004: missing state and plain PKCE are flagged; a safe flow is clean")
    func protections() {
        let unsafe = SSOWorkbench.reconstructOAuth(
            authorizeURL: "https://idp/authorize?response_type=code&client_id=a"
                + "&redirect_uri=https://app/cb&code_challenge=x&code_challenge_method=plain")
        let findings = SSOWorkbench.protectionFindings(unsafe)
        let kinds = Set(findings.map(\.kind))
        #expect(kinds.contains(.stateMissing))
        #expect(kinds.contains(.pkcePlain))

        let safe = SSOWorkbench.reconstructOAuth(
            authorizeURL: "https://idp/authorize?response_type=code&client_id=a"
                + "&redirect_uri=https://app/cb&state=s1&code_challenge=x&code_challenge_method=S256")
        #expect(SSOWorkbench.protectionFindings(safe).isEmpty)
    }

    @Test("SSO-004: a repeated state value is flagged as static/replayable")
    func staticState() {
        let flow = SSOWorkbench.reconstructOAuth(
            authorizeURL:
                "https://idp/authorize?response_type=code&client_id=a&redirect_uri=https://app/cb&state=CONST&code_challenge=x&code_challenge_method=S256"
        )
        let findings = SSOWorkbench.protectionFindings(flow, priorStates: ["CONST"])
        #expect(findings.contains { $0.kind == .stateStatic })
    }
}

@Suite("SSO Workbench — SAML (F25 SSO-002/005)")
struct SSOSAMLTests {
    // A minimal signed SAML Response: the Signature covers only the Response (#_resp), NOT the assertion.
    static let signedResponse = """
        <samlp:Response ID="_resp" xmlns:samlp="urn:p" xmlns:saml="urn:a">
        <ds:Signature xmlns:ds="urn:ds"><ds:SignedInfo><ds:Reference URI="#_resp"/></ds:SignedInfo>\
        <ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>
        <saml:Assertion ID="_a1"><saml:Subject><saml:NameID>alice</saml:NameID>\
        <saml:SubjectConfirmationData Recipient="https://sp.example/acs" NotOnOrAfter="2020-01-01T00:00:00Z"/>\
        </saml:Subject><saml:Conditions><saml:AudienceRestriction>\
        <saml:Audience>https://sp.example/sp</saml:Audience></saml:AudienceRestriction></saml:Conditions>\
        </saml:Assertion></samlp:Response>
        """

    @Test("SSO-002: POST-binding base64 decode round-trips")
    func decodePost() {
        let xml = "<samlp:Response ID=\"_r\"/>"
        let encoded = Data(xml.utf8).base64EncodedString()
        #expect(SAMLWorkbench.decode(encoded, binding: .post) == xml)
    }

    @Test("SSO-002: Redirect-binding base64+DEFLATE decode round-trips")
    func decodeRedirect() throws {
        let xml = "<samlp:AuthnRequest ID=\"_q\"/>"
        let deflated = try Compression.compress([UInt8](xml.utf8), .raw)
        let encoded = Data(deflated).base64EncodedString()
        #expect(SAMLWorkbench.decode(encoded, binding: .redirect) == xml)
    }

    @Test("SSO-002: parse finds the assertion unsigned when the signature only covers the Response")
    func signatureScope() {
        let msg = SAMLWorkbench.parse(Self.signedResponse)
        #expect(msg.kind == .response)
        #expect(msg.assertionIDs == ["_a1"])
        #expect(msg.signedIDs == ["_resp"])
        #expect(msg.unsignedAssertionIDs == ["_a1"])  // the assertion is NOT in the signed-node set
    }

    @Test("SSO-005: signature stripping removes the Signature block")
    func stripSignature() {
        let muts = SAMLWorkbench.mutations(Self.signedResponse)
        let stripped = muts.first { $0.kind == .signatureStripped }
        #expect(stripped != nil)
        #expect(stripped?.xml.contains("ds:Signature") == false)
        #expect(stripped?.xml.contains("saml:Assertion") == true)
    }

    @Test("SSO-005: XSW wraps a forged admin assertion before the original")
    func signatureWrapping() {
        let muts = SAMLWorkbench.mutations(Self.signedResponse)
        let xsw = muts.first { $0.kind == .signatureWrapping }
        #expect(xsw != nil)
        #expect(xsw?.xml.contains("_xsw_") == true)
        #expect(xsw?.xml.contains(">admin<") == true)
    }

    @Test("SSO-005: field tampering mutates audience, recipient, and validity")
    func fieldTampering() {
        let muts = SAMLWorkbench.mutations(Self.signedResponse)
        let kinds = Set(muts.map(\.kind))
        #expect(kinds.contains(.audienceTampered))
        #expect(kinds.contains(.recipientTampered))
        #expect(kinds.contains(.notOnOrAfterExtended))
        #expect(muts.first { $0.kind == .audienceTampered }?.xml.contains("evil.example") == true)
        #expect(muts.first { $0.kind == .notOnOrAfterExtended }?.xml.contains("2099") == true)
    }
}
