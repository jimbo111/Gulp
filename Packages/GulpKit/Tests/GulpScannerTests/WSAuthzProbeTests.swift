import Testing

@testable import GulpScanner

@Suite("WebSocket per-message authorization (F23 WSX-004)")
struct WSAuthzProbeTests {
    @Test("missing authz: the stripped identity gets the privileged result")
    func test_WSX004_missingPerMessageAuthz() {
        let privileged = "{\"secret\":\"TOP-SECRET-FLAG-7781\"}"
        let stripped = "{\"secret\":\"TOP-SECRET-FLAG-7781\"}"
        #expect(
            WSAuthzProbe.classify(
                privilegedReply: privileged, strippedReply: stripped, successMarker: "TOP-SECRET")
                == .missing)
    }

    @Test("enforced authz: the stripped identity is refused")
    func test_WSX004_enforcedPerMessageAuthz() {
        let privileged = "{\"secret\":\"TOP-SECRET-FLAG-7781\"}"
        let stripped = "{\"error\":\"forbidden\",\"need\":\"admin\"}"
        #expect(
            WSAuthzProbe.classify(
                privilegedReply: privileged, strippedReply: stripped, successMarker: "TOP-SECRET")
                == .enforced)
    }

    @Test("inconclusive when the privileged baseline itself fails")
    func test_WSX004_inconclusiveBaseline() {
        #expect(
            WSAuthzProbe.classify(
                privilegedReply: "{\"error\":\"forbidden\"}", strippedReply: "{\"error\":\"forbidden\"}",
                successMarker: "secret") == .inconclusive)
        #expect(
            WSAuthzProbe.classify(privilegedReply: "", strippedReply: "", successMarker: "") == .inconclusive)
    }

    @Test("empty marker falls back to whole-reply equality")
    func test_WSX004_markerDefaultsToReply() {
        #expect(
            WSAuthzProbe.classify(
                privilegedReply: "{\"ok\":true,\"data\":42}", strippedReply: "{\"ok\":true,\"data\":42}",
                successMarker: "") == .missing)
        #expect(
            WSAuthzProbe.classify(
                privilegedReply: "{\"ok\":true,\"data\":42}", strippedReply: "{\"denied\":true}",
                successMarker: "") == .enforced)
    }
}
