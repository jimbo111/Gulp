import Testing

@testable import GulpScanner

@Suite("Server-side parameter pollution (F23 ADV-022)")
struct ParamPollutionTests {
    @Test("duplicate handling is classified: last-wins, first-wins, concatenated, both")
    func classify() {
        #expect(
            ParamPollution.classify(firstValue: "orig", canary: "ZZxy", baseline: "orig", dup: "ZZxy")
                == .lastWins)
        #expect(
            ParamPollution.classify(firstValue: "orig", canary: "ZZxy", baseline: "orig", dup: "orig")
                == .firstWins)
        #expect(
            ParamPollution.classify(firstValue: "orig", canary: "ZZxy", baseline: "orig", dup: "orig,ZZxy")
                == .concatenated)
        #expect(
            ParamPollution.classify(firstValue: "orig", canary: "ZZxy", baseline: "orig", dup: "orig | ZZxy")
                == .both)
        #expect(ParamPollution.isQuirk(.lastWins))
        #expect(!ParamPollution.isQuirk(.firstWins))
    }
}
