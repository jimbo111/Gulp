import Testing

@Suite("beacon scaffolding")
struct BeaconTests {
    @Test("test harness runs")
    func harness() {
        #expect(Bool(true))
    }
}
