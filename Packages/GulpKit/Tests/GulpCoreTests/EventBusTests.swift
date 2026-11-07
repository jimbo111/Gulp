import Testing

@testable import GulpCore

@Suite("GulpCore — EventBus (doc 01 §5.3)")
struct EventBusTests {
    @Test("subscribers receive published events in order")
    func deliversInOrder() async {
        let bus = EventBus()
        let a = await bus.subscribe()
        let b = await bus.subscribe()
        await bus.publish(.scopeChanged)
        await bus.publish(.exchangeRecorded(7, source: .repeater))
        var ia = a.makeAsyncIterator()
        var ib = b.makeAsyncIterator()
        let a1 = await ia.next()
        let a2 = await ia.next()
        let b1 = await ib.next()
        #expect(a1 == Delivery(event: .scopeChanged))
        #expect(a2 == Delivery(event: .exchangeRecorded(7, source: .repeater)))
        #expect(b1 == Delivery(event: .scopeChanged))
    }

    @Test("overflow drops events and later delivers one lagged marker; publish never blocks")
    func overflowReportsLag() async {
        let bus = EventBus()
        let stream = await bus.subscribe(bufferSize: 2)
        for id in 1...5 { await bus.publish(.exchangeUpdated(ExchangeID(id))) }  // 3, 4, 5 overflow
        var it = stream.makeAsyncIterator()
        let d1 = await it.next()
        let d2 = await it.next()
        #expect(d1 == Delivery(event: .exchangeUpdated(1)))
        #expect(d2 == Delivery(event: .exchangeUpdated(2)))
        await bus.publish(.exchangeUpdated(6))  // room again: marker first, then the event
        let marker = await it.next()
        let d6 = await it.next()
        #expect(marker == Delivery(event: nil, lagged: 3))
        #expect(d6 == Delivery(event: .exchangeUpdated(6)))
    }

    @Test("unsubscribe finishes the stream and removes the subscriber")
    func unsubscribeFinishes() async {
        let bus = EventBus()
        let sub = await bus.subscribeWithID()
        let before = await bus.subscriberCount
        await bus.unsubscribe(sub.id)
        let after = await bus.subscriberCount
        var it = sub.stream.makeAsyncIterator()
        let end = await it.next()
        #expect(before == 1 && after == 0)
        #expect(end == nil)
    }
}
