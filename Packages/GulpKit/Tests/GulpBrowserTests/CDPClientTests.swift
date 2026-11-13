import Foundation
import Testing

@testable import GulpBrowser

/// An in-memory CDP transport: it answers each command with a result echoing its method, and can push
/// events on demand — so the client's id-correlation and event routing are tested without a browser.
final class MockCDPTransport: CDPTransport, @unchecked Sendable {
    private let (stream, continuation) = AsyncStream<String>.makeStream()
    /// Commands the client sent, for assertions.
    private let lock = NSLock()
    private var _sent: [String] = []
    var sent: [String] { lock.withLock { _sent } }

    func send(_ text: String) async throws {
        lock.withLock { _sent.append(text) }
        guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
            let id = object["id"] as? Int
        else { return }
        let method = object["method"] as? String ?? ""
        // "Runtime.evaluate" of "boom" returns a remote error; everything else echoes the method.
        let params = (object["params"] as? [String: Any])?["expression"] as? String
        if method == "Runtime.evaluate", params == "boom" {
            continuation.yield(#"{"id":\#(id),"error":{"code":-32000,"message":"nope"}}"#)
        } else {
            continuation.yield(#"{"id":\#(id),"result":{"method":"\#(method)"}}"#)
        }
    }

    func receiveLoop(_ onText: @Sendable @escaping (String) -> Void) async {
        for await text in stream { onText(text) }
    }

    func close() async { continuation.finish() }

    /// Push a CDP event to the client.
    func emit(_ json: String) { continuation.yield(json) }
}

@Suite("GulpBrowser — CDP client (BRW-005)")
struct CDPClientTests {
    @Test("a command is answered by id; concurrent commands correlate to their own results")
    func commandCorrelation() async throws {
        let mock = MockCDPTransport()
        let client = CDPClient(transport: mock)
        await client.start()
        async let a = client.send("Page.enable")
        async let b = client.send("Runtime.enable")
        async let c = client.send("Target.getTargets")
        let results = try await [a, b, c]
        #expect(results.contains { $0.contains("Page.enable") })
        #expect(results.contains { $0.contains("Runtime.enable") })
        #expect(results.contains { $0.contains("Target.getTargets") })
        #expect(mock.sent.count == 3)
        await client.close()
    }

    @Test("a remote error becomes a thrown CDPError.remote")
    func remoteError() async throws {
        let mock = MockCDPTransport()
        let client = CDPClient(transport: mock)
        await client.start()
        await #expect(throws: CDPError.self) {
            _ = try await client.send("Runtime.evaluate", params: #"{"expression":"boom"}"#)
        }
        await client.close()
    }

    @Test("events are delivered on the events stream, not confused with responses")
    func events() async throws {
        let mock = MockCDPTransport()
        let client = CDPClient(transport: mock)
        await client.start()
        let received = Task { () -> CDPEvent? in
            for await event in client.events where event.method == "Runtime.bindingCalled" { return event }
            return nil
        }
        // An event with no id must not be mistaken for a response.
        mock.emit(
            #"{"method":"Runtime.bindingCalled","params":{"name":"__gulpReport","payload":"{}"},"sessionId":"S1"}"#
        )
        let event = await received.value
        #expect(event?.method == "Runtime.bindingCalled")
        #expect(event?.sessionId == "S1")
        #expect(event?.params.contains("__gulpReport") == true)
        await client.close()
    }

    @Test("the DOM-probe instrumentation is embedded and parses its own reports")
    func instrumentationEmbedded() {
        #expect(DOMProbe.instrumentation.contains("__gulpProbeInstalled"))
        #expect(DOMProbe.instrumentation.contains("innerHTML"))
        let finding = DOMProbe.parse(
            #"{"sink":"Element.innerHTML","source":"location.hash","sample":"<img>","snippet":"<img src=x>"}"#
        )
        #expect(finding?.sink == "Element.innerHTML")
        #expect(finding?.source == "location.hash")
    }
}

@Suite("GulpBrowser — automation launch (BRW-005)")
struct BrowserAutomationTests {
    @Test("the automation flags carry the debug port, isolated profile, proxy and SPKI pin")
    func launchFlags() {
        let args = BrowserAutomation.launchArguments(
            profile: URL(fileURLWithPath: "/tmp/p"), spkiPin: "ABC=", proxy: "127.0.0.1:8080",
            headless: true)
        #expect(args.contains("--remote-debugging-port=0"))
        #expect(args.contains("--user-data-dir=/tmp/p"))
        #expect(args.contains("--proxy-server=127.0.0.1:8080"))
        #expect(args.contains("--ignore-certificate-errors-spki-list=ABC="))
        #expect(args.contains("--headless=new"))
    }

    @Test("the DevToolsActivePort file is parsed into a ws:// endpoint")
    func portFile() {
        let endpoint = BrowserAutomation.devToolsEndpoint(
            fromPortFile: "44337\n/devtools/browser/29171063-b1cb-428c\n")
        #expect(endpoint?.absoluteString == "ws://127.0.0.1:44337/devtools/browser/29171063-b1cb-428c")
        #expect(BrowserAutomation.devToolsEndpoint(fromPortFile: "not-a-port") == nil)
    }
}
