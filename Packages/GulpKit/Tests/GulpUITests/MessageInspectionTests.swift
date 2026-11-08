import GulpCore
import Testing

@testable import GulpUI

// doc 05 UI-010 / UI-020: editable text that never loses bytes, and the Inspector's sections.

@Suite("GulpUI — MessageEditor text and Inspector (UI-010, UI-020)")
struct MessageInspectionTests {
    @Test("UTF-8 is edited as UTF-8; other bytes round-trip through the Latin-1 view")
    func textRoundTrip() {
        let utf8 = Array("GET /é HTTP/1.1\r\n\r\n".utf8)
        let (text, encoding) = MessageText.decode(utf8)
        #expect(encoding == .utf8)
        #expect(MessageText.encode(text, encoding) == utf8)
        let binary: [UInt8] = Array("POST / HTTP/1.1\r\n\r\n".utf8) + [0xFF, 0x00, 0xC3]
        let (latin, latinEncoding) = MessageText.decode(binary)
        #expect(latinEncoding == .latin1)
        #expect(MessageText.encode(latin, latinEncoding) == binary)
        #expect(MessageText.encode(latin + "é", latinEncoding) == binary + [0xE9])
    }

    @Test("Request sections: line, query, body params, cookies, headers")
    func requestSections() {
        let text =
            "POST /login?next=%2F&x HTTP/1.1\r\nHost: a\r\nCookie: sid=1; theme=dark\r\n"
            + "Content-Type: application/x-www-form-urlencoded\r\n\r\nuser=alice&pw=s3cret"
        let inspection = MessageInspection(Array(text.utf8))
        let titles = inspection.sections.map(\.title)
        #expect(titles == ["Request", "Query parameters", "Body parameters", "Cookies", "Headers"])
        let line = [
            InspectorRow("Method", "POST"), InspectorRow("Path", "/login"),
            InspectorRow("Protocol", "HTTP/1.1"),
        ]
        #expect(inspection.sections[0].rows == line)
        #expect(inspection.sections[1].rows == [InspectorRow("next", "%2F"), InspectorRow("x", "")])
        let form = [InspectorRow("user", "alice"), InspectorRow("pw", "s3cret")]
        #expect(inspection.sections[2].rows == form)
        #expect(inspection.sections[3].rows == [InspectorRow("sid", "1"), InspectorRow("theme", "dark")])
        #expect(inspection.sections[4].rows.count == 3)
    }

    @Test("Response sections: status and Set-Cookie")
    func responseSections() {
        let text = "HTTP/2 302\r\nlocation: /\r\nset-cookie: sid=9; HttpOnly\r\n\r\n"
        let inspection = MessageInspection(Array(text.utf8))
        #expect(inspection.sections.map(\.title) == ["Response", "Headers", "Set-Cookie"])
        let status = [InspectorRow("Protocol", "HTTP/2"), InspectorRow("Status", "302")]
        #expect(inspection.sections[0].rows == status)
        #expect(inspection.sections[2].rows == [InspectorRow("sid", "9")])
    }
}
