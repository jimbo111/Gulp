import Foundation
import GulpCore
import Testing

@testable import GulpScanner

// F08 §3.3 (SCN-060/061): declarative Check Recipes evaluated against a response.

@Suite("Check Recipes (SCN-060)")
struct CheckRecipeTests {
    func message(
        _ headers: [String], body: String = "ok", status: Int = 200, path: String = "/x",
        mime: String = "text/plain"
    ) -> PassiveMessage {
        let head =
            (["HTTP/1.1 \(status) X", "Content-Type: \(mime)"] + headers + [
                "Content-Length: \(body.utf8.count)"
            ]).joined(separator: "\r\n")
        let exchange = Exchange(
            id: 5, source: .proxy, target: HTTPTarget(scheme: .http, host: "lab.test"),
            request: RawRequest(Bytes("GET \(path) HTTP/1.1\r\nHost: lab.test\r\n\r\n")),
            response: RawResponse(Bytes(head + "\r\n\r\n" + body)), state: .complete)
        return PassiveMessage(exchange)!
    }

    @Test("SCN-061: a header-present recipe fires and templates the header value into the detail")
    func test_SCN061_headerLeak() {
        let recipe = CheckRecipe(
            id: "recipe.x-powered-by", name: "Stack disclosed via X-Powered-By", severity: .low,
            match: RecipeMatcher(headerPresent: "X-Powered-By"),
            detail: "The response advertises its stack: `{{header:X-Powered-By}}`.")
        let hit = recipe.evaluate(message(["X-Powered-By: Express/4.17.1"]))
        let finding = try! #require(hit)
        #expect(finding.typeID == "recipe.x-powered-by" && finding.severity == .low)
        #expect(finding.detail.contains("Express/4.17.1"), "the header value is templated in")
        #expect(recipe.evaluate(message([])) == nil, "no header, no finding")
    }

    @Test("SCN-061: matchers combine (status + body regex + header-absent) and support OR groups")
    func test_SCN061_matchers() {
        let recipe = CheckRecipe(
            id: "recipe.debug", name: "Debug endpoint", severity: .medium,
            match: RecipeMatcher(statusIn: [200], bodyRegex: #"debug=(true|1)"#, headerAbsent: "X-Guard"),
            detail: "Debug mode is on.")
        #expect(recipe.evaluate(message([], body: "mode debug=true")) != nil)
        #expect(recipe.evaluate(message(["X-Guard: 1"], body: "debug=true")) == nil, "header-absent fails")
        #expect(recipe.evaluate(message([], body: "debug=false")) == nil, "regex fails")
        let orRecipe = CheckRecipe(
            id: "recipe.any", name: "any",
            match: RecipeMatcher(any: [
                RecipeMatcher(bodyContains: "AAA"), RecipeMatcher(bodyContains: "BBB"),
            ]),
            detail: "x")
        #expect(orRecipe.evaluate(message([], body: "has BBB")) != nil)
        #expect(orRecipe.evaluate(message([], body: "neither")) == nil)
    }

    @Test("SCN-061: path and content-type gates are honoured")
    func test_SCN061_gates() {
        let recipe = CheckRecipe(
            id: "recipe.api", name: "api", pathContains: "/api/", contentType: "json",
            match: RecipeMatcher(bodyContains: "token"), detail: "x")
        #expect(recipe.evaluate(message([], body: "token", path: "/api/x", mime: "application/json")) != nil)
        #expect(
            recipe.evaluate(message([], body: "token", path: "/page", mime: "application/json")) == nil,
            "path gate")
        #expect(
            recipe.evaluate(message([], body: "token", path: "/api/x", mime: "text/html")) == nil,
            "content-type gate")
    }

    @Test("SCN-060: recipes decode from a single JSON object or an array")
    func test_SCN060_decode() throws {
        let json =
            #"{"id":"recipe.a","name":"A","severity":"high","confidence":"firm","match":{"bodyContains":"secret"},"detail":"found"}"#
        let one = try CheckRecipes.decode(Data(json.utf8))
        #expect(one.count == 1 && one[0].severity == .high)
        let array = try CheckRecipes.decode(Data("[\(json),\(json)]".utf8))
        #expect(array.count == 2)
    }
}
