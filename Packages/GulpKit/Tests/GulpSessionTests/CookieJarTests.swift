import Foundation
import GulpCore
import Testing

@testable import GulpSession

// F15 SES-001/002/012/020/021: cookie jar matching and parsing, identity variables, the macro
// runner's capture and cookie carry-forward, and the session-validity check.

@Suite("Cookie jar (SES-001)")
struct CookieJarTests {
    @Test("SES-001: Set-Cookie attributes are parsed; Max-Age wins over Expires")
    func test_SES001_parse() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let cookie = CookieJar.parse(
            "sid=abc; Domain=example.com; Path=/app; Secure; HttpOnly; SameSite=Lax; Max-Age=3600; Expires=Wed, 01 Jan 2020 00:00:00 GMT",
            host: "www.example.com", now: now)
        let c = try! #require(cookie)
        #expect(c.name == "sid" && c.value == "abc")
        #expect(c.domain == "example.com" && !c.hostOnly, "a Domain attribute allows subdomains")
        #expect(c.path == "/app" && c.secure && c.httpOnly && c.sameSite == "Lax")
        #expect(c.expires == now.addingTimeInterval(3600), "Max-Age overrides the past Expires")
    }

    @Test("SES-001: a cookie whose Domain doesn't match the host becomes host-only")
    func test_SES001_domainRejected() {
        let c = try! #require(CookieJar.parse("x=1; Domain=evil.com", host: "example.com"))
        #expect(c.hostOnly && c.domain == "example.com")
    }

    @Test("SES-001: matching honours domain, path, Secure and longest-path order")
    func test_SES001_matching() {
        var jar = CookieJar()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        jar.store(setCookies: ["a=1; Domain=example.com; Path=/"], from: "example.com", now: now)
        jar.store(setCookies: ["b=2; Path=/app"], from: "www.example.com", now: now)
        jar.store(setCookies: ["c=3; Secure"], from: "www.example.com", now: now)
        // Subdomain gets the domain cookie and the longer-path one, longest path first.
        let header = jar.header(host: "www.example.com", path: "/app/page", scheme: .http, now: now)
        #expect(header == "b=2; a=1", "longest path first; the Secure cookie is withheld over http")
        #expect(jar.header(host: "other.com", path: "/", scheme: .http, now: now) == nil)
        // Over https the Secure cookie is included (host-only, so only on the exact host).
        let https = jar.header(host: "www.example.com", path: "/app", scheme: .https, now: now)
        #expect(https?.contains("c=3") == true)
        #expect(
            jar.header(host: "example.com", path: "/app", scheme: .https, now: now)?.contains("c=3") == false,
            "a host-only cookie isn't sent to the parent domain")
    }

    @Test("SES-001: a re-set cookie replaces by name/domain/path; expiry in the past deletes")
    func test_SES001_replaceAndDelete() {
        var jar = CookieJar()
        jar.store(setCookies: ["sid=one; Path=/"], from: "lab.test")
        jar.store(setCookies: ["sid=two; Path=/"], from: "lab.test")
        #expect(jar.cookies.count == 1 && jar.cookies.first?.value == "two")
        jar.store(setCookies: ["sid=two; Path=/; Max-Age=0"], from: "lab.test")
        #expect(jar.cookies.isEmpty, "Max-Age=0 deletes")
    }

    @Test("SES-002 / SES-021: variable expansion fills ${name} and leaves unknowns")
    func test_SES002_variables() {
        let vars = ["user": "alice", "token": "xyz"]
        #expect(
            VariableExpansion.expand("u=${user}&t=${token}&k=${missing}", vars)
                == "u=alice&t=xyz&k=${missing}")
        #expect(VariableExpansion.references(in: "${a}${b}c").sorted() == ["a", "b"])
        var identity = Identity(name: "admin", variables: ["role": "admin"])
        identity.captured = ["role": "superadmin", "csrf": "t"]
        #expect(identity.allVariables["role"] == "superadmin" && identity.allVariables["csrf"] == "t")
    }

    @Test("SES-012: the validity check reads status, redirect and body markers")
    func test_SES012_validity() {
        func response(_ status: Int, location: String? = nil, body: String = "Welcome alice") -> RawResponse {
            var head = "HTTP/1.1 \(status) X\r\nContent-Length: \(body.utf8.count)\r\n"
            if let location { head += "Location: \(location)\r\n" }
            return RawResponse(Bytes(head + "\r\n" + body))
        }
        let check = ValidityCheck(
            statusIn: [200], redirectContains: "/login", bodyContains: "alice", bodyAbsent: "Please log in")
        #expect(check.isValid(response(200)))
        #expect(!check.isValid(response(302, location: "/login")))
        #expect(!check.isValid(response(200, body: "Please log in")))
        #expect(!check.isValid(response(200, body: "Welcome guest")), "missing the required marker")
        #expect(ValidityCheck().isEmpty && ValidityCheck().isValid(response(500)))
    }
}
