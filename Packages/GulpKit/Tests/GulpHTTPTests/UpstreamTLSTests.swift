import Foundation
import GulpCore
import GulpTLS
import NIOSSL
import Testing

@testable import GulpHTTP

// F02 TLS-008/TLS-009 and F03 HTTPS: the engine speaks TLS to servers, records the chain and the
// would-be validation result, and enforces validation only when asked (acceptance #4's shape).

@Suite("GulpHTTP — upstream TLS (TLS-008, TLS-009)", .serialized)
struct UpstreamTLSEngineTests {
    /// A TLS test server presenting a leaf for `host` minted by a fresh (untrusted) CA.
    static func tlsServer(host: String = "localhost") async throws -> (TestServer, CertificateAuthority) {
        let authority = try CertificateAuthority.generate(keyType: .p256)
        let minter = try LeafMinter(authority: authority)
        let context = try await minter.serverContext(for: host, alpn: ["http/1.1"])
        let server = try await TestServer.start(tls: context) { received, _ in
            headersComplete(received) ? ok("secret") : nil
        }
        return (server, authority)
    }

    func options(validate: Bool = false) -> SendOptions {
        var options = SendOptions(recordAs: .repeater)
        options.tls.validateCertificates = validate
        options.timeouts.total = .seconds(10)
        return options
    }

    @Test("HTTPS works with validation off; the chain and 'untrusted' are recorded")
    func test_TLS008_validationOff() async throws {
        let (server, authority) = try await Self.tlsServer()
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: server.port)
        let request = RawRequest(Bytes("GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        let result = await engine.send(request, to: target, options: options())
        #expect(result.error == nil, "error: \(String(describing: result.error))")
        #expect(result.exchange.response?.bytes.string().hasSuffix("secret") == true)
        let tls = try #require(result.exchange.tls)
        #expect(tls.version.hasPrefix("TLSv1."))
        // A Gulp-minted server sends its CA after the leaf (BRW-002 pins match the chain).
        #expect(tls.serverChainSHA256.count == 2)
        let caFingerprint = try authority.sha256Fingerprint()
        #expect(tls.serverChainSHA256.last == caFingerprint)
        #expect(tls.serverChainSHA256.first?.count == 64)
        #expect(tls.validation == .failed("untrusted"))
        #expect(result.exchange.timing.tlsMs != nil)
        // The server received exactly our bytes, decrypted.
        #expect(server.received() == Array("GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n".utf8))

        // Reuse reports the same TLS session and skips the handshake.
        let again = await engine.send(request, to: target, options: options())
        #expect(again.exchange.tls?.serverChainSHA256 == tls.serverChainSHA256)
        #expect(again.exchange.timing.tlsMs == nil)
        #expect(server.connections == 1)
        await engine.shutdown()
        await server.stop()
    }

    @Test("With validation on, an untrusted server fails with a clear TLS error")
    func test_TLS008_validationOn() async throws {
        let (server, _) = try await Self.tlsServer()
        let engine = NIOHTTPEngine()
        let target = HTTPTarget(scheme: .https, host: "localhost", port: server.port)
        let request = RawRequest(Bytes("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        let result = await engine.send(request, to: target, options: options(validate: true))
        guard case .tlsFailure(let message) = result.error else {
            Issue.record("expected tlsFailure, got \(String(describing: result.error))")
            return
        }
        #expect(message.contains("untrusted"))
        await engine.shutdown()
        await server.stop()
    }

    @Test("TLS-009: a version range the server can't meet fails the handshake")
    func test_TLS009_versions() async throws {
        let authority = try CertificateAuthority.generate(keyType: .p256)
        let leaf = try authority.mintLeaf(for: .dns("localhost"), key: SigningKey.generate(.p256))
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(try NIOSSLCertificate(bytes: leaf.der, format: .der))],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(leaf.key.pem.utf8), format: .pem)))
        configuration.minimumTLSVersion = .tlsv13
        let server = try await TestServer.start(tls: try NIOSSLContext(configuration: configuration)) {
            received, _ in headersComplete(received) ? ok("x") : nil
        }
        let engine = NIOHTTPEngine()
        var settings = options()
        settings.tls.maximumVersion = .tls1_2
        let target = HTTPTarget(scheme: .https, host: "localhost", port: server.port)
        let result = await engine.send(
            RawRequest(Bytes("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")), to: target, options: settings)
        guard case .tlsFailure = result.error else {
            Issue.record("expected tlsFailure, got \(String(describing: result.error))")
            return
        }
        settings.tls.maximumVersion = .tls1_3
        let ok13 = await engine.send(
            RawRequest(Bytes("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")), to: target, options: settings)
        #expect(ok13.error == nil)
        #expect(ok13.exchange.tls?.version == "TLSv1.3")
        await engine.shutdown()
        await server.stop()
    }
}
