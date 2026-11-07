import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import SwiftASN1
import Testing
import X509

@testable import GulpTLS

// F02 acceptance tests 1–3 and the helpers they rest on (host names, ClientHello sniffing).

@Suite("GulpTLS — certificate authority (TLS-001, TLS-003, TLS-006, TLS-007)")
struct CertificateAuthorityTests {
    func extensionValue(
        _ certificate: Certificate, _ oid: ASN1ObjectIdentifier
    ) -> Certificate.Extension? {
        certificate.extensions.first { $0.oid == oid }
    }

    @Test("TLS-001: a fresh RSA CA has CA:TRUE pathLen 0, keyCertSign+cRLSign, SKI, 10-year validity")
    func test_TLS001_caExtensions() throws {
        let now = Date()
        let authority = try CertificateAuthority.generate(keyType: .rsa2048, now: now)
        let certificate = authority.certificate
        #expect(certificate.subject.description.contains("Gulp CA"))
        #expect(certificate.subject.description.contains("O=Gulp"))
        #expect(certificate.issuer == certificate.subject)

        let basic = try #require(extensionValue(certificate, .X509ExtensionID.basicConstraints))
        #expect(basic.critical)
        #expect(try BasicConstraints(basic) == .isCertificateAuthority(maxPathLength: 0))

        let usage = try #require(extensionValue(certificate, .X509ExtensionID.keyUsage))
        #expect(usage.critical)
        let keyUsage = try KeyUsage(usage)
        #expect(keyUsage.keyCertSign && keyUsage.cRLSign && !keyUsage.digitalSignature)

        #expect(extensionValue(certificate, .X509ExtensionID.subjectKeyIdentifier) != nil)
        let years = certificate.notValidAfter.timeIntervalSince(now) / (365.25 * 86_400)
        #expect(years > 9.9 && years < 10.1)
        #expect(authority.key.type == .rsa2048)
    }

    @Test("TLS-001: the CA can use ECDSA P-256")
    func test_TLS001_p256() throws {
        let authority = try CertificateAuthority.generate(keyType: .p256)
        #expect(authority.key.type == .p256)
        #expect(authority.certificate.signatureAlgorithm == .ecdsaWithSHA256)
    }

    @Test("TLS-003/010: a leaf is exact-host, serverAuth, signed by the CA, valid < 398 days")
    func test_TLS003_leafShape() throws {
        let authority = try CertificateAuthority.generate(keyType: .p256)
        let key = try SigningKey.generate(.p256)
        let now = Date()
        let subject = CertificateSubject(host: "A.B.Example.COM.")
        let leaf = try authority.mintLeaf(for: subject, key: key, now: now)
        let certificate = leaf.certificate
        #expect(certificate.issuer == authority.certificate.subject)
        #expect(certificate.subject.description.contains("a.b.example.com"))

        let san = try #require(extensionValue(certificate, .X509ExtensionID.subjectAlternativeName))
        #expect(try SubjectAlternativeNames(san) == SubjectAlternativeNames([.dnsName("a.b.example.com")]))
        let eku = try #require(extensionValue(certificate, .X509ExtensionID.extendedKeyUsage))
        #expect(try ExtendedKeyUsage(eku).contains(.serverAuth))
        let basic = try #require(extensionValue(certificate, .X509ExtensionID.basicConstraints))
        #expect(try BasicConstraints(basic) == .notCertificateAuthority)
        #expect(extensionValue(certificate, .X509ExtensionID.authorityKeyIdentifier) != nil)

        let lifetime = certificate.notValidAfter.timeIntervalSince(certificate.notValidBefore) / 86_400
        #expect(lifetime < 398 && lifetime > 396)
        #expect(certificate.notValidBefore < now)
        // Positive 16-byte serial.
        #expect(certificate.serialNumber.bytes.count == 16)
        #expect(certificate.serialNumber.bytes.first.map { $0 & 0x80 == 0 } == true)
    }

    @Test("TLS-012: IP literals get an IP SAN")
    func test_TLS012_ipSAN() throws {
        let authority = try CertificateAuthority.generate(keyType: .p256)
        let key = try SigningKey.generate(.p256)
        let leaf = try authority.mintLeaf(for: CertificateSubject(host: "127.0.0.1"), key: key)
        let san = try #require(extensionValue(leaf.certificate, .X509ExtensionID.subjectAlternativeName))
        let names = try SubjectAlternativeNames(san)
        #expect(names.count == 1)
        if case .ipAddress(let octets) = names.first {
            #expect(Array(octets.bytes) == [127, 0, 0, 1])
        } else {
            Issue.record("expected an IP SAN, got \(names)")
        }
    }

    @Test("TLS-006/007: PEM export round-trips through import; a foreign key is refused")
    func test_TLS007_importExport() throws {
        let authority = try CertificateAuthority.generate(keyType: .p256)
        let pem = try authority.certificatePEM()
        #expect(pem.hasPrefix("-----BEGIN CERTIFICATE-----"))
        #expect(try authority.certificateDER().first == 0x30)
        let imported = try CertificateAuthority(certificatePEM: pem, privateKeyPEM: authority.key.pem)
        #expect(imported.certificate == authority.certificate)
        #expect(try imported.sha256Fingerprint() == authority.sha256Fingerprint())
        #expect(try imported.sha256Fingerprint().count == 64)

        let other = try SigningKey.generate(.p256)
        #expect(throws: TLSError.keyMismatch) {
            try CertificateAuthority(certificatePEM: pem, privateKeyPEM: other.pem)
        }
    }

    @Test("TLS-002: the file store writes the key with mode 0600 and loads the same CA")
    func test_TLS002_fileStore() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("gulp-ca-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = FileCAStore(directory: directory)
        #expect(try store.load() == nil)
        let created = try CertificateAuthority.loadOrCreate(from: store, keyType: .p256)
        let loaded = try #require(try store.load())
        #expect(loaded.certificate == created.certificate)
        let again = try CertificateAuthority.loadOrCreate(from: store)
        #expect(again.certificate == created.certificate)
        let attributes = try FileManager.default.attributesOfItem(atPath: store.keyURL.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        try store.delete()
        #expect(try store.load() == nil)
    }
}

@Suite("GulpTLS — host names (F02 §5)")
struct HostNameTests {
    @Test("normalisation: lowercase, trailing dot, A-labels")
    func normalise() {
        #expect(HostName.normalize("WWW.Example.COM.") == "www.example.com")
        #expect(Punycode.encode("bücher") == "bcher-kva")
        #expect(Punycode.encode("münchen") == "mnchen-3ya")
        #expect(HostName.normalize("Bücher.example") == "xn--bcher-kva.example")
        #expect(HostName.normalize("例え.テスト") == "xn--r8jz45g.xn--zckzah")
    }

    @Test("IP literals")
    func ipLiterals() {
        #expect(CertificateSubject(host: "10.0.0.1") == .ip([10, 0, 0, 1], text: "10.0.0.1"))
        #expect(CertificateSubject(host: "[::1]") == .ip(Array(repeating: 0, count: 15) + [1], text: "::1"))
        let mapped = CertificateSubject(host: "::ffff:1.2.3.4")
        let mappedBytes: [UInt8] = Array(repeating: 0, count: 10) + [0xFF, 0xFF, 1, 2, 3, 4]
        #expect(mapped == .ip(mappedBytes, text: "::ffff:1.2.3.4"))
        #expect(CertificateSubject(host: "256.1.1.1") == .dns("256.1.1.1"))
        #expect(CertificateSubject(host: "1:2:3:4:5:6:7:8:9") == .dns("1:2:3:4:5:6:7:8:9"))
    }
}

@Suite("GulpTLS — ClientHello sniffing (PRX-006/PRX-008)")
struct ClientHelloTests {
    /// A minimal ClientHello with SNI and ALPN, split over `records` TLS records.
    static func clientHello(sni: String?, alpn: [String], records: Int = 1) -> [UInt8] {
        var extensions: [UInt8] = []
        func u16(_ value: Int) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 0xFF)] }
        if let sni {
            let name = Array(sni.utf8)
            let entry = [0] + u16(name.count) + name
            extensions += u16(0) + u16(entry.count + 2) + u16(entry.count) + entry
        }
        if !alpn.isEmpty {
            let list = alpn.flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) }
            extensions += u16(16) + u16(list.count + 2) + u16(list.count) + list
        }
        var body: [UInt8] = [3, 3] + Array(repeating: 7, count: 32) + [0]  // version, random, no session
        body += u16(2) + [0x13, 0x01] + [1, 0]  // one suite, null compression
        body += u16(extensions.count) + extensions
        let length = [UInt8(body.count >> 16), UInt8((body.count >> 8) & 0xFF), UInt8(body.count & 0xFF)]
        let handshake = [1] + length + body
        var out: [UInt8] = []
        let chunk = (handshake.count + records - 1) / records
        var start = 0
        while start < handshake.count {
            let piece = handshake[start..<min(start + chunk, handshake.count)]
            out += [0x16, 3, 1] + u16(piece.count) + piece
            start += chunk
        }
        return out
    }

    @Test("reads SNI and ALPN; reassembles a hello split over records")
    func sniff() {
        let hello = Self.clientHello(sni: "example.com", alpn: ["h2", "http/1.1"])
        let expected = ClientHello(serverName: "example.com", alpn: ["h2", "http/1.1"])
        #expect(ClientHelloParser.sniff(hello) == .hello(expected))
        let split = Self.clientHello(sni: "a.test", alpn: ["http/1.1"], records: 3)
        let splitExpected = ClientHello(serverName: "a.test", alpn: ["http/1.1"])
        #expect(ClientHelloParser.sniff(split) == .hello(splitExpected))
        let bare = Self.clientHello(sni: nil, alpn: [])
        #expect(ClientHelloParser.sniff(bare) == .hello(ClientHello(serverName: nil, alpn: [])))
    }

    @Test("partial input asks for more; non-TLS and garbage are recognised")
    func partialAndInvalid() {
        let hello = Self.clientHello(sni: "example.com", alpn: ["h2"])
        for cut in [0, 1, 4, 5, 20, hello.count - 1] {
            #expect(ClientHelloParser.sniff(Array(hello[0..<cut])) == .needMoreData)
        }
        #expect(ClientHelloParser.sniff(Array("GET / HTTP/1.1\r\n".utf8)) == .notTLS)
        #expect(ClientHelloParser.sniff([0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0, 0, 0]) == .malformed)
    }
}

@Suite("GulpTLS — minting cache and live handshakes (TLS-004, TLS-005; acceptance 2–3)")
struct LeafMinterTests {
    @Test("acceptance 2: 1,000 concurrent requests for 50 hosts mint exactly 50 leaves")
    func test_TLS005_dedup() async throws {
        let minter = try LeafMinter(authority: CertificateAuthority.generate(keyType: .p256))
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<1_000 {
                group.addTask { _ = try await minter.leaf(for: "host\(index % 50).example") }
            }
            try await group.waitForAll()
        }
        #expect(await minter.mintCount == 50)
        #expect(await minter.cachedLeafCount == 50)
        // TLS-004: one shared leaf key.
        let a = try await minter.leaf(for: "host1.example")
        let b = try await minter.leaf(for: "host2.example")
        #expect(a.key.pem == b.key.pem)
    }

    @Test("the leaf cache evicts the least recently used entry beyond capacity")
    func lruEviction() async throws {
        let minter = try LeafMinter(authority: CertificateAuthority.generate(keyType: .p256), capacity: 3)
        for host in ["a.test", "b.test", "c.test", "a.test", "d.test"] {
            _ = try await minter.leaf(for: host)
        }
        #expect(await minter.cachedLeafCount == 3)
        _ = try await minter.leaf(for: "a.test")  // still cached (recently used)
        #expect(await minter.mintCount == 4)
        _ = try await minter.leaf(for: "b.test")  // was evicted
        #expect(await minter.mintCount == 5)
    }

    @Test(
        "acceptance 3: a client trusting the CA handshakes with minted leaves",
        arguments: [("localhost", "localhost"), ("bücher.example", "xn--bcher-kva.example")])
    func test_TLS003_handshake(mintFor: String, clientHost: String) async throws {
        for keyType in CAKeyType.allCases {
            let authority = try CertificateAuthority.generate(keyType: keyType)
            let minter = try LeafMinter(authority: authority)
            let context = try await minter.serverContext(for: mintFor, alpn: ["http/1.1"])
            let protocolName = try await Handshake.run(
                server: context, ca: authority.certificateDER(), host: clientHost, alpn: ["h2", "http/1.1"])
            #expect(protocolName == "http/1.1")
        }
    }

    @Test("a client that does not trust the CA fails the handshake")
    func untrusted() async throws {
        let minter = try LeafMinter(authority: CertificateAuthority.generate(keyType: .p256))
        let context = try await minter.serverContext(for: "localhost", alpn: [])
        let stranger = try CertificateAuthority.generate(keyType: .p256)
        await #expect(throws: (any Error).self) {
            _ = try await Handshake.run(
                server: context, ca: stranger.certificateDER(), host: "localhost", alpn: [])
        }
    }
}

/// Runs one TLS handshake over loopback and returns the negotiated ALPN protocol.
enum Handshake {
    static func run(
        server context: NIOSSLContext, ca: [UInt8], host: String, alpn: [String]
    ) async throws -> String? {
        let group = MultiThreadedEventLoopGroup.singleton
        let server = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        defer { server.close(promise: nil) }
        guard let address = server.localAddress else { throw ChannelError.inappropriateOperationForState }

        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = .certificates([try NIOSSLCertificate(bytes: ca, format: .der)])
        configuration.applicationProtocols = alpn
        let clientContext = try NIOSSLContext(configuration: configuration)
        let done = group.next().makePromise(of: String?.self)
        let client = try await ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let tls = try NIOSSLClientHandler(context: clientContext, serverHostname: host)
                    try channel.pipeline.syncOperations.addHandler(tls)
                    try channel.pipeline.syncOperations.addHandler(HandshakeWaiter(done: done))
                }
            }
            .connect(to: address).get()
        defer { client.close(promise: nil) }
        return try await done.futureResult.get()
    }
}

final class HandshakeWaiter: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    let done: EventLoopPromise<String?>
    private var completed = false

    init(done: EventLoopPromise<String?>) {
        self.done = done
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? TLSUserEvent, case .handshakeCompleted(let negotiated) = event, !completed {
            completed = true
            done.succeed(negotiated)
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        if !completed {
            completed = true
            done.fail(error)
        }
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !completed {
            completed = true
            done.fail(ChannelError.eof)
        }
        context.fireChannelInactive()
    }
}
